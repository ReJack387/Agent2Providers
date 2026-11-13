//! Sign in with ChatGPT（SIWC）通道绑定。
//!
//! ── 它是什么 ────────────────────────────────────────────────
//! SIWC 是 OpenAI 给「第三方 agent」开的一条独立授权通道：授权页用公开的
//! `client_id=dynamic_agent_client` 进去，但**服务端会在回调里签发一个新的
//! client_id**，之后换码与刷新都必须用这个签发的 id，而不是
//! `dynamic_agent_client`。签发的 id 与 `device_id` 一起构成这条通道的身份。
//!
//! 参考实现把它做成了独立子命令 `-siwc-bind`
//! （`CLIProxyAPI-main/internal/cmd/siwc_bind.go`），**不是** `Login()` 的一个
//! 分支 —— 因为它绑定的是「一个已经存在的 codex 凭证文件」，而不是新建账号。
//! 本模块照此设计：两个管理动作，`codex.siwc-start` 与 `codex.siwc-finish`，
//! 由界面分两步调用，最终把 `siwc` 子对象写回**同一个账号**的 secret。
//!
//! ── 为什么分两步而不是一个阻塞调用 ──────────────────────────
//! 插件的 `admin_action` 是一次 RPC，网关有超时；而 SIWC 要等用户在浏览器里
//! 完成授权（参考实现给 5 分钟）。分两步既能立刻把授权 URL 交到界面手上，
//! 也允许用户把回调地址整段粘回来（参考实现的 15 秒后手动粘贴分支）。
//!
//! ── 与普通 OAuth 的三处差别 ─────────────────────────────────
//! 1. 授权 URL 走 `https://auth.openai.com/api/accounts/authorize`，多带
//!    `resource`、`ext_agent_host_id`、`agent_name_hint`、`nonce`；
//! 2. 换码 / 刷新都带 `resource=https://api.openai.com/v1`；
//! 3. 换码必须拿到 `id_token`，且返回的 scope 必须含
//!    `chatgpt.tokens.use.direct`（`siwc_auth.go:180-223`）。

use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

use serde_json::{json, Value};

use crate::errors::GatewayError;
use crate::flight;

use super::credentials::CodexCredentials;
use super::{endpoints, oauth};

/// 授权页用的动态 client id（换码时会换成服务端签发的那个）。
pub const DYNAMIC_CLIENT_ID: &str = "dynamic_agent_client";

/// 授权页上的应用名提示。
pub const AGENT_NAME_HINT: &str = "Agent2API";

/// SIWC 授权页。
pub const AUTHORIZE_URL: &str = "https://auth.openai.com/api/accounts/authorize";

/// SIWC 换码 / 刷新端点。
pub const TOKEN_URL: &str = "https://auth.openai.com/api/accounts/oauth/token";

/// SIWC 的 resource 参数。
pub const RESOURCE: &str = "https://api.openai.com/v1";

/// 换码与刷新都必须带上的 scope。
pub const DIRECT_TOKEN_SCOPE: &str = "chatgpt.tokens.use.direct";

/// 授权页用的 scope。
pub const SCOPE: &str =
    "openid profile email offline_access resource.invoke chatgpt.tokens.use.direct";

/// 等待用户完成授权的窗口（毫秒）。参考实现是 5 分钟。
pub const PENDING_TTL_MS: i64 = 5 * 60 * 1000;

/// 一次待完成的绑定。
///
/// `state` 与 `nonce` 只在生成授权 URL 时用到，配对靠表键（= state），所以
/// 这两项在换码阶段不再读 —— 保留字段是为了排障时能把表里的记录与授权 URL
/// 对上。
#[derive(Clone)]
#[allow(dead_code)]
pub struct Pending {
    /// 本轮的 PKCE verifier。
    pub verifier: String,
    /// 本轮的 state（用于日志与排障；配对靠表键）。
    pub state: String,
    /// 本轮的 nonce（SIWC 授权页要求，换码时不回传）。
    pub nonce: String,
    /// 绑定用的 device id（36 字符 UUID）。
    pub device_id: String,
    /// 回调地址。
    pub redirect_uri: String,
    /// 创建时刻。
    pub created_at: i64,
}

/// 待完成绑定表（state → Pending）。
fn pending_table() -> &'static Mutex<HashMap<String, Pending>> {
    static TABLE: OnceLock<Mutex<HashMap<String, Pending>>> = OnceLock::new();
    TABLE.get_or_init(|| Mutex::new(HashMap::new()))
}

/// 加锁（毒锁时取回内层数据，`panic=abort` 下不会真的毒，但保持与仓内一致）。
fn with_pending<T>(action: impl FnOnce(&mut HashMap<String, Pending>) -> T) -> T {
    let mut guard = pending_table()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    action(&mut guard)
}

/// 清掉过期的待完成绑定。
fn sweep(table: &mut HashMap<String, Pending>) {
    let now = crate::logging::now_ms();
    table.retain(|_, pending| now - pending.created_at < PENDING_TTL_MS);
}

/// 校验一个字符串是不是规范的 36 字符 UUID（大小写不敏感）。
///
/// 参考实现 `siwcUUIDPattern` 要求 `8-4-4-4-12` 且全部是十六进制。
pub fn is_valid_uuid(raw: &str) -> bool {
    let text = raw.trim();
    if text.len() != 36 {
        return false;
    }
    for (index, byte) in text.bytes().enumerate() {
        let ok = match index {
            8 | 13 | 18 | 23 => byte == b'-',
            _ => byte.is_ascii_hexdigit(),
        };
        if !ok {
            return false;
        }
    }
    true
}

/// 生成一个规范的 device id（小写 UUID）。
fn new_device_id() -> String {
    crate::ids::uuid_v4().to_ascii_lowercase()
}

/// 取账号已有的 device id；没有或不合规就生成一个新的。
///
/// 参考实现 `ensureSIWCDeviceIDFromFile` 同样是「已有合规值就复用」——复用
/// 很重要，否则每次绑定都会在上游多注册一个设备。
fn device_id_of(secret: &Value) -> String {
    if let Some(existing) = secret
        .pointer("/siwc/device_id")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| is_valid_uuid(value))
    {
        return existing.to_ascii_lowercase();
    }
    new_device_id()
}

/// 组装 SIWC 授权 URL。
///
/// 参数顺序与参考实现 `GenerateSIWCAuthURL`（`siwc_auth.go:62-98`）一致。
pub fn authorize_url(
    state: &str,
    nonce: &str,
    device_id: &str,
    redirect_uri: &str,
    challenge: &str,
) -> Result<String, GatewayError> {
    if !is_valid_uuid(device_id) {
        return Err(GatewayError::with_status(
            400,
            format!("SIWC 的 device_id 必须是规范的 36 字符 UUID（当前是「{device_id}」）"),
        ));
    }
    if state.trim().is_empty() || nonce.trim().is_empty() {
        return Err(GatewayError::with_status(
            400,
            "SIWC 的 state 与 nonce 都不能为空".to_string(),
        ));
    }
    let mut url = url::Url::parse(AUTHORIZE_URL)
        .map_err(|error| GatewayError::with_status(500, format!("SIWC 授权地址无法解析：{error}")))?;
    {
        let mut query = url.query_pairs_mut();
        query.append_pair("client_id", DYNAMIC_CLIENT_ID);
        query.append_pair("agent_name_hint", AGENT_NAME_HINT);
        query.append_pair(
            "ext_agent_host_id",
            &format!("urn:uuid:{}", device_id.to_ascii_lowercase()),
        );
        query.append_pair("response_type", "code");
        query.append_pair("redirect_uri", redirect_uri);
        query.append_pair("resource", RESOURCE);
        query.append_pair("scope", SCOPE);
        query.append_pair("state", state);
        query.append_pair("code_challenge", challenge);
        query.append_pair("code_challenge_method", "S256");
        query.append_pair("nonce", nonce);
    }
    Ok(url.to_string())
}

/// 开始一次绑定：生成 PKCE / state / nonce / device_id，返回授权 URL 与 state。
///
/// 返回的 `state` 要交给界面，完成时作为 `codex.siwc-finish` 的 `state` 传回。
pub fn begin(secret: &Value) -> Result<(String, String), GatewayError> {
    let pkce = oauth::pkce()?;
    let state = oauth::new_state()?;
    let nonce = oauth::new_state()?;
    let device_id = device_id_of(secret);
    let redirect_uri = format!(
        "http://127.0.0.1:{}{}",
        endpoints::DEFAULT_CALLBACK_PORT,
        endpoints::CALLBACK_PATH
    );
    let url = authorize_url(&state, &nonce, &device_id, &redirect_uri, &pkce.challenge)?;
    let pending = Pending {
        verifier: pkce.verifier,
        state: state.clone(),
        nonce,
        device_id,
        redirect_uri,
        created_at: crate::logging::now_ms(),
    };
    with_pending(|table| {
        sweep(table);
        table.insert(state.clone(), pending);
    });
    Ok((url, state))
}

/// 取回并移除一次待完成绑定。
fn take_pending(state: &str) -> Result<Pending, GatewayError> {
    let key = state.trim();
    if key.is_empty() {
        return Err(GatewayError::with_status(
            400,
            "没有带 state，无法对上这次 SIWC 绑定".to_string(),
        ));
    }
    let pending = with_pending(|table| {
        sweep(table);
        table.remove(key)
    });
    pending.ok_or_else(|| {
        GatewayError::with_status(
            400,
            "这次 SIWC 绑定已失效（超过 5 分钟或插件重启过），请重新发起".to_string(),
        )
    })
}

/// 上游错误文案。
fn upstream_error(payload: &Value) -> (String, String) {
    let code = payload
        .pointer("/error")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .trim()
        .to_string();
    let description = payload
        .pointer("/error_description")
        .and_then(Value::as_str)
        .or_else(|| payload.pointer("/error/message").and_then(Value::as_str))
        .or_else(|| payload.get("message").and_then(Value::as_str))
        .unwrap_or_default()
        .trim()
        .to_string();
    (code, description)
}

/// POST 一个 form 到 SIWC 的令牌端点。
async fn post_token(
    form: &[(&str, String)],
    proxy: Option<&agent2api_provider_protocol::WireProxy>,
) -> Result<(u16, Value), String> {
    let client = crate::http::control_client(proxy, "direct");
    let mut request = client
        .post(TOKEN_URL)
        .timeout(std::time::Duration::from_millis(endpoints::REQUEST_TIMEOUT_MS));
    for (key, value) in endpoints::oauth_headers() {
        request = request.header(key.as_str(), value.as_str());
    }
    let response = request.form(form).send().await.map_err(|error| {
        let base = crate::http::describe(&error);
        if error.is_connect() {
            format!("{base}（本机访问 auth.openai.com 需经代理时：请开启系统代理，或给该账号配置出网代理）")
        } else {
            base
        }
    })?;
    let status = response.status().as_u16();
    let text = response.text().await.unwrap_or_default();
    let payload = serde_json::from_str::<Value>(&text).unwrap_or(Value::Null);
    Ok((status, payload))
}

/// 从令牌响应里读出 SIWC 的字段，并做与参考实现同等强度的校验。
///
/// 对照 `siwc_auth.go:163-244`：`access_token` / `refresh_token` 必须是非空
/// 字符串，`expires_in` 必须是正数，换码时 `id_token` 必须存在，且返回的
/// scope 必须含 `chatgpt.tokens.use.direct`。
fn read_token(
    payload: &Value,
    require_id_token: bool,
) -> Result<CodexCredentials, GatewayError> {
    let access_token = payload
        .get("access_token")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .trim()
        .to_string();
    if access_token.is_empty() {
        return Err(GatewayError::with_status(
            502,
            "SIWC 的令牌响应里没有 access_token".to_string(),
        ));
    }
    let refresh_token = payload
        .get("refresh_token")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .trim()
        .to_string();
    if refresh_token.is_empty() {
        return Err(GatewayError::with_status(
            502,
            "SIWC 的令牌响应里没有 refresh_token".to_string(),
        ));
    }
    let id_token = payload
        .get("id_token")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .trim()
        .to_string();
    if require_id_token && id_token.is_empty() {
        return Err(GatewayError::with_status(
            502,
            "SIWC 换码没有拿到 id_token（上游没按 SIWC 流程签发）".to_string(),
        ));
    }
    let expires_in = payload
        .get("expires_in")
        .and_then(|value| {
            value
                .as_i64()
                .or_else(|| value.as_str().and_then(|text| text.trim().parse().ok()))
        })
        .filter(|seconds| *seconds > 0)
        .ok_or_else(|| {
            GatewayError::with_status(502, "SIWC 的令牌响应里 expires_in 不合法".to_string())
        })?;
    let scope = payload
        .get("scope")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .trim()
        .to_string();
    if !scope.is_empty() && !scope.split_whitespace().any(|item| item == DIRECT_TOKEN_SCOPE) {
        return Err(GatewayError::with_status(
            502,
            format!("SIWC 这次授权没有拿到 {DIRECT_TOKEN_SCOPE}（拿到的 scope 是「{scope}」）"),
        ));
    }
    let mut credentials = CodexCredentials {
        refresh_token,
        access_token,
        id_token,
        expires_at: crate::logging::now_ms() + expires_in * 1000,
        ..Default::default()
    };
    super::credentials::absorb_id_token(&mut credentials);
    Ok(credentials)
}

/// 换码并产出要写回 secret 的 `siwc` 子对象。
///
/// `code` 可以是纯授权码，也可以是整段回调地址（参考实现允许手动粘贴）。
pub async fn finish(
    state: &str,
    code: &str,
    proxy: Option<&agent2api_provider_protocol::WireProxy>,
) -> Result<(Pending, Value), GatewayError> {
    let pending = take_pending(state)?;
    // 用户可能粘纯授权码，也可能粘整段回调地址；`client_id` 只在后者里，
    // 所以两个值都必须从**原始输入**里取。
    let raw = code.trim();
    let code = extract_code(raw);
    if code.is_empty() {
        return Err(GatewayError::with_status(
            400,
            "没有读到 SIWC 的授权码（请粘贴回调地址，或其中的 code 参数）".to_string(),
        ));
    }
    // 换码用的 client_id 是服务端在回调里签发的那个；如果用户只粘了 code，
    // 就只能用动态 id 试 —— 参考实现在这种情况下直接报错，这里保持一致。
    let issued = extract_param(raw, "client_id");
    if issued.is_empty() || issued == DYNAMIC_CLIENT_ID {
        return Err(GatewayError::with_status(
            400,
            "回调里没有服务端签发的 client_id（SIWC 绑定需要它，请粘贴完整回调地址）"
                .to_string(),
        ));
    }
    let form = vec![
        ("grant_type", "authorization_code".to_string()),
        ("client_id", issued.clone()),
        ("code", code),
        ("code_verifier", pending.verifier.clone()),
        ("redirect_uri", pending.redirect_uri.clone()),
        ("resource", RESOURCE.to_string()),
    ];
    let (status, payload) = post_token(&form, proxy)
        .await
        .map_err(|error| GatewayError::with_status(502, format!("SIWC 换码失败：{error}")))?;
    if !(200..300).contains(&status) {
        let (kind, description) = upstream_error(&payload);
        let detail = if description.is_empty() {
            format!("上游返回 HTTP {status}")
        } else {
            description
        };
        return Err(match kind.as_str() {
            "invalid_grant" => GatewayError::with_status(
                400,
                format!("SIWC 授权码已失效或已被使用：{detail}"),
            ),
            "invalid_client" | "unauthorized_client" => {
                GatewayError::with_status(401, format!("SIWC 客户端未被接受：{detail}"))
            }
            _ => GatewayError::with_status(502, format!("SIWC 换码失败（HTTP {status}）：{detail}")),
        });
    }
    let credentials = read_token(&payload, true)?;
    let stored = json!({
        "access_token": credentials.access_token,
        "refresh_token": credentials.refresh_token,
        "id_token": credentials.id_token,
        "client_id": issued,
        "scope": payload.get("scope").cloned().unwrap_or(Value::Null),
        "expires_at": credentials.expires_at,
        "device_id": pending.device_id,
        "last_refresh": crate::logging::now_ms(),
    });
    Ok((pending, stored))
}

/// 从用户输入里取出授权码。
fn extract_code(raw: &str) -> String {
    let text = raw.trim();
    if text.is_empty() {
        return String::new();
    }
    // 整段回调地址：取 query 里的 code。
    if text.contains("://") || text.starts_with('?') || text.contains("code=") {
        let from_url = extract_param(text, "code");
        if !from_url.is_empty() {
            return from_url;
        }
    }
    text.to_string()
}

/// 从 URL 或 query 串里取一个参数（百分号解码）。
fn extract_param(raw: &str, key: &str) -> String {
    let query = match raw.split_once('?') {
        Some((_, rest)) => rest,
        None => raw,
    };
    let query = query.split('#').next().unwrap_or(query);
    for pair in query.split('&') {
        let Some((name, value)) = pair.split_once('=') else {
            continue;
        };
        if name.trim() == key {
            return super::login::percent_decode(value.trim());
        }
    }
    String::new()
}

/// 从 SIWC 令牌换一对新令牌（刷新）。
///
/// 参考实现 `RefreshSIWCTokens`（`siwc_auth.go:312-350`）的 form 只有四个键：
/// `grant_type`、`client_id`、`refresh_token`、`resource` —— **没有 scope**。
pub async fn refresh(
    siwc: &Value,
    proxy: Option<&agent2api_provider_protocol::WireProxy>,
) -> Result<Value, GatewayError> {
    let refresh_token = siwc
        .get("refresh_token")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .trim()
        .to_string();
    let client_id = siwc
        .get("client_id")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .trim()
        .to_string();
    if refresh_token.is_empty() {
        return Err(GatewayError::with_status(
            401,
            "SIWC 通道缺少 refresh token，请重新绑定".to_string(),
        ));
    }
    if client_id.is_empty() {
        return Err(GatewayError::with_status(
            401,
            "SIWC 通道缺少服务端签发的 client_id，请重新绑定".to_string(),
        ));
    }
    let device_id = siwc
        .get("device_id")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    // 与普通 OAuth 刷新一样做单飞，避免并发把 refresh token 用掉两次。
    let key = format!(
        "codex-siwc:{}:{}",
        client_id,
        flight::fingerprint(&refresh_token)
    );
    let table = flights();
    match table.join(&key) {
        flight::Join::Waiter(waiter) => waiter.wait().await,
        flight::Join::Leader(leader) => {
            let result = refresh_once(&refresh_token, &client_id, &device_id, proxy).await;
            leader.finish(result.clone());
            result
        }
    }
}

/// 单飞表。
fn flights() -> &'static flight::Table<Value> {
    static FLIGHTS: OnceLock<flight::Table<Value>> = OnceLock::new();
    FLIGHTS.get_or_init(flight::Table::new)
}

/// 真正发一次刷新请求。
async fn refresh_once(
    refresh_token: &str,
    client_id: &str,
    device_id: &str,
    proxy: Option<&agent2api_provider_protocol::WireProxy>,
) -> Result<Value, GatewayError> {
    let form = vec![
        ("grant_type", "refresh_token".to_string()),
        ("client_id", client_id.to_string()),
        ("refresh_token", refresh_token.to_string()),
        ("resource", RESOURCE.to_string()),
    ];
    let (status, payload) = post_token(&form, proxy)
        .await
        .map_err(|error| GatewayError::with_status(502, format!("SIWC 刷新失败：{error}")))?;
    if !(200..300).contains(&status) {
        let (kind, description) = upstream_error(&payload);
        let detail = if description.is_empty() {
            format!("上游返回 HTTP {status}")
        } else {
            description
        };
        return Err(match kind.as_str() {
            "invalid_grant" => GatewayError::with_status(
                401,
                format!("SIWC 的 refresh token 已失效或被撤销，请重新绑定：{detail}"),
            ),
            "invalid_client" | "unauthorized_client" => {
                GatewayError::with_status(401, format!("SIWC 客户端未被接受：{detail}"))
            }
            _ => {
                GatewayError::with_status(502, format!("SIWC 刷新失败（HTTP {status}）：{detail}"))
            }
        });
    }
    let credentials = read_token(&payload, false)?;
    Ok(json!({
        "access_token": credentials.access_token,
        "refresh_token": credentials.refresh_token,
        "id_token": credentials.id_token,
        "client_id": client_id,
        "device_id": device_id,
        "expires_at": credentials.expires_at,
        "last_refresh": crate::logging::now_ms(),
    }))
}

/// 账号是否已绑定 SIWC。
pub fn bound(secret: &Value) -> bool {
    secret
        .pointer("/siwc/refresh_token")
        .and_then(Value::as_str)
        .map(|value| !value.trim().is_empty())
        .unwrap_or(false)
}

/// 把 `siwc` 子对象合进 secret（保留其它键）。
pub fn merge_into(secret: &Value, siwc: Value) -> Value {
    let mut next = secret.clone();
    if let Some(object) = next.as_object_mut() {
        object.insert("siwc".to_string(), siwc);
    }
    next
}

/// 按 SIWC 通道的规则清洗请求体。
///
/// 对照参考实现 `applyCodexSIWCRequestBodyRulesDoc`（`codex_executor_request.go`
/// :415-427）与 `stripCodexSIWCUnsupportedFieldsDoc`（:487-507）：
///
/// * `store` 强制 false —— SIWC 令牌没有 ChatGPT 会话存储权限；
/// * `stream` 强制 true；
/// * 删掉 `prompt_cache_retention` / `prompt_cache_options` /
///   `max_completion_tokens` / `temperature`（SIWC 授权不带这些能力）；
/// * `instructions` 为空时整条删掉（不是设成空串）。
pub fn shape_body(payload: &mut Value) {
    let Some(object) = payload.as_object_mut() else {
        return;
    };
    object.insert("store".to_string(), Value::Bool(false));
    object.insert("stream".to_string(), Value::Bool(true));
    for key in [
        "prompt_cache_retention",
        "prompt_cache_options",
        "max_completion_tokens",
        "temperature",
    ] {
        object.remove(key);
    }
    let empty_instructions = object
        .get("instructions")
        .map(|value| match value {
            Value::Null => true,
            Value::String(text) => text.trim().is_empty(),
            _ => false,
        })
        .unwrap_or(false);
    if empty_instructions {
        object.remove("instructions");
    }
}

#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_canonical_uuid_is_accepted() {
        assert!(is_valid_uuid("0193f0a1-2b3c-4d5e-8f90-a1b2c3d4e5f6"));
        assert!(is_valid_uuid("0193F0A1-2B3C-4D5E-8F90-A1B2C3D4E5F6"));
        assert!(is_valid_uuid("  0193f0a1-2b3c-4d5e-8f90-a1b2c3d4e5f6  "));
    }

    #[test]
    fn a_malformed_uuid_is_rejected() {
        assert!(!is_valid_uuid(""));
        assert!(!is_valid_uuid("not-a-uuid"));
        assert!(!is_valid_uuid("0193f0a12b3c4d5e8f90a1b2c3d4e5f6"));
        assert!(!is_valid_uuid("0193f0a1-2b3c-4d5e-8f90-a1b2c3d4e5fz"));
        // 位置错了也不行
        assert!(!is_valid_uuid("0193f0a12-b3c-4d5e-8f90-a1b2c3d4e5f6"));
    }

    #[test]
    fn the_authorization_url_carries_the_siwc_parameters() {
        let url = authorize_url(
            "st-1",
            "nonce-1",
            "0193f0a1-2b3c-4d5e-8f90-a1b2c3d4e5f6",
            "http://127.0.0.1:1455/auth/callback",
            "ch-1",
        )
        .unwrap();
        assert!(url.starts_with("https://auth.openai.com/api/accounts/authorize?"));
        assert!(url.contains("client_id=dynamic_agent_client"));
        assert!(url.contains("agent_name_hint=Agent2API"));
        assert!(url.contains(
            "ext_agent_host_id=urn%3Auuid%3A0193f0a1-2b3c-4d5e-8f90-a1b2c3d4e5f6"
        ));
        assert!(url.contains("resource=https%3A%2F%2Fapi.openai.com%2Fv1"));
        assert!(url.contains("code_challenge_method=S256"));
        assert!(url.contains("nonce=nonce-1"));
        assert!(url.contains("state=st-1"));
        assert!(url.contains("chatgpt.tokens.use.direct"));
    }

    #[test]
    fn a_bad_device_id_stops_the_url() {
        let error = authorize_url("st", "nonce", "nope", "http://127.0.0.1/cb", "ch").unwrap_err();
        assert_eq!(error.status_code, 400);
        assert!(error.message.contains("UUID"));
    }

    #[test]
    fn an_existing_device_id_is_reused() {
        let secret = json!({"siwc": {"device_id": "0193F0A1-2B3C-4D5E-8F90-A1B2C3D4E5F6"}});
        assert_eq!(
            device_id_of(&secret),
            "0193f0a1-2b3c-4d5e-8f90-a1b2c3d4e5f6"
        );
    }

    #[test]
    fn a_missing_device_id_is_generated() {
        let generated = device_id_of(&json!({}));
        assert!(is_valid_uuid(&generated), "generated = {generated}");
        assert_eq!(generated, generated.to_ascii_lowercase());
    }

    #[test]
    fn a_token_response_is_read_strictly() {
        let payload = json!({
            "access_token": "at",
            "refresh_token": "rt",
            "id_token": "it",
            "expires_in": 3600,
            "scope": "openid chatgpt.tokens.use.direct",
        });
        let credentials = read_token(&payload, true).unwrap();
        assert_eq!(credentials.access_token, "at");
        assert_eq!(credentials.refresh_token, "rt");
        assert_eq!(credentials.id_token, "it");
        assert!(credentials.expires_at > 0);
    }

    #[test]
    fn a_token_response_without_the_direct_scope_is_refused() {
        let payload = json!({
            "access_token": "at",
            "refresh_token": "rt",
            "id_token": "it",
            "expires_in": 3600,
            "scope": "openid profile",
        });
        let error = read_token(&payload, true).err().expect("应当拒绝");
        assert_eq!(error.status_code, 502);
        assert!(error.message.contains(DIRECT_TOKEN_SCOPE));
    }

    #[test]
    fn an_exchange_without_an_id_token_is_refused() {
        let payload = json!({
            "access_token": "at",
            "refresh_token": "rt",
            "expires_in": 3600,
            "scope": "chatgpt.tokens.use.direct",
        });
        let error = read_token(&payload, true).err().expect("应当拒绝");
        assert!(error.message.contains("id_token"));
        // 刷新时 id_token 可以不回。
        assert!(read_token(&payload, false).is_ok());
    }

    #[test]
    fn a_scope_omitted_on_refresh_does_not_discard_the_token() {
        let payload = json!({
            "access_token": "at",
            "refresh_token": "rt2",
            "expires_in": 3600,
        });
        let credentials = read_token(&payload, false).unwrap();
        assert_eq!(credentials.refresh_token, "rt2");
    }

    #[test]
    fn a_bad_expires_in_is_refused() {
        for bad in [json!(0), json!(-1), json!("nope"), Value::Null] {
            let payload = json!({
                "access_token": "at",
                "refresh_token": "rt",
                "id_token": "it",
                "expires_in": bad,
            });
            assert!(read_token(&payload, true).is_err(), "expires_in = {bad}");
        }
    }

    #[test]
    fn a_numeric_string_expires_in_is_accepted() {
        let payload = json!({
            "access_token": "at",
            "refresh_token": "rt",
            "id_token": "it",
            "expires_in": "3600",
        });
        assert!(read_token(&payload, true).is_ok());
    }

    #[test]
    fn a_pasted_callback_url_yields_the_code_and_client_id() {
        let raw = "http://127.0.0.1:1455/auth/callback?code=abc123&state=st-1&client_id=issued-client";
        assert_eq!(extract_code(raw), "abc123");
        assert_eq!(extract_param(raw, "client_id"), "issued-client");
        assert_eq!(extract_param(raw, "state"), "st-1");
    }

    #[test]
    fn a_plain_code_is_kept_whole() {
        assert_eq!(extract_code("abc123"), "abc123");
    }

    #[test]
    fn a_percent_encoded_value_is_decoded() {
        assert_eq!(extract_param("code=a%2Bb", "code"), "a+b");
    }

    #[test]
    fn an_unbound_account_reports_unbound() {
        assert!(!bound(&json!({})));
        assert!(!bound(&json!({"siwc": {"refresh_token": ""}})));
        assert!(bound(&json!({"siwc": {"refresh_token": "rt"}})));
    }

    #[test]
    fn merging_keeps_the_other_keys() {
        let secret = json!({"refreshToken": "outer", "email": "a@b.c"});
        let next = merge_into(&secret, json!({"refresh_token": "inner"}));
        assert_eq!(next["refreshToken"], json!("outer"));
        assert_eq!(next["email"], json!("a@b.c"));
        assert_eq!(next["siwc"]["refresh_token"], json!("inner"));
    }

    #[test]
    fn an_expired_pending_entry_is_swept() {
        let mut table = HashMap::new();
        table.insert(
            "old".to_string(),
            Pending {
                verifier: "v".to_string(),
                state: "old".to_string(),
                nonce: "n".to_string(),
                device_id: "0193f0a1-2b3c-4d5e-8f90-a1b2c3d4e5f6".to_string(),
                redirect_uri: "http://127.0.0.1/cb".to_string(),
                created_at: crate::logging::now_ms() - PENDING_TTL_MS - 1,
            },
        );
        table.insert(
            "fresh".to_string(),
            Pending {
                verifier: "v".to_string(),
                state: "fresh".to_string(),
                nonce: "n".to_string(),
                device_id: "0193f0a1-2b3c-4d5e-8f90-a1b2c3d4e5f6".to_string(),
                redirect_uri: "http://127.0.0.1/cb".to_string(),
                created_at: crate::logging::now_ms(),
            },
        );
        sweep(&mut table);
        assert!(!table.contains_key("old"));
        assert!(table.contains_key("fresh"));
    }

    #[test]
    fn the_siwc_body_rule_strips_unsupported_fields() {
        let mut payload = json!({
            "model": "gpt-5.4",
            "stream": false,
            "store": true,
            "prompt_cache_retention": "24h",
            "prompt_cache_options": {"mode": "explicit"},
            "max_completion_tokens": 100,
            "temperature": 0.7,
            "instructions": "   ",
            "input": [],
        });
        shape_body(&mut payload);
        assert_eq!(payload["stream"], json!(true));
        assert_eq!(payload["store"], json!(false));
        for key in [
            "prompt_cache_retention",
            "prompt_cache_options",
            "max_completion_tokens",
            "temperature",
            "instructions",
        ] {
            assert!(payload.get(key).is_none(), "{key} 应当被删掉");
        }
        assert_eq!(payload["model"], json!("gpt-5.4"));
        assert!(payload.get("input").is_some());
    }

    #[test]
    fn a_non_empty_instructions_survives_the_siwc_rule() {
        let mut payload = json!({"instructions": "be brief", "stream": true});
        shape_body(&mut payload);
        assert_eq!(payload["instructions"], json!("be brief"));
    }

    #[test]
    fn the_siwc_user_agent_has_the_reference_shape() {
        let ua = endpoints::siwc_user_agent();
        assert!(ua.starts_with("Agent2API ("), "ua = {ua}");
        assert!(ua.ends_with(')'), "ua = {ua}");
        assert!(ua.contains(std::env::consts::OS), "ua = {ua}");
    }

    #[test]
    fn the_siwc_headers_omit_the_chatgpt_fingerprint() {
        let headers = endpoints::siwc_responses_headers("tok", "sess-1");
        let names: Vec<&str> = headers.iter().map(|(key, _)| key.as_str()).collect();
        assert!(names.contains(&"Authorization"));
        assert!(names.contains(&"session_id"));
        assert!(names.contains(&"X-Client-Request-Id"));
        // 这三条只属于普通 OAuth 分支。
        assert!(!names.iter().any(|name| name.eq_ignore_ascii_case("Originator")));
        assert!(!names
            .iter()
            .any(|name| name.eq_ignore_ascii_case("Chatgpt-Account-Id")));
        assert!(!names.contains(&endpoints::ROUTING_HINT_HEADER));
    }
}
