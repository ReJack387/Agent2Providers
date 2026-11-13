//! Claude 的 OAuth：PKCE / 换码 / 刷新 / 账号信息尽力读取。
//!
//! ── 与 Google 家（Antigravity）的三处关键差别 ────────────────
//! 1. **换码与刷新都是 JSON body**，不是 `application/x-www-form-urlencoded`
//!    （参考实现 `authorizationCodeExchangeRequest` 就是个 struct 直接编码）。
//! 2. **换码端点不是 `api.anthropic.com`**：Claude Code 2.1.x 打的是
//!    `platform.claude.com/v1/oauth/token`（见 `endpoints::TOKEN_URL` 的注释）。
//! 3. **授权 URL 的 scope 多一个 `org:create_api_key`**，而刷新用的 scope 没有
//!    它 —— 两者不能混用，混了会被判 scope 不匹配。
//!
//! ── 为什么刷新失败不重试 ────────────────────────────────────
//! 参考实现明确写了：Anthropic 的 refresh token 是**一次性**的，重放会把一次
//! 瞬时网络故障变成永久的 `invalid_grant`（账号直接废掉）。因此这里只在
//! 「上游明确回了 5xx」时认为没消费，其余一律不重试。
//!
//! ── 硬约束 ──────────────────────────────────────────────────
//! release 是 `panic=abort`：本文件零 unwrap / expect / panic。

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::errors::GatewayError;
use crate::flight;
use crate::logging;
use crate::store;

use super::credentials::ClaudeCredentials;
use super::endpoints;

/// 一条账号记录里的 secret 视图（写回时用来做「比较再写」）。
pub struct Refreshed {
    pub credentials: ClaudeCredentials,
    /// 上游这次有没有换发新的 refresh token。
    pub refresh_rotated: bool,
}

/// PKCE 材料。
pub struct Pkce {
    pub verifier: String,
    pub challenge: String,
}

/// 造一套 PKCE（verifier 128 字符，challenge = SHA-256 → base64url 无填充）。
///
/// ── 为什么 verifier 用 96 字节 ──────────────────────────────
/// RFC 7636 允许 43–128 字符；参考实现取上限 128（96 字节随机）。取上限的
/// 好处是与原生客户端逐字同形 —— 上游对「短 verifier」没有额外惩罚，但
/// 长得像原生客户端永远不吃亏。
pub fn pkce() -> Result<Pkce, GatewayError> {
    let mut raw = [0u8; 96];
    getrandom::getrandom(&mut raw)
        .map_err(|error| GatewayError::new(format!("生成 PKCE 随机数失败：{error}")))?;
    let verifier = URL_SAFE_NO_PAD.encode(raw);
    let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
    Ok(Pkce {
        verifier,
        challenge,
    })
}

/// 造一个 OAuth `state`（32 字节随机 → 43 字符 base64url）。
pub fn new_state() -> Result<String, GatewayError> {
    let mut raw = [0u8; 32];
    getrandom::getrandom(&mut raw)
        .map_err(|error| GatewayError::new(format!("生成 state 失败：{error}")))?;
    Ok(URL_SAFE_NO_PAD.encode(raw))
}

/// 授权地址（PKCE + state）。
pub fn authorize_url(redirect_uri: &str, state: &str, challenge: &str) -> Result<String, GatewayError> {
    let url = endpoints::authorize_url(redirect_uri, state, challenge);
    if url.is_empty() {
        return Err(GatewayError::new("Claude 授权地址构造失败（端点常量不合法）"));
    }
    Ok(url)
}

/// 把上游错误体压成一句可读的话。
fn upstream_error(payload: &Value) -> (String, String) {
    let code = payload
        .get("error")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .trim()
        .to_string();
    let description = payload
        .get("error_description")
        .and_then(Value::as_str)
        .or_else(|| payload.get("message").and_then(Value::as_str))
        .unwrap_or_default()
        .trim()
        .to_string();
    (code, description)
}

/// 按字符（不是字节）截断，避免把多字节字符劈开。
fn truncate(text: &str) -> String {
    let trimmed = text.trim();
    if trimmed.chars().count() <= endpoints::MAX_ERROR_CHARS {
        return trimmed.to_string();
    }
    trimmed.chars().take(endpoints::MAX_ERROR_CHARS).collect()
}

/// 从 token 响应里读 `expires_in`（数字或数字字符串都认）。
fn expires_in_of(payload: &Value) -> i64 {
    let raw = payload.get("expires_in");
    let value = match raw {
        Some(Value::Number(number)) => number.as_i64().or_else(|| number.as_f64().map(|f| f as i64)),
        Some(Value::String(text)) => text.trim().parse::<i64>().ok(),
        _ => None,
    };
    match value {
        // 越界的值一律按默认时长算，避免把 expires_at 算到几十年后。
        Some(seconds) if (1..=7 * 24 * 3600).contains(&seconds) => seconds,
        _ => endpoints::DEFAULT_EXPIRES_IN_SECONDS,
    }
}

/// 发一次 OAuth 请求（JSON body）。
async fn post_oauth(
    url: &str,
    body: &Value,
    proxy: Option<&agent2api_provider_protocol::WireProxy>,
) -> Result<(u16, Value), String> {
    let client = crate::http::control_client(proxy, "direct");
    let headers = endpoints::oauth_headers();
    let mut request = client
        .post(url)
        .timeout(std::time::Duration::from_millis(endpoints::REQUEST_TIMEOUT_MS))
        .body(body.to_string());
    for (key, value) in &headers {
        request = request.header(key.as_str(), value.as_str());
    }
    let response = request.send().await.map_err(|error| {
        let base = crate::http::describe_chain(&error);
        if error.is_connect() {
            format!("{base}（本机访问 claude.ai / platform.claude.com 需经代理时：请开启系统代理，或给该账号配置出网代理）")
        } else {
            base
        }
    })?;
    let status = response.status().as_u16();
    let text = response.text().await.unwrap_or_default();
    let payload = serde_json::from_str::<Value>(&text).unwrap_or(Value::Null);
    Ok((status, payload))
}

/// 换码失败 → 网关错误。
fn classify_exchange_failure(status: u16, text: &str, payload: &Value) -> GatewayError {
    let (code, description) = upstream_error(payload);
    let detail = if description.is_empty() {
        truncate(text)
    } else {
        truncate(&description)
    };
    match code.as_str() {
        "invalid_grant" => GatewayError::with_status(
            400,
            format!("Claude 授权码已失效或已被使用：{detail}"),
        ),
        "redirect_uri_mismatch" => GatewayError::with_status(
            400,
            format!("Claude 授权页登记的 redirect_uri 与换码时给的不一致：{detail}"),
        ),
        "invalid_client" | "unauthorized_client" => {
            GatewayError::with_status(401, format!("Claude OAuth 客户端未被接受：{detail}"))
        }
        _ => GatewayError::with_status(
            502,
            format!(
                "Claude 换码失败（HTTP {status}）：{}",
                if detail.is_empty() {
                    "上游没有给出原因".to_string()
                } else {
                    detail
                }
            ),
        ),
    }
}

/// 用授权码换凭证。
///
/// `redirect_uri` 必须与授权 URL 里那个**逐字相同**（包括端口），否则上游回
/// `redirect_uri_mismatch`。
pub async fn exchange_code(
    code: &str,
    state: &str,
    verifier: &str,
    redirect_uri: &str,
    proxy: Option<&agent2api_provider_protocol::WireProxy>,
) -> Result<ClaudeCredentials, GatewayError> {
    let code = code.trim();
    if code.is_empty() {
        return Err(GatewayError::with_status(400, "Claude 回调没有带回授权码"));
    }
    if code.len() > endpoints::MAX_CODE_LENGTH {
        return Err(GatewayError::with_status(400, "Claude 授权码长度异常"));
    }
    if state.len() > endpoints::MAX_STATE_LENGTH {
        return Err(GatewayError::with_status(400, "Claude 回调的 state 长度异常"));
    }
    if redirect_uri.trim().is_empty() {
        return Err(GatewayError::new("Claude 换码缺少 redirect_uri"));
    }
    // 字段顺序与参考实现一致：grant_type → code → redirect_uri → client_id →
    // code_verifier → state。JSON 顺序对上游没有语义，但保持同形便于对日志。
    let body = json!({
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": redirect_uri,
        "client_id": endpoints::CLIENT_ID,
        "code_verifier": verifier,
        "state": state,
    });
    let (status, payload) = post_oauth(endpoints::TOKEN_URL, &body, proxy)
        .await
        .map_err(|message| GatewayError::new(format!("Claude 换码请求失败：{message}")))?;
    if !(200..300).contains(&status) {
        let text = payload.to_string();
        return Err(classify_exchange_failure(status, &text, &payload));
    }
    let access_token = payload
        .get("access_token")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .trim()
        .to_string();
    if access_token.is_empty() {
        return Err(GatewayError::with_status(
            502,
            "Claude 换码成功但上游没有返回 access_token",
        ));
    }
    let refresh_token = payload
        .get("refresh_token")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .trim()
        .to_string();
    let mut credentials = ClaudeCredentials {
        access_token,
        refresh_token,
        expires_at: logging::now_ms() + expires_in_of(&payload) * 1000,
        ..Default::default()
    };
    // token 响应里通常已经带了组织与邮箱；再用 profile / roles 补一次。
    absorb_token_metadata(&mut credentials, &payload);
    inspect_account(&mut credentials, proxy).await;
    Ok(credentials)
}

/// 从 token 响应里吸走组织与邮箱（`organization` / `account` 两个子对象）。
fn absorb_token_metadata(credentials: &mut ClaudeCredentials, payload: &Value) {
    let email = payload
        .pointer("/account/email_address")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .trim();
    if !email.is_empty() {
        credentials.email = email.to_string();
    }
    let account_uuid = payload
        .pointer("/account/uuid")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .trim();
    if !account_uuid.is_empty() {
        credentials.account_uuid = account_uuid.to_string();
    }
    let organization_uuid = payload
        .pointer("/organization/uuid")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .trim();
    if !organization_uuid.is_empty() {
        credentials.organization_uuid = organization_uuid.to_string();
    }
    let organization_name = payload
        .pointer("/organization/name")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .trim();
    if !organization_name.is_empty() {
        credentials.organization_name = organization_name.to_string();
    }
}

/// 尽力补全账号信息（profile → roles）。
///
/// ── 为什么失败不阻断 ────────────────────────────────────────
/// 换码已经成功了，令牌是能用的；profile / roles 只影响界面显示（邮箱、组织
/// 名、套餐）。因为一个展示字段把「已经拿到手的令牌」丢掉是最差的选择。
/// 参考实现同样只 warn。
pub async fn inspect_account(
    credentials: &mut ClaudeCredentials,
    proxy: Option<&agent2api_provider_protocol::WireProxy>,
) {
    let token = credentials.access_token.trim().to_string();
    if token.is_empty() {
        return;
    }
    let client = crate::http::control_client(proxy, "direct");
    let headers = endpoints::inspect_headers(&token);

    if let Ok(response) = build_get(&client, endpoints::PROFILE_URL, &headers)
        .send()
        .await
    {
        if response.status().is_success() {
            let payload = response
                .json::<Value>()
                .await
                .unwrap_or(Value::Null);
            let email = payload
                .pointer("/account/email")
                .or_else(|| payload.pointer("/account/email_address"))
                .and_then(Value::as_str)
                .unwrap_or_default()
                .trim();
            if !email.is_empty() {
                credentials.email = email.to_string();
            }
            let account_uuid = payload
                .pointer("/account/uuid")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .trim();
            if !account_uuid.is_empty() {
                credentials.account_uuid = account_uuid.to_string();
            }
            let organization_uuid = payload
                .pointer("/organization/uuid")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .trim();
            if !organization_uuid.is_empty() {
                credentials.organization_uuid = organization_uuid.to_string();
            }
            let organization_name = payload
                .pointer("/organization/name")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .trim();
            if !organization_name.is_empty() {
                credentials.organization_name = organization_name.to_string();
            }
        } else {
            logging::verbose("[Claude]", "读取 profile 未成功（不影响令牌可用性）");
        }
    }

    if let Ok(response) = build_get(&client, endpoints::ROLES_URL, &headers)
        .send()
        .await
    {
        if response.status().is_success() {
            let payload = response.json::<Value>().await.unwrap_or(Value::Null);
            // roles 的形态不固定（可能是数组、可能是带 plan 的对象），
            // 只挑几个确定的键，读不到就算了。
            let plan = payload
                .pointer("/plan")
                .or_else(|| payload.pointer("/subscription/plan"))
                .or_else(|| payload.pointer("/organization/plan"))
                .and_then(Value::as_str)
                .unwrap_or_default()
                .trim();
            if !plan.is_empty() {
                credentials.plan = plan.to_string();
            }
        }
    }
}

/// 造一个带齐头的 GET（profile / roles 用）。
fn build_get(
    client: &reqwest::Client,
    url: &str,
    headers: &[(String, String)],
) -> reqwest::RequestBuilder {
    let mut request = client
        .get(url)
        .timeout(std::time::Duration::from_millis(endpoints::REQUEST_TIMEOUT_MS));
    for (key, value) in headers {
        request = request.header(key.as_str(), value.as_str());
    }
    request
}

/// 刷新失败 → 网关错误。
fn classify_refresh_failure(status: u16, text: &str, payload: &Value) -> GatewayError {
    let (code, description) = upstream_error(payload);
    let detail = if description.is_empty() {
        truncate(text)
    } else {
        truncate(&description)
    };
    match code.as_str() {
        "invalid_grant" => GatewayError::with_status(
            401,
            format!("Claude refresh token 已失效或被撤销，请重新登录：{detail}"),
        ),
        "invalid_client" | "unauthorized_client" => GatewayError::with_status(
            401,
            format!("Claude OAuth 客户端未被接受（令牌可能来自别的客户端）：{detail}"),
        ),
        _ => GatewayError::with_status(
            502,
            format!(
                "Claude 刷新令牌失败（HTTP {status}）：{}",
                if detail.is_empty() {
                    "上游没有给出原因".to_string()
                } else {
                    detail
                }
            ),
        ),
    }
}

/// 刷新一次（不落盘、不单飞）。
pub async fn refresh_access_token(
    refresh_token: &str,
    proxy: Option<&agent2api_provider_protocol::WireProxy>,
) -> Result<Refreshed, GatewayError> {
    let token = refresh_token.trim();
    if token.is_empty() {
        return Err(GatewayError::with_status(
            401,
            "Claude 账号没有 refresh token，无法续期（请重新登录）",
        ));
    }
    // 刷新的 scope 用不带 `org:create_api_key` 的那份（见模块头第 3 条）。
    let body = json!({
        "client_id": endpoints::CLIENT_ID,
        "grant_type": "refresh_token",
        "refresh_token": token,
        "scope": endpoints::OAUTH_SCOPE,
    });
    let (status, payload) = post_oauth(endpoints::TOKEN_URL, &body, proxy)
        .await
        .map_err(|message| GatewayError::new(format!("Claude 刷新请求失败：{message}")))?;
    if !(200..300).contains(&status) {
        let text = payload.to_string();
        return Err(classify_refresh_failure(status, &text, &payload));
    }
    let access_token = payload
        .get("access_token")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .trim()
        .to_string();
    if access_token.is_empty() {
        return Err(GatewayError::with_status(
            502,
            "Claude 刷新成功但上游没有返回 access_token",
        ));
    }
    let rotated = payload
        .get("refresh_token")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string);
    let refresh_rotated = rotated.is_some();
    let mut credentials = ClaudeCredentials {
        refresh_token: rotated.unwrap_or_else(|| token.to_string()),
        access_token,
        expires_at: logging::now_ms() + expires_in_of(&payload) * 1000,
        ..Default::default()
    };
    absorb_token_metadata(&mut credentials, &payload);
    Ok(Refreshed {
        credentials,
        refresh_rotated,
    })
}

/// 读一条账号记录（点名的账号取不到直接报错，**不回落队首**）。
pub async fn read_record(
    ctx: &agent2api_provider_sdk::PluginCtx,
    account_id: &str,
) -> Result<Value, GatewayError> {
    store::record(ctx, super::PROVIDER_ID, account_id).await
}

/// 确保拿到一个可用的 access token（临期主动刷 + 单飞 + 比较再写）。
pub async fn ensure_fresh(
    ctx: &agent2api_provider_sdk::PluginCtx,
    account_id: &str,
    force: bool,
) -> Result<ClaudeCredentials, GatewayError> {
    let record = read_record(ctx, account_id).await?;
    let credentials = super::credentials::from_record(Some(&record))?;
    if !force && !credentials.expiring() {
        return Ok(credentials);
    }
    if !credentials.can_refresh() {
        return Err(GatewayError::with_status(
            401,
            "Claude 账号没有 refresh token，无法续期（请重新登录）",
        ));
    }
    // 单飞：同一 refresh token 只允许一次真实刷新，其余等结果。
    let key = format!(
        "claude:{}:{}",
        account_id,
        flight::fingerprint(&credentials.refresh_token)
    );
    let table = flights();
    match table.join(&key) {
        flight::Join::Waiter(waiter) => {
            let refreshed = waiter.wait().await?;
            Ok(refreshed)
        }
        flight::Join::Leader(leader) => {
            let result = refresh_and_save(ctx, &record, &credentials).await;
            let payload = result.clone();
            leader.finish(result);
            payload
        }
    }
}

/// 进程内单飞表。
fn flights() -> &'static flight::Table<ClaudeCredentials> {
    static FLIGHTS: std::sync::OnceLock<flight::Table<ClaudeCredentials>> =
        std::sync::OnceLock::new();
    FLIGHTS.get_or_init(flight::Table::new)
}

/// 刷新并把结果写回账号记录。
async fn refresh_and_save(
    ctx: &agent2api_provider_sdk::PluginCtx,
    record: &Value,
    credentials: &ClaudeCredentials,
) -> Result<ClaudeCredentials, GatewayError> {
    let proxy = super::account_proxy(record)?;
    let refreshed = refresh_access_token(&credentials.refresh_token, proxy.as_ref()).await?;
    let mut next = credentials.clone();
    next.access_token = refreshed.credentials.access_token.clone();
    next.expires_at = refreshed.credentials.expires_at;
    if refreshed.refresh_rotated {
        next.refresh_token = refreshed.credentials.refresh_token.clone();
    }
    // 组织 / 邮箱只在原来为空时补，不覆盖用户看到的既有值。
    if next.email.trim().is_empty() && !refreshed.credentials.email.trim().is_empty() {
        next.email = refreshed.credentials.email.clone();
    }
    if next.organization_uuid.trim().is_empty()
        && !refreshed.credentials.organization_uuid.trim().is_empty()
    {
        next.organization_uuid = refreshed.credentials.organization_uuid.clone();
    }
    if next.organization_name.trim().is_empty()
        && !refreshed.credentials.organization_name.trim().is_empty()
    {
        next.organization_name = refreshed.credentials.organization_name.clone();
    }
    write_back(ctx, record, &next).await;
    Ok(next)
}

/// 把新令牌写回记录（比较再写；失败只记日志）。
///
/// ── 为什么写失败不算刷新失败 ────────────────────────────────
/// 令牌已经拿到手了，这一次请求完全可以用它跑完；写不进去说明期间记录被别处
/// 改过（换账号 / 被删），下一轮会重新读盘并再刷一次。把「已经刷成功」判成
/// 失败等于白白多打一次上游、还多烧掉一个一次性 refresh token。
async fn write_back(
    ctx: &agent2api_provider_sdk::PluginCtx,
    record: &Value,
    credentials: &ClaudeCredentials,
) {
    let account_id = record.get("id").and_then(Value::as_str).unwrap_or_default();
    if account_id.is_empty() {
        return;
    }
    let expect = store::secret_view(record);
    let fields: Vec<(&str, Value)> = vec![
        (
            "accessToken",
            Value::String(credentials.access_token.clone()),
        ),
        ("refreshToken", Value::String(credentials.refresh_token.clone())),
        (
            "expiresAt",
            Value::Number(serde_json::Number::from(credentials.expires_at)),
        ),
    ];
    let next = store::with_fields(&expect, &fields);
    match store::save(ctx, account_id, &expect, &next).await {
        Ok(true) => {}
        Ok(false) => logging::warn(
            "[Claude]",
            "刷新结果未能写回账号记录（期间被改动过），本次请求用新令牌",
        ),
        Err(error) => logging::warn(
            "[Claude]",
            &format!("刷新结果写回账号记录失败：{}", error.message),
        ),
    }
}

#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pkce_material_sits_inside_the_rfc_range() {
        let value = pkce().expect("pkce");
        assert_eq!(value.verifier.len(), 128, "参考实现取 RFC 上限");
        assert_eq!(value.challenge.len(), 43, "SHA-256 → base64url 恒 43 字符");
        assert!(!value.verifier.contains('='), "必须是 url-safe 无填充");
    }

    #[test]
    fn state_is_short_and_url_safe() {
        let state = new_state().expect("state");
        assert_eq!(state.len(), 43);
        assert!(state
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || ch == '-' || ch == '_'));
    }

    #[test]
    fn authorize_url_carries_every_required_parameter() {
        let url = authorize_url("http://localhost:54545/callback", "st", "ch").expect("url");
        for needle in [
            "code=true",
            "response_type=code",
            "code_challenge_method=S256",
            "state=st",
            "code_challenge=ch",
        ] {
            assert!(url.contains(needle), "missing {needle} in {url}");
        }
        // 授权 scope 必须带 org:create_api_key（换码/刷新用的那份不带）。
        assert!(url.contains("org%3Acreate_api_key") || url.contains("org:create_api_key"));
    }

    #[test]
    fn expires_in_accepts_numbers_and_strings() {
        assert_eq!(expires_in_of(&json!({"expires_in": 28800})), 28_800);
        assert_eq!(expires_in_of(&json!({"expires_in": "28800"})), 28_800);
        // 越界与缺失都回落到默认时长。
        assert_eq!(
            expires_in_of(&json!({"expires_in": 0})),
            endpoints::DEFAULT_EXPIRES_IN_SECONDS
        );
        assert_eq!(
            expires_in_of(&json!({})),
            endpoints::DEFAULT_EXPIRES_IN_SECONDS
        );
        assert_eq!(
            expires_in_of(&json!({"expires_in": 99_999_999})),
            endpoints::DEFAULT_EXPIRES_IN_SECONDS
        );
    }

    #[test]
    fn token_metadata_is_absorbed_from_nested_objects() {
        let payload = json!({
            "access_token": "a",
            "account": {"uuid": "acct", "email_address": "u@e.com"},
            "organization": {"uuid": "org", "name": "Acme"},
        });
        let mut credentials = ClaudeCredentials::default();
        absorb_token_metadata(&mut credentials, &payload);
        assert_eq!(credentials.email, "u@e.com");
        assert_eq!(credentials.account_uuid, "acct");
        assert_eq!(credentials.organization_uuid, "org");
        assert_eq!(credentials.organization_name, "Acme");
    }

    #[test]
    fn invalid_grant_maps_to_a_login_again_message() {
        let error = classify_refresh_failure(
            400,
            "{}",
            &json!({"error": "invalid_grant", "error_description": "expired"}),
        );
        assert_eq!(error.status_code, 401);
        assert!(error.message.contains("重新登录"));
    }

    #[test]
    fn unknown_exchange_failure_is_a_bad_gateway() {
        let error = classify_exchange_failure(500, "boom", &json!({}));
        assert_eq!(error.status_code, 502);
        assert!(error.message.contains("500"));
    }
}
