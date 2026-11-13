//! Codex 的 OAuth：PKCE / 换码 / 刷新 / 设备流。
//!
//! ── 与 Claude 家（`providers/claude/oauth.rs`）的三处关键差别 ──
//! 1. **换码与刷新都是 form-urlencoded**，不是 JSON（参考实现 `url.Values`）。
//! 2. **刷新响应是严格判据**：`access_token` 必须是非空 string、`expires_in`
//!    必须是 >0 的 number、`refresh_token` 必须是非空 string，任一不满足即判
//!    失败 —— 参考实现把这种情况单列为 `RefreshOutcomeUnknownError{Stage:
//!    "response-decode"}`，因为「拿到了但解不出」与「没拿到」的处置不同。
//! 3. **多一条设备流**（`shouldUseCodexDeviceFlow`）：无浏览器的环境用
//!    user code 轮询，拿到授权码后仍走同一套换码。
//!
//! ── 为什么刷新不重试 ────────────────────────────────────────
//! 与 Claude 家同理：参考实现有 refresh journal（`refresh_journal.go`）保证
//! 「一次成功即记账」，就是为了避免重放把瞬时故障变成 `invalid_grant`。这里
//! 只做单飞，不做重试。
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

use super::credentials::{self, CodexCredentials};
use super::endpoints;

/// 刷新结果。
pub struct Refreshed {
    pub credentials: CodexCredentials,
    /// 上游这次有没有换发新的 refresh token。
    pub refresh_rotated: bool,
}

/// PKCE 材料。
pub struct Pkce {
    pub verifier: String,
    pub challenge: String,
}

/// 造一套 PKCE（verifier 128 字符，challenge = SHA-256 → base64url 无填充）。
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
pub fn authorize_url(
    redirect_uri: &str,
    state: &str,
    challenge: &str,
) -> Result<String, GatewayError> {
    let url = endpoints::authorize_url(redirect_uri, state, challenge);
    if url.is_empty() {
        return Err(GatewayError::new(
            "Codex 授权地址构造失败（端点常量不合法）",
        ));
    }
    Ok(url)
}

/// 把上游错误体压成 (code, description)。
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

/// 按字符（不是字节）截断。
fn truncate(text: &str) -> String {
    let trimmed = text.trim();
    if trimmed.chars().count() <= endpoints::MAX_ERROR_CHARS {
        return trimmed.to_string();
    }
    trimmed.chars().take(endpoints::MAX_ERROR_CHARS).collect()
}

/// POST 一个 form 到 OAuth 端点。
async fn post_form(
    url: &str,
    form: &[(&str, String)],
    proxy: Option<&agent2api_provider_protocol::WireProxy>,
) -> Result<(u16, Value), String> {
    let client = crate::http::control_client(proxy, "direct");
    let mut request = client
        .post(url)
        .timeout(std::time::Duration::from_millis(endpoints::REQUEST_TIMEOUT_MS));
    for (key, value) in endpoints::oauth_headers() {
        request = request.header(key.as_str(), value.as_str());
    }
    let response = request.form(form).send().await.map_err(|error| {
        let base = crate::http::describe(&error);
        if error.is_connect() {
            format!(
                "{base}（本机访问 auth.openai.com 需经代理时：请开启系统代理，或给该账号配置出网代理）"
            )
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
            format!("Codex 授权码已失效或已被使用：{detail}"),
        ),
        "invalid_client" | "unauthorized_client" => GatewayError::with_status(
            401,
            format!("Codex OAuth 客户端未被接受：{detail}"),
        ),
        _ => GatewayError::with_status(
            502,
            format!(
                "Codex 换取令牌失败（HTTP {status}）：{}",
                if detail.is_empty() {
                    "上游没有给出原因".to_string()
                } else {
                    detail
                }
            ),
        ),
    }
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
            format!("Codex refresh token 已失效或被撤销，请重新登录：{detail}"),
        ),
        "invalid_client" | "unauthorized_client" => GatewayError::with_status(
            401,
            format!("Codex OAuth 客户端未被接受：{detail}"),
        ),
        _ => GatewayError::with_status(
            502,
            format!(
                "Codex 刷新令牌失败（HTTP {status}）：{}",
                if detail.is_empty() {
                    "上游没有给出原因".to_string()
                } else {
                    detail
                }
            ),
        ),
    }
}

/// 从换码 / 刷新响应里读出凭证。
///
/// ── 严格判据 ────────────────────────────────────────────────
/// 参考实现 `CodexTokenData` 的三个字段缺一不可：`access_token` 非空 string、
/// `expires_in` >0 的 number、`refresh_token` 非空 string。少一个就说明上游回了
/// 意料之外的东西（可能是维护页 / 错误信封），继续用会得到一串 401。
fn read_token_response(
    payload: &Value,
    fallback_refresh: Option<&str>,
) -> Result<Refreshed, GatewayError> {
    let access_token = payload
        .get("access_token")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            GatewayError::with_status(502, "Codex 上游没有返回可用的 access_token")
        })?;
    let expires_in = payload
        .get("expires_in")
        .and_then(Value::as_i64)
        .filter(|seconds| *seconds > 0)
        .ok_or_else(|| {
            GatewayError::with_status(502, "Codex 上游没有返回有效的 expires_in（应为正整数秒）")
        })?;
    let upstream_refresh = payload
        .get("refresh_token")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty());
    let refresh_token = match (upstream_refresh, fallback_refresh) {
        (Some(value), _) => value.to_string(),
        (None, Some(value)) => value.to_string(),
        (None, None) => {
            return Err(GatewayError::with_status(
                502,
                "Codex 上游没有返回 refresh_token（首次登录必须拿到它，否则无法续期）",
            ))
        }
    };
    let refresh_rotated = upstream_refresh.is_some();
    let mut credentials = CodexCredentials {
        refresh_token,
        access_token: access_token.to_string(),
        id_token: payload
            .get("id_token")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .trim()
            .to_string(),
        expires_at: logging::now_ms() + expires_in * 1000,
        ..Default::default()
    };
    credentials::absorb_id_token(&mut credentials);
    Ok(Refreshed {
        credentials,
        refresh_rotated,
    })
}

/// 换一次授权码。
pub async fn exchange_code(
    code: &str,
    verifier: &str,
    redirect_uri: &str,
    proxy: Option<&agent2api_provider_protocol::WireProxy>,
) -> Result<CodexCredentials, GatewayError> {
    let code = code.trim();
    if code.is_empty() {
        return Err(GatewayError::with_status(400, "Codex 授权码为空"));
    }
    if code.chars().count() > endpoints::MAX_CODE_LENGTH {
        return Err(GatewayError::with_status(400, "Codex 授权码过长"));
    }
    if redirect_uri.trim().is_empty() {
        return Err(GatewayError::with_status(400, "Codex 换码缺少 redirect_uri"));
    }
    let form = vec![
        ("grant_type", "authorization_code".to_string()),
        ("client_id", endpoints::CLIENT_ID.to_string()),
        ("code", code.to_string()),
        ("redirect_uri", redirect_uri.trim().to_string()),
        ("code_verifier", verifier.to_string()),
    ];
    let (status, payload) = post_form(endpoints::TOKEN_URL, &form, proxy)
        .await
        .map_err(|message| GatewayError::new(format!("Codex 换码请求失败：{message}")))?;
    if !(200..300).contains(&status) {
        let text = payload.to_string();
        return Err(classify_exchange_failure(status, &text, &payload));
    }
    read_token_response(&payload, None).map(|refreshed| refreshed.credentials)
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
            "Codex 账号没有 refresh token，无法续期（请重新登录）",
        ));
    }
    let form = vec![
        ("client_id", endpoints::CLIENT_ID.to_string()),
        ("grant_type", "refresh_token".to_string()),
        ("refresh_token", token.to_string()),
        ("scope", endpoints::REFRESH_SCOPE.to_string()),
    ];
    let (status, payload) = post_form(endpoints::TOKEN_URL, &form, proxy)
        .await
        .map_err(|message| GatewayError::new(format!("Codex 刷新请求失败：{message}")))?;
    if !(200..300).contains(&status) {
        let text = payload.to_string();
        return Err(classify_refresh_failure(status, &text, &payload));
    }
    read_token_response(&payload, Some(token))
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
) -> Result<CodexCredentials, GatewayError> {
    let record = read_record(ctx, account_id).await?;
    let credentials = super::credentials::from_record(Some(&record))?;
    if !force && !credentials.expiring() {
        return Ok(credentials);
    }
    // SIWC 通道走自己的刷新端点与签发的 client_id（参考实现
    // `RefreshSIWCTokens`），拿普通 OAuth 的端点刷会被拒。
    let secret = crate::store::secret_view(&record);
    if super::siwc::bound(&secret) {
        return refresh_siwc_and_save(ctx, &record, &secret, &credentials).await;
    }
    if !credentials.can_refresh() {
        return Err(GatewayError::with_status(
            401,
            "Codex 账号没有 refresh token，无法续期（请重新登录）",
        ));
    }
    let key = format!(
        "codex:{}:{}",
        account_id,
        flight::fingerprint(&credentials.refresh_token)
    );
    let table = flights();
    match table.join(&key) {
        flight::Join::Waiter(waiter) => waiter.wait().await,
        flight::Join::Leader(leader) => {
            let result = refresh_and_save(ctx, &record, &credentials).await;
            let payload = result.clone();
            leader.finish(result);
            payload
        }
    }
}

/// 刷新 SIWC 通道并把结果写回 `siwc` 子对象。
async fn refresh_siwc_and_save(
    ctx: &agent2api_provider_sdk::PluginCtx,
    record: &Value,
    secret: &Value,
    credentials: &CodexCredentials,
) -> Result<CodexCredentials, GatewayError> {
    let proxy = super::account_proxy(record)?;
    let siwc = secret.get("siwc").cloned().unwrap_or(Value::Null);
    let refreshed = super::siwc::refresh(&siwc, proxy.as_ref()).await?;
    let mut next = credentials.clone();
    next.access_token = refreshed
        .get("access_token")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    if let Some(expires_at) = refreshed.get("expires_at").and_then(Value::as_i64) {
        next.expires_at = expires_at;
    }
    if let Some(token) = refreshed.get("refresh_token").and_then(Value::as_str) {
        if !token.trim().is_empty() {
            next.refresh_token = token.to_string();
        }
    }
    if let Some(token) = refreshed.get("id_token").and_then(Value::as_str) {
        if !token.trim().is_empty() {
            next.id_token = token.to_string();
        }
    }
    if next.access_token.trim().is_empty() {
        return Err(GatewayError::with_status(
            502,
            "SIWC 刷新没有拿到新的 access token".to_string(),
        ));
    }
    super::credentials::absorb_id_token(&mut next);
    let merged = super::siwc::merge_into(secret, refreshed);
    let saved = crate::store::save(ctx, account_of(record), secret, &merged).await;
    match saved {
        Ok(false) => crate::logging::warn(
            "[Codex]",
            "SIWC 刷新结果未能写回账号记录（期间被改动过），本次请求用新令牌",
        ),
        Ok(true) => {}
        Err(error) => crate::logging::warn(
            "[Codex]",
            &format!("SIWC 刷新结果写回失败：{}", error.message),
        ),
    }
    Ok(next)
}

/// 从记录里取账号 id（写回用）。
fn account_of(record: &Value) -> &str {
    record.get("id").and_then(Value::as_str).unwrap_or_default()
}

/// 进程内单飞表。
fn flights() -> &'static flight::Table<CodexCredentials> {
    static FLIGHTS: std::sync::OnceLock<flight::Table<CodexCredentials>> =
        std::sync::OnceLock::new();
    FLIGHTS.get_or_init(flight::Table::new)
}

/// 刷新并把结果写回账号记录。
async fn refresh_and_save(
    ctx: &agent2api_provider_sdk::PluginCtx,
    record: &Value,
    credentials: &CodexCredentials,
) -> Result<CodexCredentials, GatewayError> {
    let proxy = super::account_proxy(record)?;
    let refreshed = refresh_access_token(&credentials.refresh_token, proxy.as_ref()).await?;
    let mut next = credentials.clone();
    next.access_token = refreshed.credentials.access_token.clone();
    next.expires_at = refreshed.credentials.expires_at;
    if refreshed.refresh_rotated {
        next.refresh_token = refreshed.credentials.refresh_token.clone();
    }
    if !refreshed.credentials.id_token.trim().is_empty() {
        next.id_token = refreshed.credentials.id_token.clone();
    }
    // 账号 / 套餐 / 邮箱只在原来为空时补。
    if next.account_id.trim().is_empty() && !refreshed.credentials.account_id.trim().is_empty() {
        next.account_id = refreshed.credentials.account_id.clone();
    }
    if next.plan_type.trim().is_empty() && !refreshed.credentials.plan_type.trim().is_empty() {
        next.plan_type = refreshed.credentials.plan_type.clone();
    }
    if next.email.trim().is_empty() && !refreshed.credentials.email.trim().is_empty() {
        next.email = refreshed.credentials.email.clone();
    }
    write_back(ctx, record, &next).await;
    Ok(next)
}

/// 把新令牌写回记录（比较再写；失败只记日志）。
async fn write_back(
    ctx: &agent2api_provider_sdk::PluginCtx,
    record: &Value,
    credentials: &CodexCredentials,
) {
    let account_id = record
        .get("id")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if account_id.is_empty() {
        return;
    }
    let expect = store::secret_view(record);
    let mut fields: Vec<(&str, Value)> = vec![
        (
            "accessToken",
            Value::String(credentials.access_token.clone()),
        ),
        (
            "refreshToken",
            Value::String(credentials.refresh_token.clone()),
        ),
        (
            "expiresAt",
            Value::Number(serde_json::Number::from(credentials.expires_at)),
        ),
    ];
    if !credentials.id_token.trim().is_empty() {
        fields.push(("idToken", Value::String(credentials.id_token.clone())));
    }
    let next = store::with_fields(&expect, &fields);
    match store::save(ctx, account_id, &expect, &next).await {
        Ok(true) => {}
        Ok(false) => logging::warn(
            "[Codex]",
            "刷新结果未能写回账号记录（期间被改动过），本次请求用新令牌",
        ),
        Err(error) => logging::warn(
            "[Codex]",
            &format!("刷新结果写回账号记录失败：{}", error.message),
        ),
    }
}

/// 设备流：申请一对 user code。
pub struct DeviceCode {
    pub device_auth_id: String,
    pub user_code: String,
    pub interval_seconds: u64,
    pub verify_url: String,
}

/// 设备流：申请 user code（参考实现 `codexDeviceUserCodeURL`）。
///
/// 设备面是 **JSON** 体（`{client_id}`），与换码 / 刷新的 form 不同 —— 所以这里
/// 不传 `oauth_headers()`，让 `post_json` 自己设 `application/json`。
pub async fn device_request(
    proxy: Option<&agent2api_provider_protocol::WireProxy>,
) -> Result<DeviceCode, GatewayError> {
    let body = json!({ "client_id": endpoints::CLIENT_ID });
    let (status, payload) = crate::http::post_json(
        &crate::http::control_client(proxy, "direct"),
        endpoints::DEVICE_USERCODE_URL,
        &[],
        &body,
    )
    .await
    .map_err(|message| GatewayError::new(format!("Codex 设备授权申请失败：{message}")))?;
    if !(200..300).contains(&status) {
        return Err(GatewayError::with_status(
            502,
            format!(
                "Codex 设备授权申请失败（HTTP {status}）：{}",
                truncate(&endpoints::upstream_message(&payload))
            ),
        ));
    }
    let pick = |keys: &[&str]| -> String {
        for key in keys {
            if let Some(text) = payload.get(*key).and_then(Value::as_str) {
                let trimmed = text.trim();
                if !trimmed.is_empty() {
                    return trimmed.to_string();
                }
            }
        }
        String::new()
    };
    let device_auth_id = pick(&["device_auth_id", "deviceAuthId", "id"]);
    // 上游两个字段名都见过：`user_code` 与 `usercode`。
    let user_code = pick(&["user_code", "usercode", "userCode"]);
    if device_auth_id.is_empty() || user_code.is_empty() {
        return Err(GatewayError::with_status(
            502,
            "Codex 设备授权响应缺少 device_auth_id 或 user_code",
        ));
    }
    let interval_seconds = payload
        .get("interval")
        .and_then(Value::as_u64)
        .filter(|seconds| *seconds > 0)
        .unwrap_or(endpoints::DEVICE_POLL_INTERVAL_SECONDS);
    let verify_url = endpoints::device_verify_url(&user_code);
    Ok(DeviceCode {
        device_auth_id,
        user_code,
        interval_seconds,
        verify_url,
    })
}

/// 设备流：轮询一次。
///
/// 返回 `Ok(None)` = 还在等用户确认（403/404 按 pending 处理，与参考实现一致）；
/// `Ok(Some(credentials))` = 拿到账号。
pub async fn device_poll(
    device: &DeviceCode,
    proxy: Option<&agent2api_provider_protocol::WireProxy>,
) -> Result<Option<CodexCredentials>, GatewayError> {
    let body = json!({
        "device_auth_id": device.device_auth_id,
        "user_code": device.user_code,
    });
    let (status, payload) = crate::http::post_json(
        &crate::http::control_client(proxy, "direct"),
        endpoints::DEVICE_TOKEN_URL,
        &[],
        &body,
    )
    .await
    .map_err(|message| GatewayError::new(format!("Codex 设备授权轮询失败：{message}")))?;
    if status == 403 || status == 404 {
        return Ok(None);
    }
    if !(200..300).contains(&status) {
        return Err(GatewayError::with_status(
            502,
            format!(
                "Codex 设备授权轮询失败（HTTP {status}）：{}",
                truncate(&endpoints::upstream_message(&payload))
            ),
        ));
    }
    let code = payload
        .get("authorization_code")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            GatewayError::with_status(502, "Codex 设备授权响应缺少 authorization_code")
        })?;
    // 设备流会连 code_verifier 一起下发（PKCE 由上游生成），直接拿来换码。
    let verifier = payload
        .get("code_verifier")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            GatewayError::with_status(502, "Codex 设备授权响应缺少 code_verifier")
        })?;
    let credentials = exchange_code(code, verifier, endpoints::DEVICE_REDIRECT_URI, proxy).await?;
    Ok(Some(credentials))
}

#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pkce_material_sits_inside_the_rfc_range() {
        let value = pkce().expect("pkce");
        assert_eq!(value.verifier.len(), 128);
        assert_eq!(value.challenge.len(), 43);
        assert!(!value.verifier.contains('='));
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
    fn token_response_requires_all_three_fields() {
        let complete = json!({
            "access_token": "at",
            "refresh_token": "rt",
            "expires_in": 3600,
        });
        assert!(read_token_response(&complete, None).is_ok());

        let no_access = json!({"refresh_token": "rt", "expires_in": 3600});
        assert!(read_token_response(&no_access, None).is_err());

        let no_expiry = json!({"access_token": "at", "refresh_token": "rt"});
        assert!(read_token_response(&no_expiry, None).is_err());

        let zero_expiry = json!({"access_token": "at", "refresh_token": "rt", "expires_in": 0});
        assert!(read_token_response(&zero_expiry, None).is_err());

        let no_refresh = json!({"access_token": "at", "expires_in": 3600});
        assert!(read_token_response(&no_refresh, None).is_err());
    }

    #[test]
    fn refresh_fallback_keeps_the_old_token_when_upstream_omits_it() {
        let payload = json!({"access_token": "at2", "expires_in": 3600});
        let refreshed = read_token_response(&payload, Some("old-rt")).expect("fallback");
        assert_eq!(refreshed.credentials.refresh_token, "old-rt");
        assert!(!refreshed.refresh_rotated, "上游没换发就不算轮换");
    }

    #[test]
    fn refresh_rotation_is_flagged() {
        let payload = json!({
            "access_token": "at2",
            "refresh_token": "new-rt",
            "expires_in": 3600,
        });
        let refreshed = read_token_response(&payload, Some("old-rt")).expect("rotated");
        assert_eq!(refreshed.credentials.refresh_token, "new-rt");
        assert!(refreshed.refresh_rotated);
    }

    #[test]
    fn invalid_grant_maps_to_401() {
        let payload = json!({"error": "invalid_grant", "error_description": "revoked"});
        let error = classify_refresh_failure(400, "{}", &payload);
        assert_eq!(error.status_code, 401);
        assert!(error.message.contains("已失效"));
    }

    #[test]
    fn an_unknown_exchange_failure_is_502() {
        let payload = json!({"message": "boom"});
        let error = classify_exchange_failure(500, "{}", &payload);
        assert_eq!(error.status_code, 502);
    }
}
