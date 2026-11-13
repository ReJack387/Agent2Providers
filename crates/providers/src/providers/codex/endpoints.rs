//! Codex（ChatGPT 订阅账号）的端点、OAuth 参数与请求头。
//!
//! ── 三套平面 ────────────────────────────────────────────────
//! ```text
//!  授权面  https://auth.openai.com/oauth/authorize       （浏览器）
//!          https://auth.openai.com/oauth/token           （换码 / 刷新，form）
//!  设备面  https://auth.openai.com/api/accounts/deviceauth/usercode
//!          https://auth.openai.com/api/accounts/deviceauth/token
//!  数据面  https://chatgpt.com/backend-api/codex/responses （Responses 流）
//! ```
//!
//! ── 为什么数据面不是 api.openai.com ─────────────────────────
//! 订阅额度走 ChatGPT 的后端，不是 API 计费面。`/backend-api/codex/responses`
//! 只认 ChatGPT 的 access token（ID token 里的 `chatgpt_account_id` 决定归属）。
//!
//! ── 头集合的证据 ────────────────────────────────────────────
//! 全部逐条对照 `CLIProxyAPI-main/internal/runtime/executor/codex_executor_request.go`
//! 的 `applyCodexHeadersWithSIWC`（:513-583）与 `applyCodexRoutingHint`
//! （:603-623）：
//!
//! * `User-Agent` / `Originator` 用的是参考实现的常量
//!   `codexUserAgent = "codex-tui/0.154.0 (Mac OS 26.5.2; arm64) iTerm.app/3.6.11 (codex-tui; 0.154.0)"`
//!   与 `codexOriginator = "codex-tui"`（:32-33）。之前这里发的是
//!   `codex_cli_rs/0.153.4` —— 那只是 Go 测试里的观测值，不是生产常量。
//! * `Chatgpt-Account-Id` 来自 ID token 的 `chatgpt_account_id`（:570-576），
//!   **只在 OAuth 账号时发**，API key 账号不发。
//! * `X-Codex-Routing-Hint: model=<slug>[;tier=<tier>]`（:585-623）是原生 Codex
//!   给每个 ChatGPT 后端请求都带的路由提示，缺了它服务端无法判断 priority 档位。
//! * `Accept` / `Connection: Keep-Alive`（:557-562）。
//!
//! `X-Codex-Beta-Features` / `Version` / `X-Codex-Turn-Metadata` /
//! `X-Codex-Turn-State` / `X-Codex-Window-Id` / `Thread-Id` / `Session-Id` /
//! `X-Openai-Internal-Codex-Responses-Lite` 在参考实现里是**从客户端透传**的
//! （`misc.EnsureHeader` 语义：客户端有才带），本插件的入站请求来自网关而不是
//! Codex 客户端，所以不发 —— 凭空造这些值反而与请求体不一致。

/// OAuth 授权页。
pub const AUTH_URL: &str = "https://auth.openai.com/oauth/authorize";

/// OAuth 换码 / 刷新（form-urlencoded，不是 JSON）。
pub const TOKEN_URL: &str = "https://auth.openai.com/oauth/token";

/// 公开的 Codex CLI OAuth 客户端 id。
pub const CLIENT_ID: &str = "app_EMoamEEZ73f0CkXaXp7hrann";

/// 浏览器登录用的授权 scope。
pub const AUTHORIZE_SCOPE: &str = "openid email profile offline_access";

/// 刷新用的 scope（比授权少 `offline_access`，与参考实现一致）。
pub const REFRESH_SCOPE: &str = "openid profile email";

/// 回调路径（参考实现 `RedirectURI = http://localhost:1455/auth/callback`）。
pub const CALLBACK_PATH: &str = "/auth/callback";

/// 参考实现固定的回调端口。
pub const DEFAULT_CALLBACK_PORT: u16 = 1455;

/// 环境变量：把回调端口钉死（默认用 1455，被占用时自动退让）。
pub const ENV_CALLBACK_PORT: &str = "CODEX_CALLBACK_PORT";

/// 设备授权：申请 user code。
pub const DEVICE_USERCODE_URL: &str = "https://auth.openai.com/api/accounts/deviceauth/usercode";

/// 设备授权：轮询令牌。
pub const DEVICE_TOKEN_URL: &str = "https://auth.openai.com/api/accounts/deviceauth/token";

/// 设备授权：用户要打开的页面。
pub const DEVICE_VERIFY_URL: &str = "https://auth.openai.com/codex/device";

/// 设备流换码时使用的 redirect_uri（固定值，不是本机回调）。
pub const DEVICE_REDIRECT_URI: &str = "https://auth.openai.com/deviceauth/callback";

/// 数据面：Codex 的 Responses 端点。
pub const RESPONSES_URL: &str = "https://chatgpt.com/backend-api/codex/responses";

/// 控制面请求超时。
pub const REQUEST_TIMEOUT_MS: u64 = 30_000;

/// 授权码的长度上限（防御异常输入）。
pub const MAX_CODE_LENGTH: usize = 8192;

/// 上游错误文案的截断长度。
pub const MAX_ERROR_CHARS: usize = 300;

/// 数据面 `User-Agent`。
///
/// 逐字取自 `codex_executor_request.go:32` 的 `codexUserAgent`。这是
/// `codex-tui` 0.154.0 在 macOS arm64 上的真实形态（含终端标识
/// `iTerm.app/3.6.11`），上游按它识别客户端家族与版本。
pub const MESSAGES_USER_AGENT: &str =
    "codex-tui/0.154.0 (Mac OS 26.5.2; arm64) iTerm.app/3.6.11 (codex-tui; 0.154.0)";

/// `Originator` 头（`codex_executor_request.go:33` 的 `codexOriginator`）。
pub const ORIGINATOR: &str = "codex-tui";

/// 路由提示头的名字（`codex_executor_request.go:585`）。
pub const ROUTING_HINT_HEADER: &str = "X-Codex-Routing-Hint";

/// 设备流轮询的缺省间隔（秒）。
pub const DEVICE_POLL_INTERVAL_SECONDS: u64 = 5;

/// 设备流的整体超时（秒）。
pub const DEVICE_TIMEOUT_SECONDS: u64 = 900;

/// 组装授权 URL。
///
/// 参数顺序与参考实现 `GenerateAuthURL` 一致（上游按 query 解析，不依赖顺序，
/// 但保持同形便于比对抓包）。
pub fn authorize_url(redirect_uri: &str, state: &str, challenge: &str) -> String {
    let Ok(mut url) = url::Url::parse(AUTH_URL) else {
        return String::new();
    };
    {
        let mut query = url.query_pairs_mut();
        query.append_pair("client_id", CLIENT_ID);
        query.append_pair("response_type", "code");
        query.append_pair("redirect_uri", redirect_uri);
        query.append_pair("scope", AUTHORIZE_SCOPE);
        query.append_pair("state", state);
        query.append_pair("code_challenge", challenge);
        query.append_pair("code_challenge_method", "S256");
        query.append_pair("prompt", "login");
        query.append_pair("id_token_add_organizations", "true");
        query.append_pair("codex_cli_simplified_flow", "true");
    }
    url.to_string()
}

/// OAuth 换码 / 刷新请求头。
pub fn oauth_headers() -> Vec<(String, String)> {
    vec![
        (
            "Content-Type".to_string(),
            "application/x-www-form-urlencoded".to_string(),
        ),
        ("Accept".to_string(), "application/json".to_string()),
    ]
}

/// 数据面请求头。
///
/// 逐条对照 `applyCodexHeadersWithSIWC`（`codex_executor_request.go:513-583`）
/// 的非 SIWC 分支，外加 `applyCodexRoutingHint`（:603-623）：
///
/// * `Chatgpt-Account-Id` 来自 ID token 的 `chatgpt_account_id`；为空时不发
///   （免费账号可能没有组织）。
/// * `X-Codex-Routing-Hint` 形如 `model=<slug>` 或 `model=<slug>;tier=<tier>`。
///   这是原生 Codex 给每个 ChatGPT 后端请求都带的路由提示，服务端按它选
///   后端档位；缺了它请求会被当低优先级处理。
/// * `session_id` 用 SIWC 分支的写法（非 SIWC 分支是透传客户端的
///   `Session-Id`，本插件的入站请求不来自 Codex 客户端，所以自己生成一个）。
pub fn responses_headers(
    access_token: &str,
    account_id: &str,
    session_id: &str,
    model: &str,
    service_tier: &str,
) -> Vec<(String, String)> {
    let mut headers = vec![
        ("Content-Type".to_string(), "application/json".to_string()),
        (
            "Authorization".to_string(),
            format!("Bearer {}", access_token.trim()),
        ),
        (
            "User-Agent".to_string(),
            MESSAGES_USER_AGENT.to_string(),
        ),
        ("Accept".to_string(), "text/event-stream".to_string()),
        ("Connection".to_string(), "Keep-Alive".to_string()),
        ("Originator".to_string(), ORIGINATOR.to_string()),
    ];
    if !account_id.trim().is_empty() {
        headers.push((
            "Chatgpt-Account-Id".to_string(),
            account_id.trim().to_string(),
        ));
    }
    if !session_id.trim().is_empty() {
        headers.push(("session_id".to_string(), session_id.trim().to_string()));
    }
    if let Some(hint) = routing_hint(model, service_tier) {
        headers.push((ROUTING_HINT_HEADER.to_string(), hint));
    }
    headers
}

/// 组装 `X-Codex-Routing-Hint` 的值。
///
/// 参考实现 `applyCodexRoutingHint` 在模型名为空时整条不发，`service_tier`
/// 非空时追加 `;tier=<value>`。这里同样：模型为空返回 None。
pub fn routing_hint(model: &str, service_tier: &str) -> Option<String> {
    let model = model.trim();
    if model.is_empty() {
        return None;
    }
    let tier = service_tier.trim();
    if tier.is_empty() {
        Some(format!("model={model}"))
    } else {
        Some(format!("model={model};tier={tier}"))
    }
}

/// SIWC 通道的 `User-Agent`。
///
/// 参考实现 `codexSIWCUserAgent`（`codex_executor_request.go:399-405`）是
/// `fmt.Sprintf("%s (%s; %s)", agentName, runtime.GOOS, runtime.GOARCH)`，
/// `agentName` 取 `config.DefaultSignInWithChatGPTIdentifier`（默认
/// `"CLIProxyAPI"`）。本插件用自己的名字，形态保持一致。
pub fn siwc_user_agent() -> String {
    format!("Agent2API ({}; {})", std::env::consts::OS, std::env::consts::ARCH)
}

/// SIWC 通道的数据面请求头。
///
/// 逐条对照 `applyCodexHeadersWithSIWC` 的 SIWC 分支（`codex_executor_request.go`
/// :520-560）：只发 `Content-Type`、`Authorization`、`session_id`、
/// `X-Client-Request-Id`、SIWC 专属 UA、`Accept`、`Connection: Keep-Alive`。
/// **不发 `Originator`、`Chatgpt-Account-Id`、`X-Codex-Routing-Hint`** ——
/// 参考实现在 SIWC 分支里直接 return，后面那几条都在非 SIWC 分支。
pub fn siwc_responses_headers(access_token: &str, session_id: &str) -> Vec<(String, String)> {
    let mut headers = vec![
        ("Content-Type".to_string(), "application/json".to_string()),
        (
            "Authorization".to_string(),
            format!("Bearer {}", access_token.trim()),
        ),
        ("User-Agent".to_string(), siwc_user_agent()),
        ("Accept".to_string(), "text/event-stream".to_string()),
        ("Connection".to_string(), "Keep-Alive".to_string()),
    ];
    if !session_id.trim().is_empty() {
        headers.push(("session_id".to_string(), session_id.trim().to_string()));
        headers.push((
            "X-Client-Request-Id".to_string(),
            session_id.trim().to_string(),
        ));
    }
    headers
}

/// 上游错误文案（`error.message` → `message` → `error`）。
pub fn upstream_message(payload: &serde_json::Value) -> String {
    if let Some(text) = payload
        .pointer("/error/message")
        .and_then(serde_json::Value::as_str)
    {
        return text.trim().to_string();
    }
    if let Some(text) = payload.get("message").and_then(serde_json::Value::as_str) {
        return text.trim().to_string();
    }
    if let Some(text) = payload.pointer("/error").and_then(serde_json::Value::as_str) {
        return text.trim().to_string();
    }
    String::new()
}

/// 设备授权页的完整地址（带上 user code，省得用户手抄）。
pub fn device_verify_url(user_code: &str) -> String {
    let code = user_code.trim();
    if code.is_empty() {
        return DEVICE_VERIFY_URL.to_string();
    }
    format!("{DEVICE_VERIFY_URL}?user_code={code}")
}

#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn authorize_url_carries_the_codex_flow_parameters() {
        let url = authorize_url("http://localhost:1455/auth/callback", "st", "ch");
        assert!(url.starts_with("https://auth.openai.com/oauth/authorize?"));
        assert!(url.contains("code_challenge_method=S256"));
        assert!(url.contains("codex_cli_simplified_flow=true"));
        assert!(url.contains("id_token_add_organizations=true"));
        assert!(url.contains("prompt=login"));
        assert!(url.contains("scope=openid+email+profile+offline_access"));
    }

    #[test]
    fn token_endpoint_is_the_auth_host() {
        assert_eq!(TOKEN_URL, "https://auth.openai.com/oauth/token");
    }

    #[test]
    fn responses_headers_carry_the_codex_fingerprint() {
        let headers = responses_headers("tok", "acct-1", "sess-1", "gpt-5.4", "");
        let find = |name: &str| {
            headers
                .iter()
                .find(|(key, _)| key.eq_ignore_ascii_case(name))
                .map(|(_, value)| value.as_str())
        };
        assert_eq!(find("Originator"), Some("codex-tui"));
        assert_eq!(find("Chatgpt-Account-Id"), Some("acct-1"));
        assert_eq!(find("session_id"), Some("sess-1"));
        assert_eq!(find("Accept"), Some("text/event-stream"));
        assert_eq!(find("Connection"), Some("Keep-Alive"));
        assert_eq!(find(ROUTING_HINT_HEADER), Some("model=gpt-5.4"));
        // UA 必须是 codex-tui 家族（参考实现 `codexUserAgent`），不是 codex_cli_rs。
        let ua = find("User-Agent").unwrap_or("");
        assert!(ua.starts_with("codex-tui/0.154.0 "), "ua = {ua}");
    }

    #[test]
    fn the_routing_hint_carries_the_service_tier() {
        let headers = responses_headers("tok", "", "", "gpt-5.4", "priority");
        let hint = headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(ROUTING_HINT_HEADER))
            .map(|(_, value)| value.as_str());
        assert_eq!(hint, Some("model=gpt-5.4;tier=priority"));
    }

    #[test]
    fn an_empty_model_omits_the_routing_hint() {
        assert_eq!(routing_hint("", "priority"), None);
        assert_eq!(routing_hint("   ", ""), None);
        assert_eq!(routing_hint("gpt-5.4", "  "), Some("model=gpt-5.4".to_string()));
    }

    #[test]
    fn empty_account_id_is_not_sent() {
        let headers = responses_headers("tok", "", "", "", "");
        assert!(!headers
            .iter()
            .any(|(key, _)| key.eq_ignore_ascii_case("chatgpt-account-id")));
        assert!(!headers
            .iter()
            .any(|(key, _)| key.eq_ignore_ascii_case("session_id")));
        assert!(!headers
            .iter()
            .any(|(key, _)| key.eq_ignore_ascii_case(ROUTING_HINT_HEADER)));
    }

    #[test]
    fn upstream_message_reads_the_nested_error_first() {
        let nested = serde_json::json!({"error": {"message": "bad"}});
        assert_eq!(upstream_message(&nested), "bad");
        let flat = serde_json::json!({"message": "flat"});
        assert_eq!(upstream_message(&flat), "flat");
    }

    #[test]
    fn device_verify_url_embeds_the_user_code() {
        assert_eq!(
            device_verify_url("ABCD-1234"),
            "https://auth.openai.com/codex/device?user_code=ABCD-1234"
        );
        assert_eq!(device_verify_url(""), DEVICE_VERIFY_URL);
    }
}
