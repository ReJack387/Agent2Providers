//! Claude 的端点、客户端常量与请求头口径。
//!
//! ── 依据 ────────────────────────────────────────────────────
//! 控制面：`CliProxyAPI-auth/claude/anthropic_auth.go:23-45`、
//! `CliProxyAPI-auth/claude/utls_transport.go:22-62`。
//! 数据面：`CLIProxyAPI-main/internal/runtime/executor/claude_executor_request.go`
//! （头集合 :1496-1650、beta 常量 :30-73）与
//! `internal/runtime/executor/helps/claude_device_profile.go:22-31`（设备指纹）。
//!
//! ── 三个容易踩的点 ──────────────────────────────────────────
//! ① **换码打 `platform.claude.com`，不是 `api.anthropic.com`**。
//!    Claude Code 2.1.220 起 OAuth 令牌端点迁到了 platform 域，照抄老文档
//!    的 `api.anthropic.com/v1/oauth/token` 会 404。
//! ② **授权 URL 的 scope 比 refresh 多一个 `org:create_api_key`**。
//!    授权时多要这个权限，换码/刷新时必须用不带它的那份 scope，否则上游
//!    报 scope 不一致。
//! ③ **`/v1/messages` 必须带 `?beta=true`**。
//!    参考实现两处都这么拼（`claude_executor_execute.go:35`、
//!    `claude_executor_stream.go:39`），漏掉它上游按非 beta 通道处理，
//!    OAuth 令牌会被当成「没有 API key 的普通调用」拒绝。

use serde_json::Value;

/// 授权页（用户浏览器打开的那一页）。
pub const AUTH_URL: &str = "https://claude.ai/oauth/authorize";

/// 换码与刷新共用的令牌端点。
///
/// 注意是 `platform.claude.com`（见模块头的第 ① 点）。
pub const TOKEN_URL: &str = "https://platform.claude.com/v1/oauth/token";

/// 账号资料（换码后读 email / account_uuid / organization_uuid）。
pub const PROFILE_URL: &str = "https://api.anthropic.com/api/oauth/profile";

/// 角色 / 套餐信息（换码后尽力读一次，失败不阻断）。
pub const ROLES_URL: &str = "https://api.anthropic.com/api/oauth/claude_cli/roles";

/// 数据面：消息接口。
///
/// **带 `?beta=true`**（模块头第 ③ 点）。
pub const MESSAGES_URL: &str = "https://api.anthropic.com/v1/messages?beta=true";

/// Claude Code 的 OAuth 客户端 id（公开常量，桌面端与 CLI 共用）。
pub const CLIENT_ID: &str = "9d1c250a-e61b-44d9-88ed-5944d1962f5e";

/// 授权 URL 里要的 scope（比 [`OAUTH_SCOPE`] 多一个 `org:create_api_key`）。
pub const AUTHORIZE_SCOPE: &str =
    "org:create_api_key user:profile user:inference user:sessions:claude_code user:mcp_servers user:file_upload";

/// 换码 / 刷新时声明的 scope（**不带** `org:create_api_key`）。
pub const OAUTH_SCOPE: &str =
    "user:profile user:inference user:sessions:claude_code user:mcp_servers user:file_upload";

/// 本机回调路径。
///
/// 与参考实现 `RedirectURI = "http://localhost:54545/callback"` 的路径段一致。
/// 端口由 [`super::callback_server`] 现绑现取（参考实现固定 54545，但那会与
/// 本机已装的 Claude Code 抢端口），端口不同不影响授权 —— 上游只校验
/// `redirect_uri` 与换码请求里的一致。
pub const CALLBACK_PATH: &str = "/callback";

/// 环境变量：把回调端口钉死（调试 / 需要固定 `redirect_uri` 时用）。
///
/// 不设时走系统分配的空闲端口（参考实现固定用 54545，但那会与本机已装的
/// Claude Code 抢端口）。
pub const ENV_CALLBACK_PORT: &str = "CLAUDE_CALLBACK_PORT";

/// 控制面请求的 User-Agent。
///
/// 参考实现 `applyClaudeOAuthAxiosHeaders` 逐字用的是 `axios/1.15.2` ——
/// Claude Code 的 OAuth 流程跑在 Node 的 axios 上，上游按 UA 区分调用方。
pub const OAUTH_USER_AGENT: &str = "axios/1.15.2";

/// 数据面的 User-Agent（Claude Code CLI 形态）。
///
/// 取自 `helps/claude_device_profile.go:23` 的
/// `defaultClaudeFingerprintUserAgent`（Claude Code 2.1.321）。
pub const MESSAGES_USER_AGENT: &str = "claude-cli/2.1.321 (external, cli)";

/// 设备指纹：`X-Stainless-Package-Version`（`@anthropic-ai/sdk` 版本）。
pub const STAINLESS_PACKAGE_VERSION: &str = "0.128.0";

/// 设备指纹：`X-Stainless-Runtime-Version`（Node 版本）。
pub const STAINLESS_RUNTIME_VERSION: &str = "v26.12.1";

/// 设备指纹：`X-Stainless-OS`。
pub const STAINLESS_OS: &str = "MacOS";

/// 设备指纹：`X-Stainless-Arch`。
pub const STAINLESS_ARCH: &str = "arm64";

/// 设备指纹：`X-Stainless-Timeout`（秒，字符串形态）。
///
/// 参考实现 `claudeDefaultStainlessTimeout`。`count_tokens` 不发这个头。
pub const STAINLESS_TIMEOUT: &str = "600";

/// Anthropic API 版本头。
pub const ANTHROPIC_VERSION: &str = "2023-06-01";

/// 数据面的 `anthropic-beta`（OAuth 令牌 + Claude Code CLI 基线组合）。
///
/// 逐条对照参考实现的 `claudeCodeCLIBetas`（`claude_executor_request.go:179-300`），
/// 取的是一个**普通 OAuth 请求、无特殊特性、非 subagent** 时上游实际收到的
/// 那串，顺序与参考实现一致：
///   1. `claude-code-20250219` —— 让上游按 Claude Code 客户端口径处理；
///   2. `oauth-2025-04-20` —— 用 OAuth 令牌调 Messages 必须带；
///   3. `interleaved-thinking-2025-05-14` … 4 条来自
///      `claudeCodeCLIConstantBetas`（:68-73）；
///   4. `mid-conversation-tool-changes-2026-07-01` —— 非 Sonnet 5 才加；
///   5. `thinking-token-count-2026-05-13` —— 无条件（非配额探测时）；
///   6. `extended-cache-ttl-2025-04-11` —— OAuth 且非 subagent 时加。
///
/// **刻意不逐条实现参考实现的全部条件分支**（quota probe、haiku-5-5 后置
/// scope、per-turn control、inline tools、advisor、fast-mode、afk-mode、
/// message-threads 等）：它们都由请求体的特定字段触发，而本插件转出来的
/// 请求体不带那些字段，发了反而与体不一致。
pub const ANTHROPIC_BETA: &str = concat!(
    "claude-code-20250219,",
    "oauth-2025-04-20,",
    "interleaved-thinking-2025-05-14,",
    "redact-thinking-2026-02-12,",
    "context-management-2025-06-27,",
    "prompt-caching-scope-2026-01-05,",
    "mid-conversation-tool-changes-2026-07-01,",
    "thinking-token-count-2026-05-13,",
    "extended-cache-ttl-2025-04-11"
);

/// 请求超时（控制面：换码 / 刷新 / profile）。
pub const REQUEST_TIMEOUT_MS: u64 = 30_000;

/// 授权码 / state 的长度上限（与参考实现同一量级，防超长注入）。
pub const MAX_CODE_LENGTH: usize = 8192;
pub const MAX_STATE_LENGTH: usize = 512;

/// 错误文案的截断长度。
pub const MAX_ERROR_CHARS: usize = 300;

/// 令牌有效期缺省值（上游不返回 `expires_in` 时用）。
pub const DEFAULT_EXPIRES_IN_SECONDS: i64 = 3600;

/// 授权页地址。
///
/// 参数顺序与参考实现 `GenerateAuthURL` 一致（:327-345）：`code=true` 在最前，
/// 它让上游返回一个「可换码」的一次性码而不是直接渲染应用页。
pub fn authorize_url(redirect_uri: &str, state: &str, challenge: &str) -> String {
    let mut url = match url::Url::parse(AUTH_URL) {
        Ok(url) => url,
        Err(_) => return String::new(),
    };
    url.query_pairs_mut()
        .append_pair("code", "true")
        .append_pair("client_id", CLIENT_ID)
        .append_pair("response_type", "code")
        .append_pair("redirect_uri", redirect_uri)
        .append_pair("scope", AUTHORIZE_SCOPE)
        .append_pair("code_challenge", challenge)
        .append_pair("code_challenge_method", "S256")
        .append_pair("state", state);
    url.to_string()
}

/// 控制面请求头（换码 / 刷新用）。
///
/// 逐条对照 `applyClaudeOAuthAxiosHeaders`（`anthropic_auth.go:219-229`）。
/// `Connection: close` 是参考实现显式设的（`req.Close = true`）—— Node 的
/// axios 默认不复用连接，保持同形能少一处指纹差异。
pub fn oauth_headers() -> Vec<(String, String)> {
    vec![
        (
            "Accept".to_string(),
            "application/json, text/plain, */*".to_string(),
        ),
        ("Content-Type".to_string(), "application/json".to_string()),
        ("User-Agent".to_string(), OAUTH_USER_AGENT.to_string()),
        (
            "Accept-Encoding".to_string(),
            "gzip, compress, deflate, br".to_string(),
        ),
        ("Connection".to_string(), "close".to_string()),
    ]
}

/// 控制面 GET 的请求头（profile / roles 用）。
///
/// 在 [`oauth_headers`] 之上加 `Authorization` 与 `Cache-Control: no-cache`
/// （参考实现 :246-247）。
pub fn inspect_headers(access_token: &str) -> Vec<(String, String)> {
    let mut headers = oauth_headers();
    headers.retain(|(name, _)| !name.eq_ignore_ascii_case("Content-Type"));
    headers.push((
        "Authorization".to_string(),
        format!("Bearer {access_token}"),
    ));
    headers.push(("Cache-Control".to_string(), "no-cache".to_string()));
    headers
}

/// 数据面 `/v1/messages` 的请求头。
///
/// ── 哪些是必须的 ────────────────────────────────────────────
///   - `Authorization: Bearer <oauth token>`；
///   - `anthropic-version`：缺了上游直接 400；
///   - `anthropic-beta`：用 OAuth 令牌时必须带 `oauth-2025-04-20`，
///     否则上游把请求当成「API key 调用」并因为 key 为空而拒绝；
///   - `Content-Type`：POST JSON。
///
/// ── 客户端指纹（参考实现全部会发，缺了不像真客户端）─────────
/// 参考实现 `applyClaudeHeaders` 在「非 confirmed 客户端」时**强制覆盖**这
/// 一组身份头（`claude_executor_request.go:1503-1523`）：
///   - `Anthropic-Dangerous-Direct-Browser-Access: true`
///   - `X-App: cli`
///   - `X-Stainless-Retry-Count: 0`、`X-Stainless-Runtime: node`、
///     `X-Stainless-Lang: js`、`X-Stainless-Timeout: 600`
///
/// 再加上 `ApplyClaudeDefaultDeviceProfileHeaders` 的 5 个：
/// `User-Agent`、`X-Stainless-Package-Version`、`X-Stainless-Runtime-Version`、
/// `X-Stainless-OS`、`X-Stainless-Arch`。
///
/// 顺序按参考实现记录的 wire 顺序
/// （`claude_executor_wire_casing_test.go:23-41`）排列，少一处顺序差异就少一个
/// 指纹。`session_id` 为空时省略 `X-Claude-Code-Session-Id`。
///
/// `Connection: keep-alive` 与 `Accept-Encoding: gzip, deflate, br, zstd` 是
/// 参考实现对 api.anthropic.com 的固定选择（:1589、:1609）。reqwest 自己会按
/// 实际编码能力改写 `Accept-Encoding`，这里仍显式设置以保持形态一致。
pub fn messages_headers(access_token: &str, session_id: &str) -> Vec<(String, String)> {
    let mut headers: Vec<(String, String)> = vec![
        ("Accept".to_string(), "application/json".to_string()),
        (
            "Authorization".to_string(),
            format!("Bearer {access_token}"),
        ),
        ("Content-Type".to_string(), "application/json".to_string()),
    ];
    if !session_id.trim().is_empty() {
        headers.push((
            "X-Claude-Code-Session-Id".to_string(),
            session_id.trim().to_string(),
        ));
    }
    headers.push((
        "X-Stainless-Arch".to_string(),
        STAINLESS_ARCH.to_string(),
    ));
    headers.push(("X-Stainless-Lang".to_string(), "js".to_string()));
    headers.push(("X-Stainless-OS".to_string(), STAINLESS_OS.to_string()));
    headers.push((
        "X-Stainless-Package-Version".to_string(),
        STAINLESS_PACKAGE_VERSION.to_string(),
    ));
    headers.push((
        "X-Stainless-Retry-Count".to_string(),
        "0".to_string(),
    ));
    headers.push(("X-Stainless-Runtime".to_string(), "node".to_string()));
    headers.push((
        "X-Stainless-Runtime-Version".to_string(),
        STAINLESS_RUNTIME_VERSION.to_string(),
    ));
    headers.push((
        "X-Stainless-Timeout".to_string(),
        STAINLESS_TIMEOUT.to_string(),
    ));
    headers.push((
        "anthropic-beta".to_string(),
        ANTHROPIC_BETA.to_string(),
    ));
    headers.push((
        "anthropic-dangerous-direct-browser-access".to_string(),
        "true".to_string(),
    ));
    headers.push((
        "anthropic-version".to_string(),
        ANTHROPIC_VERSION.to_string(),
    ));
    headers.push(("x-app".to_string(), "cli".to_string()));
    headers.push((
        "User-Agent".to_string(),
        MESSAGES_USER_AGENT.to_string(),
    ));
    headers.push((
        "Accept-Encoding".to_string(),
        "gzip, deflate, br, zstd".to_string(),
    ));
    headers.push(("Connection".to_string(), "keep-alive".to_string()));
    headers
}

/// 上游错误体的可读摘要（`error.message` / `message` / 原始文本）。
pub fn upstream_message(payload: &Value) -> String {
    for pointer in ["/error/message", "/message", "/error"] {
        if let Some(text) = payload.pointer(pointer).and_then(Value::as_str) {
            let trimmed = text.trim();
            if !trimmed.is_empty() {
                return trimmed.to_string();
            }
        }
    }
    String::new()
}

#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn authorize_url_carries_every_required_parameter() {
        let url = authorize_url("http://127.0.0.1:8080/callback", "st", "ch");
        assert!(url.starts_with("https://claude.ai/oauth/authorize?"));
        assert!(url.contains("code=true"));
        assert!(url.contains("client_id=9d1c250a-e61b-44d9-88ed-5944d1962f5e"));
        assert!(url.contains("code_challenge_method=S256"));
        assert!(url.contains("redirect_uri=http%3A%2F%2F127.0.0.1%3A8080%2Fcallback"));
        // 授权时多要 org:create_api_key
        assert!(url.contains("org%3Acreate_api_key"));
    }

    #[test]
    fn oauth_scope_drops_the_org_grant() {
        assert!(AUTHORIZE_SCOPE.starts_with("org:create_api_key "));
        assert!(!OAUTH_SCOPE.contains("org:create_api_key"));
        assert!(AUTHORIZE_SCOPE.ends_with(OAUTH_SCOPE));
    }

    #[test]
    fn token_endpoint_is_the_platform_host() {
        // 照抄 api.anthropic.com 的老文档会 404。
        assert_eq!(TOKEN_URL, "https://platform.claude.com/v1/oauth/token");
    }

    #[test]
    fn the_messages_endpoint_asks_for_the_beta_channel() {
        // 漏掉 ?beta=true 上游会把 OAuth 令牌当普通调用拒绝。
        assert!(MESSAGES_URL.ends_with("/v1/messages?beta=true"));
    }

    #[test]
    fn messages_headers_carry_oauth_beta() {
        let headers = messages_headers("tok", "sess");
        let beta = headers
            .iter()
            .find(|(name, _)| name == "anthropic-beta")
            .map(|(_, value)| value.as_str());
        assert_eq!(beta, Some(ANTHROPIC_BETA));
        assert!(ANTHROPIC_BETA.contains("oauth-2025-04-20"));
        assert!(headers
            .iter()
            .any(|(name, value)| name == "Authorization" && value == "Bearer tok"));
    }

    #[test]
    fn messages_headers_carry_the_claude_code_fingerprint() {
        let headers = messages_headers("tok", "sess-1");
        let value = |want: &str| {
            headers
                .iter()
                .find(|(name, _)| name.eq_ignore_ascii_case(want))
                .map(|(_, value)| value.as_str())
        };
        assert_eq!(value("User-Agent"), Some(MESSAGES_USER_AGENT));
        assert!(MESSAGES_USER_AGENT.starts_with("claude-cli/2.1.321"));
        assert_eq!(value("x-app"), Some("cli"));
        assert_eq!(
            value("anthropic-dangerous-direct-browser-access"),
            Some("true")
        );
        assert_eq!(value("anthropic-version"), Some("2023-06-01"));
        assert_eq!(value("X-Stainless-Lang"), Some("js"));
        assert_eq!(value("X-Stainless-Runtime"), Some("node"));
        assert_eq!(value("X-Stainless-Retry-Count"), Some("0"));
        assert_eq!(value("X-Stainless-Timeout"), Some("600"));
        assert_eq!(value("X-Stainless-Package-Version"), Some("0.128.0"));
        assert_eq!(value("X-Stainless-Runtime-Version"), Some("v26.12.1"));
        assert_eq!(value("X-Stainless-OS"), Some("MacOS"));
        assert_eq!(value("X-Stainless-Arch"), Some("arm64"));
        assert_eq!(value("X-Claude-Code-Session-Id"), Some("sess-1"));
    }

    #[test]
    fn an_empty_session_id_omits_the_session_header() {
        let headers = messages_headers("tok", "  ");
        assert!(!headers
            .iter()
            .any(|(name, _)| name.eq_ignore_ascii_case("X-Claude-Code-Session-Id")));
    }

    #[test]
    fn inspect_headers_drop_the_json_content_type() {
        // profile / roles 是 GET，带 Content-Type: application/json 会多一处指纹。
        let headers = inspect_headers("tok");
        assert!(!headers
            .iter()
            .any(|(name, _)| name.eq_ignore_ascii_case("Content-Type")));
        assert!(headers
            .iter()
            .any(|(name, value)| name == "Authorization" && value == "Bearer tok"));
        assert!(headers
            .iter()
            .any(|(name, _)| name.eq_ignore_ascii_case("Cache-Control")));
    }

    #[test]
    fn upstream_message_reads_the_nested_error_first() {
        let payload = serde_json::json!({"error": {"message": "bad"}});
        assert_eq!(upstream_message(&payload), "bad");
        let flat = serde_json::json!({"message": "flat"});
        assert_eq!(upstream_message(&flat), "flat");
        assert!(upstream_message(&serde_json::json!({})).is_empty());
    }
}
