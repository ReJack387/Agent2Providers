//! Claude 账号面：归一化 + 公开视图 + 稳定身份。
//!
//! ── 两条添加路径 ────────────────────────────────────────────
//! ```text
//!   Manual{payload}  粘贴 refresh token → 一次真实刷新校验（login::verify_paste）
//!                    → 落账号
//!   Desktop          不支持（Claude 的登录态在浏览器 cookie / 客户端钥匙串里，
//!                    插件侧没有可靠的读取点）
//!   FileText/Base64  不支持（凭证是令牌，不是文件）
//! ```
//! 网页登录是另一条链（`login.rs` → `oauth::exchange_code` → 同一个
//! [`account_of`]）。
//!
//! ── 身份怎么认（email + 组织 → 账号 uuid → 令牌摘要）──────────
//! email 对同一个 Claude 账号是稳定的：重新授权会换一枚新的 refresh token，
//! 但 email 不变，按 email 派生身份才能让「重新登录」更新同一条记录。但
//! **同一 email 在不同组织下是两个额度池**，所以组织 uuid 也进身份。
//!
//! ── 硬约束 ──────────────────────────────────────────────────
//! release 是 `panic=abort`：本文件零 unwrap / expect / panic。

use serde_json::{Map, Value};

use agent2api_provider_protocol as proto;
use agent2api_provider_sdk::PluginCtx;

use super::credentials::ClaudeCredentials;

/// 账号名长度上限。
const MAX_NAME_LENGTH: usize = 100;

/// 添加账号入口。
pub(super) async fn normalize(
    ctx: &PluginCtx,
    input: proto::NormalizeInput,
) -> Result<proto::NormalizedAccount, String> {
    let payload = match input.source {
        proto::NormalizeSource::Manual { payload } => payload,
        proto::NormalizeSource::Desktop => {
            return Err(
                "Claude 不支持导入桌面端登录态，请用「网页登录」或粘贴 refresh token 添加"
                    .to_string(),
            )
        }
        proto::NormalizeSource::FileText { .. } | proto::NormalizeSource::FileBase64 { .. } => {
            return Err(
                "Claude 没有可导入的凭证文件（凭证是 OAuth refresh token），请直接粘贴".to_string(),
            )
        }
    };
    // `auth.methods` 的 `type: "api"` 入口把用户填的字段包在 `inputs` 里（网关的
    // 动态登录表单），旧的手动凭证入口则把字段平铺在顶层。两种都认。
    let payload = payload
        .get("inputs")
        .filter(|value| value.is_object())
        .cloned()
        .unwrap_or(payload);
    // 校验刷新是**必需**的：「用户粘了一串东西」与「这串能用」之间没有本地
    // 判据（refresh token 的形态不唯一，`sk-ant-ort01-` 只是当前前缀）。
    let credentials = super::login::verify_paste(&payload, input.proxy.as_ref()).await?;
    let _ = ctx;
    let name = input
        .name
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|value| crate::json::truncate_text(value, MAX_NAME_LENGTH));
    Ok(account_of(&credentials, "manual", name))
}

/// 凭证 → 可落库的账号（网页登录与手工粘贴两条路共用）。
pub(super) fn account_of(
    credentials: &ClaudeCredentials,
    source: &str,
    explicit_name: Option<String>,
) -> proto::NormalizedAccount {
    let mut secret = Map::new();
    secret.insert(
        "refreshToken".to_string(),
        Value::String(credentials.refresh_token.clone()),
    );
    if !credentials.access_token.trim().is_empty() {
        secret.insert(
            "accessToken".to_string(),
            Value::String(credentials.access_token.clone()),
        );
    }
    if credentials.expires_at > 0 {
        secret.insert("expiresAt".to_string(), Value::from(credentials.expires_at));
    }
    for (key, value) in [
        ("email", &credentials.email),
        ("accountUuid", &credentials.account_uuid),
        ("organizationUuid", &credentials.organization_uuid),
        ("organizationName", &credentials.organization_name),
        ("plan", &credentials.plan),
    ] {
        if !value.trim().is_empty() {
            secret.insert(key.to_string(), Value::String(value.clone()));
        }
    }
    // userId = 本家的稳定身份（网关「从其他工具导入 / 导出」那条链路按通用
    // 字段 `userId` 认身份；Claude 没有 userId，用 email 顶）。
    if !credentials.email.trim().is_empty() {
        secret.insert(
            "userId".to_string(),
            Value::String(credentials.email.clone()),
        );
    }
    secret.insert(
        "tokenTail".to_string(),
        Value::String(crate::store::token_tail(&credentials.refresh_token)),
    );
    secret.insert("source".to_string(), Value::String(source.to_string()));
    let name = explicit_name
        .or_else(|| Some(credentials.display_name()).filter(|value| !value.trim().is_empty()))
        .unwrap_or_else(|| "Claude 账号".to_string());
    secret.insert(
        "name".to_string(),
        Value::String(crate::json::truncate_text(&name, MAX_NAME_LENGTH)),
    );
    let secret = Value::Object(secret);
    proto::NormalizedAccount {
        public: account_view(&secret),
        identity: identity_of(&secret),
        secret,
        // 本家没有「实时读本机客户端」这条来源，恒 false
        desktop: false,
    }
}

/// Claude 专属的公开字段；账号 id 与 provider 由网关注入。
pub(super) fn account_view(secret: &Value) -> Value {
    let refresh_token = crate::store::pick(secret, &["refreshToken", "refresh_token"]);
    let access_token = crate::store::pick(secret, &["accessToken", "access_token"]);
    let mut view = serde_json::json!({
        "name": crate::store::pick(secret, &["name"]),
        "userId": crate::store::pick(secret, &["userId", "email"]),
        "email": crate::store::pick(secret, &["email"]),
        "organizationName": crate::store::pick(secret, &["organizationName", "organization_name"]),
        "plan": crate::store::pick(secret, &["plan"]),
        "source": crate::store::pick(secret, &["source"]),
        // 展示用的尾号取 **refresh token**（本家的主凭证；access 只活几小时，
        // 按它算尾号会让同一账号每次刷新后显示不同）
        "tokenTail": crate::store::token_tail(&refresh_token),
        "hasRefreshToken": !refresh_token.is_empty(),
        "refreshTokenLongLived": true,
        "hasAccessToken": !access_token.is_empty(),
        "desktop": false,
        // 有 refreshToken 就算「当前可用」（accessToken 可以由刷新补齐）
        "available": !refresh_token.is_empty(),
    });
    let expires_at = ["expiresAt", "expires_at"]
        .iter()
        .find_map(|key| secret.get(*key).and_then(Value::as_i64))
        .filter(|value| *value > 0);
    if let Some(object) = view.as_object_mut() {
        if let Some(expires_at) = expires_at {
            object.insert("expiresAt".to_string(), Value::from(expires_at));
        }
    }
    view
}

/// 账号的稳定身份（`claude-<email>[-<org>]` / `claude-<account uuid>` /
/// `claude-<令牌摘要>`）。
pub(super) fn identity_of(secret: &Value) -> String {
    let email = crate::store::pick(secret, &["email", "userId", "user_id"]);
    if !email.is_empty() {
        let organization = crate::store::pick(secret, &["organizationUuid", "organization_uuid"]);
        if organization.is_empty() {
            return format!("claude-{email}");
        }
        return format!("claude-{email}-{organization}");
    }
    let account = crate::store::pick(secret, &["accountUuid", "account_uuid"]);
    if !account.is_empty() {
        return format!("claude-{account}");
    }
    let refresh_token = crate::store::pick(secret, &["refreshToken", "refresh_token"]);
    if refresh_token.is_empty() {
        return String::new();
    }
    format!("claude-{}", crate::flight::fingerprint(&refresh_token))
}

#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#[cfg(test)]
mod tests {
    use super::*;

    fn credentials() -> ClaudeCredentials {
        ClaudeCredentials {
            refresh_token: "sk-ant-ort01-abcdefgh".to_string(),
            access_token: "sk-ant-oat01-1234".to_string(),
            expires_at: 1_700_000_000_000,
            email: "user@example.com".to_string(),
            organization_uuid: "org-1".to_string(),
            organization_name: "Acme".to_string(),
            plan: "max".to_string(),
            ..Default::default()
        }
    }

    #[test]
    fn the_secret_carries_everything_the_view_needs() {
        let account = account_of(&credentials(), "manual", None);
        assert_eq!(account.secret["refreshToken"], "sk-ant-ort01-abcdefgh");
        assert_eq!(account.secret["organizationUuid"], "org-1");
        assert_eq!(account.secret["userId"], "user@example.com");
        assert_eq!(account.secret["source"], "manual");
        assert!(!account.desktop);
    }

    #[test]
    fn the_view_exposes_the_fields_the_panel_renders() {
        let account = account_of(&credentials(), "manual", None);
        let view = &account.public;
        assert_eq!(view["email"], "user@example.com");
        assert_eq!(view["organizationName"], "Acme");
        assert_eq!(view["plan"], "max");
        assert_eq!(view["hasRefreshToken"], Value::Bool(true));
        assert_eq!(view["available"], Value::Bool(true));
        // 尾号取 refresh token，不是 access token。
        assert_eq!(view["tokenTail"], "efgh");
    }

    #[test]
    fn identity_separates_organizations_of_the_same_email() {
        let first = account_of(&credentials(), "manual", None);
        assert_eq!(first.identity, "claude-user@example.com-org-1");

        let mut other = credentials();
        other.organization_uuid = "org-2".to_string();
        let second = account_of(&other, "manual", None);
        assert_ne!(first.identity, second.identity, "换组织必须是另一个账号");
    }

    #[test]
    fn identity_falls_back_to_account_uuid_then_fingerprint() {
        let mut no_email = credentials();
        no_email.email = String::new();
        no_email.account_uuid = "acct-9".to_string();
        assert_eq!(
            account_of(&no_email, "manual", None).identity,
            "claude-acct-9"
        );

        let mut bare = credentials();
        bare.email = String::new();
        bare.account_uuid = String::new();
        bare.organization_uuid = String::new();
        let identity = account_of(&bare, "manual", None).identity;
        assert!(identity.starts_with("claude-"));
        assert!(identity.len() > "claude-".len());
    }

    #[test]
    fn an_explicit_name_wins_over_the_email() {
        let account = account_of(&credentials(), "manual", Some("工作号".to_string()));
        assert_eq!(account.secret["name"], "工作号");
    }

    #[test]
    fn an_overlong_name_is_truncated() {
        let account = account_of(&credentials(), "manual", Some("号".repeat(500)));
        let name = account.secret["name"].as_str().unwrap_or_default();
        assert_eq!(name.chars().count(), MAX_NAME_LENGTH);
    }
}
