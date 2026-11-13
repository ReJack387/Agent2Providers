//! Codex 账号的归一化与视图。
//!
//! ── 为什么只接粘贴 ──────────────────────────────────────────
//! Codex 的凭证是一组 OAuth token（refresh / access / id），没有可导入的
//! 桌面端登录态文件：参考实现把 token 存在自己的 filestore 里，插件这边
//! 由网关的 store 承担同样职责。所以 `NormalizeSource::Desktop` 与
//! `FileText` / `FileBase64` 都明确报错，而不是假装读到了什么。
//!
//! ── 粘贴即校验 ──────────────────────────────────────────────
//! `normalize` 拿到 refresh token 后会真刷新一次：只有上游认这个 token，
//! 才算账号可用。这样用户不会添加一个「看起来像 token」的死字符串。

use serde_json::{json, Value};

use agent2api_provider_protocol as proto;
use agent2api_provider_sdk::PluginCtx;

use super::credentials::CodexCredentials;
use super::{login, PROVIDER_ID};
use crate::store;

/// 账号名的长度上限（网关前端按这个裁剪展示）。
const MAX_NAME_LENGTH: usize = 100;

/// 把面板提交的内容归一成一个账号。
pub(super) async fn normalize(
    ctx: &PluginCtx,
    input: proto::NormalizeInput,
) -> Result<proto::NormalizedAccount, String> {
    let _ = ctx;
    let payload = match input.source {
        proto::NormalizeSource::Manual { payload } => payload,
        proto::NormalizeSource::Desktop => {
            return Err(
                "Codex 不支持导入桌面端登录态，请用「网页登录」「设备码」或粘贴 refresh token 添加"
                    .to_string(),
            )
        }
        proto::NormalizeSource::FileText { .. } | proto::NormalizeSource::FileBase64 { .. } => {
            return Err(
                "Codex 没有可导入的凭证文件（凭证是 OAuth refresh token），请直接粘贴".to_string(),
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
    let credentials = login::verify_paste(&payload, input.proxy.as_ref()).await?;
    Ok(account_of(&credentials, "manual", input.name))
}

/// 凭证 → 账号。
pub(super) fn account_of(
    credentials: &CodexCredentials,
    source: &str,
    explicit_name: Option<String>,
) -> proto::NormalizedAccount {
    let mut secret = json!({
        "refreshToken": credentials.refresh_token,
        "tokenTail": store::token_tail(&credentials.refresh_token),
        "source": source,
    });
    if let Some(object) = secret.as_object_mut() {
        if !credentials.access_token.trim().is_empty() {
            object.insert(
                "accessToken".to_string(),
                Value::String(credentials.access_token.clone()),
            );
        }
        if credentials.expires_at > 0 {
            object.insert(
                "expiresAt".to_string(),
                Value::Number(credentials.expires_at.into()),
            );
        }
        if !credentials.id_token.trim().is_empty() {
            object.insert(
                "idToken".to_string(),
                Value::String(credentials.id_token.clone()),
            );
        }
        if !credentials.account_id.trim().is_empty() {
            object.insert(
                "accountId".to_string(),
                Value::String(credentials.account_id.clone()),
            );
        }
        if !credentials.plan_type.trim().is_empty() {
            object.insert(
                "planType".to_string(),
                Value::String(credentials.plan_type.clone()),
            );
        }
        if !credentials.email.trim().is_empty() {
            object.insert("email".to_string(), Value::String(credentials.email.clone()));
            object.insert(
                "userId".to_string(),
                Value::String(credentials.email.clone()),
            );
        }
    }
    let name = explicit_name
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| credentials.display_name());
    let name = crate::json::truncate_text(&name, MAX_NAME_LENGTH);
    if let Some(object) = secret.as_object_mut() {
        object.insert("name".to_string(), Value::String(name));
    }
    proto::NormalizedAccount {
        public: account_view(&secret),
        identity: identity_of(&secret),
        secret,
        desktop: false,
    }
}

/// 账号的展示视图。
pub(super) fn account_view(secret: &Value) -> Value {
    let mut view = json!({
        "name": store::pick(secret, &["name"]),
        "userId": store::pick(secret, &["userId", "email"]),
        "email": store::pick(secret, &["email"]),
        "plan": store::pick(secret, &["planType", "plan"]),
        "source": store::pick(secret, &["source"]),
        "tokenTail": token_tail(secret),
        "hasRefreshToken": !store::pick(secret, &["refreshToken"]).is_empty(),
        "refreshTokenLongLived": true,
        "hasAccessToken": !store::pick(secret, &["accessToken"]).is_empty(),
        "desktop": false,
    });
    let expires_at = secret
        .get("expiresAt")
        .and_then(Value::as_i64)
        .or_else(|| secret.get("expires_at").and_then(Value::as_i64))
        .unwrap_or(0);
    if let Some(object) = view.as_object_mut() {
        if expires_at > 0 {
            object.insert("expiresAt".to_string(), Value::Number(expires_at.into()));
            object.insert("available".to_string(), Value::Bool(true));
        } else {
            object.insert("available".to_string(), Value::Bool(true));
        }
    }
    view
}

fn token_tail(secret: &Value) -> String {
    let stored = store::pick(secret, &["tokenTail"]);
    if !stored.is_empty() {
        return stored;
    }
    store::token_tail(&store::pick(secret, &["refreshToken"]))
}

/// 账号去重键。
///
/// 优先级：email → account_id → refresh token 指纹。同一个 ChatGPT 账号在不
/// 同设备登录会拿到不同 refresh token，用 email / account_id 才能认出是同一
/// 个号；两者都缺时才退到指纹（此时不同 token 就是不同账号）。
pub(super) fn identity_of(secret: &Value) -> String {
    let email = store::pick(secret, &["email"]).trim().to_ascii_lowercase();
    if !email.is_empty() {
        return format!("codex-{email}");
    }
    let account = store::pick(secret, &["accountId", "account_id"])
        .trim()
        .to_ascii_lowercase();
    if !account.is_empty() {
        return format!("codex-{account}");
    }
    let seed = store::pick(secret, &["refreshToken", "accessToken"]);
    format!("codex-{}", crate::flight::fingerprint(&seed))
}

/// 账号是否属于本家（面板会拿它做前置校验）。
#[allow(dead_code)]
pub(super) fn belongs_to(secret: &Value) -> bool {
    let _ = PROVIDER_ID;
    secret.is_object()
}

#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#[cfg(test)]
mod tests {
    use super::*;

    fn credentials() -> CodexCredentials {
        CodexCredentials {
            refresh_token: "rt_abcdefgh".to_string(),
            access_token: "eyJhbGci".to_string(),
            id_token: String::new(),
            expires_at: 1_700_000_000_000,
            account_id: "acc-1".to_string(),
            plan_type: "plus".to_string(),
            email: "user@example.com".to_string(),
            name: String::new(),
        }
    }

    #[test]
    fn the_secret_carries_the_tokens() {
        let account = account_of(&credentials(), "manual", None);
        assert_eq!(
            account.secret.get("refreshToken").and_then(Value::as_str),
            Some("rt_abcdefgh")
        );
        assert_eq!(
            account.secret.get("accessToken").and_then(Value::as_str),
            Some("eyJhbGci")
        );
        assert_eq!(account.secret.get("expiresAt").and_then(Value::as_i64), Some(1_700_000_000_000));
    }

    #[test]
    fn the_view_exposes_what_the_panel_shows() {
        let account = account_of(&credentials(), "manual", None);
        assert_eq!(
            account.public.get("email").and_then(Value::as_str),
            Some("user@example.com")
        );
        assert_eq!(
            account.public.get("tokenTail").and_then(Value::as_str),
            Some("efgh")
        );
        assert_eq!(
            account.public.get("hasRefreshToken").and_then(Value::as_bool),
            Some(true)
        );
    }

    #[test]
    fn an_explicit_name_wins() {
        let account = account_of(&credentials(), "manual", Some("工作号".to_string()));
        assert_eq!(
            account.secret.get("name").and_then(Value::as_str),
            Some("工作号")
        );
    }

    #[test]
    fn identity_prefers_the_email() {
        let account = account_of(&credentials(), "manual", None);
        assert_eq!(account.identity, "codex-user@example.com");
    }

    #[test]
    fn identity_falls_back_to_the_account_id() {
        let mut credentials = credentials();
        credentials.email.clear();
        let account = account_of(&credentials, "manual", None);
        assert_eq!(account.identity, "codex-acc-1");
    }

    #[test]
    fn identity_falls_back_to_the_fingerprint() {
        let mut credentials = credentials();
        credentials.email.clear();
        credentials.account_id.clear();
        let account = account_of(&credentials, "manual", None);
        assert!(account.identity.starts_with("codex-"));
        assert_ne!(account.identity, "codex-");
    }
}
