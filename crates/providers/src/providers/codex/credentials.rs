//! Codex 的凭证形态与 ID token 解析。
//!
//! 参考实现 `CliProxyAPI-auth/codex/token.go` 与 `jwt_parser.go` 的结构：
//! `CodexTokenData{id_token, access_token, refresh_token, account_id, email,
//! expired(RFC3339), plan_type}`。这里保留同样的字段，但：
//!   * `expired` 改存毫秒时间戳（与网关其它家一致，`expiresAt` 语义统一）；
//!   * `plan_type` 单独存，因为**模型清单按它分档**（参考实现
//!     `service_models.go` 的 codex 分支按 `plan_type` 选清单）。
//!
//! ── ID token 不验签 ────────────────────────────────────────
//! 与参考实现一致：只 base64url 解 payload 取声明。ID token 是上游经 TLS
//! 直接下发的，验签对「防篡改」没有增量收益（拿得到 token 就已是账号持有者）。

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use serde_json::Value;

use crate::errors::GatewayError;

/// 到期前多久开始续期。
///
/// 取参考实现 `sdk/cliproxy/auth/types.go:1106` 的
/// `CodexOuterRefreshLead = 96 * time.Hour`（注释：conservative proactive
/// refresh lead）。Codex 的 access token 只有 1 小时，但上游对短时间内反复
/// 刷新有额外风控，所以宁可提前四天换一次 —— 这也意味着**几乎每次取令牌都会
/// 触发一次刷新**，与参考实现的行为一致。
pub const REFRESH_LEAD_MS: i64 = 96 * 60 * 60 * 1000;

/// 一条 Codex 账号的凭证。
#[derive(Clone, Default)]
pub struct CodexCredentials {
    /// OAuth refresh token。
    pub refresh_token: String,
    /// ChatGPT access token（JWT）。
    pub access_token: String,
    /// ID token（JWT，含账号与套餐声明）。
    pub id_token: String,
    /// access token 到期时刻（毫秒时间戳；0 = 未知）。
    pub expires_at: i64,
    /// `chatgpt_account_id`（数据面 `chatgpt-account-id` 头）。
    pub account_id: String,
    /// `chatgpt_plan_type`（决定模型清单档位）。
    pub plan_type: String,
    /// 账号 email。
    pub email: String,
    /// 展示名（用户显式起的名字优先）。
    pub name: String,
}

impl CodexCredentials {
    pub fn can_refresh(&self) -> bool {
        !self.refresh_token.trim().is_empty()
    }

    pub fn has_access_token(&self) -> bool {
        !self.access_token.trim().is_empty()
    }

    /// 是否该续期。
    pub fn expiring(&self) -> bool {
        if !self.has_access_token() {
            return true;
        }
        if self.expires_at <= 0 {
            return false;
        }
        self.expires_at - REFRESH_LEAD_MS <= crate::logging::now_ms()
    }

    /// 展示用的令牌尾号（取 refresh token，它才是长期凭证）。
    pub fn token_tail(&self) -> String {
        crate::store::token_tail(&self.refresh_token)
    }

    /// 账号显示名。
    pub fn display_name(&self) -> String {
        let name = self.name.trim();
        if !name.is_empty() {
            return name.to_string();
        }
        let email = self.email.trim();
        if !email.is_empty() {
            return email.to_string();
        }
        let tail = self.token_tail();
        if tail.is_empty() {
            "Codex 账号".to_string()
        } else {
            format!("Codex …{tail}")
        }
    }
}

/// 从账号记录里读出凭证。
///
/// 同时接受驼峰与下划线（面板粘贴的 JSON 两种写法都见过）。
pub fn from_record(record: Option<&Value>) -> Result<CodexCredentials, GatewayError> {
    let Some(record) = record else {
        return Err(GatewayError::with_status(404, "Codex 账号记录不存在"));
    };
    let pick = |keys: &[&str]| -> String {
        for key in keys {
            if let Some(text) = record.get(*key).and_then(Value::as_str) {
                let trimmed = text.trim();
                if !trimmed.is_empty() {
                    return trimmed.to_string();
                }
            }
        }
        String::new()
    };
    let expires_at = ["expiresAt", "expires_at", "expiredAt", "expired_at"]
        .iter()
        .find_map(|key| record.get(*key).and_then(Value::as_i64))
        .unwrap_or(0);
    let credentials = CodexCredentials {
        refresh_token: pick(&["refreshToken", "refresh_token"]),
        access_token: pick(&["accessToken", "access_token"]),
        id_token: pick(&["idToken", "id_token"]),
        expires_at,
        account_id: pick(&["accountId", "account_id", "chatgptAccountId"]),
        plan_type: pick(&["planType", "plan_type", "plan"]),
        email: pick(&["email", "emailAddress"]),
        name: pick(&["name"]),
    };
    Ok(credentials)
}

/// ID token 里我们关心的声明。
///
/// `user_id` 只用于排查（同一个 ChatGPT 用户在不同工作区有不同 account_id），
/// 不参与账号去重，所以不读取。
#[derive(Default)]
pub struct IdClaims {
    pub email: String,
    pub account_id: String,
    pub plan_type: String,
    #[allow(dead_code)]
    pub user_id: String,
}

/// 解析 ID token 的 payload 段（不验签）。
///
/// 结构（参考实现 `JWTClaims` / `CodexAuthInfo`）：顶层有 `email`，账号与套餐
/// 藏在 `https://api.openai.com/auth` 这个命名空间对象里。
pub fn parse_id_token(id_token: &str) -> IdClaims {
    let payload = match id_token.split('.').nth(1) {
        Some(payload) => payload,
        None => return IdClaims::default(),
    };
    let decoded = match URL_SAFE_NO_PAD.decode(payload.trim()) {
        Ok(bytes) => bytes,
        Err(_) => return IdClaims::default(),
    };
    let Ok(value) = serde_json::from_slice::<Value>(&decoded) else {
        return IdClaims::default();
    };
    let text = |source: &Value, key: &str| {
        source
            .get(key)
            .and_then(Value::as_str)
            .map(str::trim)
            .unwrap_or("")
            .to_string()
    };
    let auth = value
        .get("https://api.openai.com/auth")
        .cloned()
        .unwrap_or(Value::Null);
    IdClaims {
        email: text(&value, "email"),
        account_id: text(&auth, "chatgpt_account_id"),
        plan_type: text(&auth, "chatgpt_plan_type"),
        user_id: text(&auth, "chatgpt_user_id"),
    }
}

/// 用 ID token 的声明补齐凭证里缺的字段（不覆盖已有的）。
pub fn absorb_id_token(credentials: &mut CodexCredentials) {
    if credentials.id_token.trim().is_empty() {
        return;
    }
    let claims = parse_id_token(&credentials.id_token);
    if credentials.email.trim().is_empty() {
        credentials.email = claims.email;
    }
    if credentials.account_id.trim().is_empty() {
        credentials.account_id = claims.account_id;
    }
    if credentials.plan_type.trim().is_empty() {
        credentials.plan_type = claims.plan_type;
    }
}

#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#[cfg(test)]
mod tests {
    use super::*;

    fn credentials() -> CodexCredentials {
        CodexCredentials {
            refresh_token: "rt-abcdefgh".to_string(),
            access_token: "at-1234".to_string(),
            id_token: String::new(),
            expires_at: 1_700_000_000_000,
            account_id: "acct-1".to_string(),
            plan_type: "plus".to_string(),
            email: "user@example.com".to_string(),
            name: String::new(),
        }
    }

    fn token_with(payload: &str) -> String {
        let encoded = URL_SAFE_NO_PAD.encode(payload.as_bytes());
        format!("header.{encoded}.signature")
    }

    #[test]
    fn record_accepts_both_casings() {
        let camel = serde_json::json!({
            "refreshToken": "rt",
            "accessToken": "at",
            "expiresAt": 5,
            "accountId": "acct",
            "planType": "pro",
        });
        let parsed = from_record(Some(&camel)).expect("camel");
        assert_eq!(parsed.refresh_token, "rt");
        assert_eq!(parsed.expires_at, 5);
        assert_eq!(parsed.account_id, "acct");
        assert_eq!(parsed.plan_type, "pro");

        let snake = serde_json::json!({
            "refresh_token": "rt2",
            "access_token": "at2",
            "expires_at": 7,
            "account_id": "acct2",
            "plan_type": "free",
        });
        let parsed = from_record(Some(&snake)).expect("snake");
        assert_eq!(parsed.refresh_token, "rt2");
        assert_eq!(parsed.expires_at, 7);
        assert_eq!(parsed.plan_type, "free");
    }

    #[test]
    fn a_missing_record_is_an_error() {
        assert!(from_record(None).is_err());
    }

    #[test]
    fn id_token_yields_account_and_plan() {
        let token = token_with(
            r#"{"email":"a@b.c","https://api.openai.com/auth":{"chatgpt_account_id":"acct-9","chatgpt_plan_type":"plus"}}"#,
        );
        let claims = parse_id_token(&token);
        assert_eq!(claims.email, "a@b.c");
        assert_eq!(claims.account_id, "acct-9");
        assert_eq!(claims.plan_type, "plus");
    }

    #[test]
    fn a_broken_id_token_is_empty_not_a_panic() {
        assert!(parse_id_token("nope").email.is_empty());
        assert!(parse_id_token("a.!!!.c").account_id.is_empty());
    }

    #[test]
    fn absorb_only_fills_blanks() {
        let mut credentials = credentials();
        credentials.id_token = token_with(
            r#"{"email":"other@example.com","https://api.openai.com/auth":{"chatgpt_account_id":"acct-9","chatgpt_plan_type":"pro"}}"#,
        );
        absorb_id_token(&mut credentials);
        assert_eq!(credentials.email, "user@example.com", "已有值不被覆盖");
        assert_eq!(credentials.account_id, "acct-1", "已有值不被覆盖");
        assert_eq!(credentials.plan_type, "plus", "已有值不被覆盖");

        let mut blank = CodexCredentials {
            id_token: credentials.id_token.clone(),
            ..Default::default()
        };
        absorb_id_token(&mut blank);
        assert_eq!(blank.email, "other@example.com");
        assert_eq!(blank.account_id, "acct-9");
        assert_eq!(blank.plan_type, "pro");
    }

    #[test]
    fn expiring_treats_missing_token_as_stale() {
        assert!(CodexCredentials::default().expiring());
        // 提前量是 96 小时（参考实现 `CodexOuterRefreshLead`），所以只有活过
        // 四天以上的令牌才算「新鲜」。一小时有效的令牌落进提前量区间，应当
        // 立刻触发刷新。
        let mut fresh = credentials();
        fresh.expires_at = crate::logging::now_ms() + REFRESH_LEAD_MS + 3_600_000;
        assert!(!fresh.expiring());
        let mut stale = credentials();
        stale.expires_at = crate::logging::now_ms() + 3_600_000;
        assert!(stale.expiring());
    }

    #[test]
    fn display_name_falls_back_through_email_to_tail() {
        assert_eq!(credentials().display_name(), "user@example.com");
        let mut unnamed = credentials();
        unnamed.email = String::new();
        // `token_tail` 取的是 refresh token 的尾 4 位（"rt-abcdefgh"）——它才是
        // 长期凭证；access token 每小时换一次，拿它做展示名会一直变。
        assert_eq!(unnamed.display_name(), "Codex …efgh");
    }
}
