//! Claude 的凭证形态与到期判定。
//!
//! ── 字段依据 ────────────────────────────────────────────────
//! `CliProxyAPI-auth/claude/anthropic.go` 的 `ClaudeTokenData`：
//! `AccessToken` / `RefreshToken` / `Email` / `AccountUUID` /
//! `OrganizationUUID` / `OrganizationName` / `Expire`，外加 `DeviceIDs`
//! （metadata 键 `claude_device_ids`）。
//!
//! ── 为什么保留 `organization_uuid` 与 `account_uuid` ─────────
//! 同一台机器上换一个 Claude 组织登录，email 不变但组织变了 —— 上游的额度
//! 是按组织算的。账号身份（`accounts::identity_of`）把它们纳入，避免「换组织」被
//! 当成「同一个账号」而覆盖掉旧记录。
//!
//! ── panic=abort ────────────────────────────────────────────
//! 本文件零 unwrap / expect / panic。

use serde_json::Value;

use crate::errors::GatewayError;

/// 到期前多久就开始续期。
///
/// 参考实现 `RefreshLead() = 4 * time.Hour`（`auth/claude.go`）—— Claude 的
/// 令牌有效期短（约 8 小时），提前 4 小时续期可以覆盖「一个长会话跑到一半
/// 令牌过期」的情形。这里换算成毫秒。
pub const REFRESH_LEAD_MS: i64 = 4 * 60 * 60 * 1000;

/// 一条 Claude 账号的凭证。
#[derive(Clone, Default)]
pub struct ClaudeCredentials {
    /// OAuth refresh token。
    pub refresh_token: String,
    /// OAuth access token。
    pub access_token: String,
    /// access token 到期时刻（毫秒时间戳；`0` = 未知）。
    pub expires_at: i64,
    /// 账号邮箱（profile 返回；可能为空）。
    pub email: String,
    /// Claude 账号 uuid（profile 的 `account.uuid`）。
    pub account_uuid: String,
    /// 组织 uuid（额度按组织算）。
    pub organization_uuid: String,
    /// 组织名（界面显示用）。
    pub organization_name: String,
    /// 套餐标识（`roles` 接口尽力读；可能为空）。
    pub plan: String,
    /// 显示名（用户指定或 email）。
    pub name: String,
}

impl ClaudeCredentials {
    /// 能不能续期（有没有 refresh token）。
    pub fn can_refresh(&self) -> bool {
        !self.refresh_token.trim().is_empty()
    }

    /// 有没有可用的 access token。
    pub fn has_access_token(&self) -> bool {
        !self.access_token.trim().is_empty()
    }

    /// access token 是否到了该续期的时刻。
    ///
    /// 三态（与 Antigravity 家同一取舍）：
    ///   - 没有 access token → `true`（必须先刷）；
    ///   - `expires_at <= 0`（上游没给到期时刻）→ `false`（不预测，避免误杀）；
    ///   - 否则看「到期时刻 - 提前量」是否已过。
    pub fn expiring(&self) -> bool {
        if !self.has_access_token() {
            return true;
        }
        if self.expires_at <= 0 {
            return false;
        }
        self.expires_at - REFRESH_LEAD_MS <= crate::logging::now_ms()
    }

    /// 令牌尾 4 位（界面显示用，绝不暴露完整令牌）。
    pub fn token_tail(&self) -> String {
        crate::store::token_tail(&self.access_token)
    }

    /// 显示名：用户起的名字 → email → 组织名 → 令牌尾。
    pub fn display_name(&self) -> String {
        for candidate in [&self.name, &self.email, &self.organization_name] {
            let trimmed = candidate.trim();
            if !trimmed.is_empty() {
                return trimmed.to_string();
            }
        }
        let tail = self.token_tail();
        if tail.is_empty() {
            "Claude 账号".to_string()
        } else {
            format!("Claude …{tail}")
        }
    }
}

/// 从落库记录里还原凭证。
///
/// ── 为什么同时接受驼峰与下划线 ──────────────────────────────
/// 本插件写入的是驼峰（`accessToken` / `refreshToken`，与 Antigravity 家
/// 一致）；但用户可能粘贴参考实现导出的 JSON（那是下划线：`access_token`）。
/// 两种都认，导入就不会「成功但字段全空」。
pub fn from_record(record: Option<&Value>) -> Result<ClaudeCredentials, GatewayError> {
    let Some(record) = record else {
        return Err(GatewayError::with_status(404, "Claude 账号记录不存在"));
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
    let expires_at = ["expiresAt", "expires_at", "expire"]
        .iter()
        .find_map(|key| record.get(*key).and_then(Value::as_i64))
        .unwrap_or(0);
    let credentials = ClaudeCredentials {
        refresh_token: pick(&["refreshToken", "refresh_token"]),
        access_token: pick(&["accessToken", "access_token"]),
        expires_at,
        email: pick(&["email", "emailAddress"]),
        account_uuid: pick(&["accountUuid", "account_uuid"]),
        organization_uuid: pick(&["organizationUuid", "organization_uuid"]),
        organization_name: pick(&["organizationName", "organization_name"]),
        plan: pick(&["plan", "planType", "subscriptionType"]),
        name: pick(&["name"]),
    };
    Ok(credentials)
}

#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn credentials() -> ClaudeCredentials {
        ClaudeCredentials {
            access_token: "sk-ant-oat01-abcdefgh".to_string(),
            refresh_token: "sk-ant-ort01-zzzz".to_string(),
            expires_at: crate::logging::now_ms() + 10 * 60 * 60 * 1000,
            email: "user@example.com".to_string(),
            ..Default::default()
        }
    }

    #[test]
    fn a_token_with_plenty_of_time_left_is_not_expiring() {
        assert!(!credentials().expiring());
    }

    #[test]
    fn a_token_inside_the_lead_window_is_expiring() {
        let mut value = credentials();
        // 提前量是 4 小时；这里只剩 1 小时。
        value.expires_at = crate::logging::now_ms() + 60 * 60 * 1000;
        assert!(value.expiring());
    }

    #[test]
    fn a_missing_access_token_is_always_expiring() {
        let mut value = credentials();
        value.access_token = String::new();
        assert!(value.expiring());
    }

    #[test]
    fn an_unknown_expiry_is_never_guessed() {
        // 上游没给到期时刻时不做预测，否则会误杀仍然可用的账号。
        let mut value = credentials();
        value.expires_at = 0;
        assert!(!value.expiring());
    }

    #[test]
    fn record_accepts_both_camel_and_snake_case() {
        let camel = from_record(Some(&json!({
            "accessToken": "a", "refreshToken": "r", "expiresAt": 5, "email": "e@x.com"
        })))
        .expect("camel case record");
        assert_eq!(camel.access_token, "a");
        assert_eq!(camel.refresh_token, "r");
        assert_eq!(camel.expires_at, 5);

        let snake = from_record(Some(&json!({
            "access_token": "a2", "refresh_token": "r2", "expire": 7
        })))
        .expect("snake case record");
        assert_eq!(snake.access_token, "a2");
        assert_eq!(snake.refresh_token, "r2");
        assert_eq!(snake.expires_at, 7);
    }

    #[test]
    fn a_missing_record_is_an_error_not_an_empty_credential() {
        assert!(from_record(None).is_err());
    }

    #[test]
    fn display_name_falls_back_through_email_to_tail() {
        assert_eq!(credentials().display_name(), "user@example.com");
        let mut unnamed = credentials();
        unnamed.email = String::new();
        unnamed.organization_name = "Acme".to_string();
        assert_eq!(unnamed.display_name(), "Acme");
        let mut bare = credentials();
        bare.email = String::new();
        bare.organization_name = String::new();
        // `token_tail` 取的是 access token 的尾 4 位（"sk-ant-oat01-abcdefgh"）。
        assert_eq!(bare.display_name(), "Claude …efgh");
    }
}
