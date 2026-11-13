//! 账号归一：把「粘贴的 API Key」变成一条账号。
//!
//! ── 为什么先看 `inputs` ────────────────────────────────────────
//! 网关的 `type: "api"` 登录方式**不走 `login.start`**，而是把表单值收成
//! `payload.inputs` 再调 `account.normalize`。旧网关则是把表单值平铺在
//! payload 顶层。两种都要认，否则表现是「表单填完提交，插件说没读到
//! API Key」。
//!
//! ── 为什么 identity 用 Key 的指纹 ─────────────────────────────
//! Gemini API Key 本身没有可读的账号标识（除非再花一次请求去调模型）。
//! 拿指纹当 identity 有两个好处：同一把 Key 反复添加会落到同一条账号上
//! （网关用 identity 当账号 id），且不同 Key 不会因为尾号相同而撞在一起
//! —— 只用尾号时 `AIza…ABCD` 和另一把 `…ABCD` 会合并成一个账号。
//!
//! 指纹与 Key 同等敏感，**绝不写进日志或错误文案**；界面上只露尾号。

use serde_json::{json, Value};

use agent2api_provider_protocol as proto;
use agent2api_provider_sdk::PluginCtx;

use super::credentials;

/// 从 secret 里拼公开信息（账号卡片显示用）。
pub fn public(secret: &Value) -> Value {
    let token = credentials::token_of(secret).unwrap_or_default();
    let name = secret
        .get("name")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|text| !text.is_empty())
        .map(str::to_string)
        .unwrap_or_else(|| format!("Google AI Studio {}", credentials::token_tail(&token)));
    json!({
        "name": name,
        "uid": identity_of(&token),
        "tokenTail": credentials::token_tail(&token),
    })
}

/// 账号 identity（网关拿它当账号 id）。
///
/// 用截断的 SHA-256 指纹而不是 Key 尾号：尾号只有 4 个字符，两把不同的
/// Key 很容易撞到同一条账号上。
pub fn identity_of(token: &str) -> String {
    format!(
        "{}-{}",
        super::endpoints::PROVIDER_ID,
        crate::flight::fingerprint(token)
    )
}

pub fn identity(secret: &Value) -> String {
    let token = credentials::token_of(secret).unwrap_or_default();
    identity_of(&token)
}

/// 归一入口。
pub async fn normalize(
    _ctx: &PluginCtx,
    input: proto::NormalizeInput,
) -> Result<proto::NormalizedAccount, String> {
    let (token, name) = match &input.source {
        proto::NormalizeSource::Manual { payload } => {
            // 新版网关把表单值收进 `inputs`；旧版平铺在顶层。
            let fields = payload
                .get("inputs")
                .filter(|value| value.is_object())
                .unwrap_or(payload);
            let token = credentials::token_from_payload(fields);
            let name = fields
                .get("name")
                .and_then(Value::as_str)
                .map(str::trim)
                .filter(|text| !text.is_empty())
                .map(str::to_string);
            (token, name)
        }
        proto::NormalizeSource::FileText { content, .. } => {
            let trimmed = content.trim();
            if trimmed.is_empty() {
                return Err("文件是空的".to_string());
            }
            // 支持直接粘一段 JSON：{"apiKey":"…"}
            match serde_json::from_str::<Value>(trimmed) {
                Ok(parsed) if parsed.is_object() => {
                    let token = credentials::token_from_payload(&parsed);
                    let name = parsed
                        .get("name")
                        .and_then(Value::as_str)
                        .map(str::trim)
                        .filter(|text| !text.is_empty())
                        .map(str::to_string);
                    (token, name)
                }
                _ => (credentials::token_from_payload(&json!(trimmed)), None),
            }
        }
        proto::NormalizeSource::FileBase64 { .. } => {
            return Err("Google AI Studio 不支持二进制凭证文件，请直接粘贴 API Key".to_string())
        }
        proto::NormalizeSource::Desktop => {
            return Err("Google AI Studio 没有桌面端登录态可读，请粘贴 API Key".to_string())
        }
    };

    if token.is_empty() {
        return Err(format!(
            "没读到 API Key。请到 {} 生成一个，粘贴到「API Key」输入框",
            super::endpoints::KEY_PAGE
        ));
    }

    let tail = credentials::token_tail(&token);
    let display = input
        .name
        .clone()
        .or(name)
        .unwrap_or_else(|| format!("Google AI Studio {tail}"));

    let secret = json!({
        "apiKey": token,
        "name": display,
    });
    let public = json!({
        "name": display,
        "uid": identity_of(&token),
        "tokenTail": tail,
    });

    Ok(proto::NormalizedAccount {
        secret,
        public,
        identity: identity_of(&token),
        desktop: false,
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn identity_is_stable_and_collision_free() {
        let first = identity_of("AIzaSyAAAA");
        assert_eq!(first, identity_of("AIzaSyAAAA"), "同一把 Key 必须落到同一账号");
        // 尾号相同、前缀不同：不能合并成一个账号。
        assert_ne!(first, identity_of("AIzaSyBBBB"));
        assert!(first.starts_with("google-ai-studio-"));
        // 指纹是 32 位 hex，不能把完整 Key 写进 identity。
        assert_eq!(first.len(), "google-ai-studio-".len() + 32);
        assert!(!first.contains("AIza"));
    }

    #[test]
    fn public_falls_back_to_the_tail() {
        let view = public(&json!({ "apiKey": "AIzaSyWXYZ" }));
        assert_eq!(view.get("name").and_then(Value::as_str), Some("Google AI Studio WXYZ"));
        assert_eq!(view.get("tokenTail").and_then(Value::as_str), Some("WXYZ"));
    }

    #[test]
    fn public_keeps_an_explicit_name() {
        let view = public(&json!({ "apiKey": "AIzaSyWXYZ", "name": "主号" }));
        assert_eq!(view.get("name").and_then(Value::as_str), Some("主号"));
    }
}
