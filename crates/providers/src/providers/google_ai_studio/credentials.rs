//! 从账号 secret / 表单 payload 里取 Gemini API Key。
//!
//! ── 一处定义，两处使用 ────────────────────────────────────────
//! `token_of`（读已存的 secret）与 `token_from_payload`（读刚提交的表单）
//! 必须用**同一组键名**，否则会出现「粘贴成功、下次调用又报缺 Key」这种
//! 只在第二次请求才暴露的错。两处都走 `pick`。

use serde_json::Value;

/// 认的键名，按优先级排列。
///
/// `apiKey` 是本家表单写的键；其余是用户在别的工具里复制过来的常见写法
/// （整段 JSON、环境变量名、`key=…` 之类），都兜一下。
const KEYS: &[&str] = &["apiKey", "api_key", "googleApiKey", "geminiApiKey", "key", "token", "accessToken"];

/// 逐个 key 取第一个非空 trim 字符串。
fn pick(record: &Value, keys: &[&str]) -> String {
    for key in keys {
        if let Some(text) = record.get(*key).and_then(Value::as_str) {
            let trimmed = text.trim();
            if !trimmed.is_empty() {
                return trimmed.to_string();
            }
        }
    }
    String::new()
}

/// 去掉用户可能一起粘进来的 `Bearer ` 前缀与包裹引号。
fn clean(raw: &str) -> String {
    let mut text = raw.trim();
    if let Some(rest) = text.strip_prefix("Bearer ") {
        text = rest.trim();
    } else if let Some(rest) = text.strip_prefix("bearer ") {
        text = rest.trim();
    }
    text.trim_matches('"').trim_matches('\'').trim().to_string()
}

/// 从已存的账号 secret 里取 Key。
pub fn token_of(secret: &Value) -> Result<String, String> {
    let token = clean(&pick(secret, KEYS));
    if token.is_empty() {
        return Err("这个账号里没有 API Key，请重新粘贴一次".to_string());
    }
    Ok(token)
}

/// 从表单 payload 里取 Key（与 `token_of` 的键名逐字一致）。
pub fn token_from_payload(payload: &Value) -> String {
    clean(&pick(payload, KEYS))
}

/// 取末尾 4 个**字符**（不按字节切，避免多字节边界 panic）。
pub fn token_tail(token: &str) -> String {
    let tail: String = token.chars().rev().take(4).collect::<Vec<char>>().into_iter().rev().collect();
    if tail.is_empty() {
        "????".to_string()
    } else {
        tail
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn reads_the_form_key() {
        let payload = json!({ "apiKey": "  AIzaSy-example  " });
        assert_eq!(token_from_payload(&payload), "AIzaSy-example");
    }

    #[test]
    fn strips_bearer_and_quotes() {
        let payload = json!({ "apiKey": "Bearer \"AIzaSy-x\"" });
        assert_eq!(token_from_payload(&payload), "AIzaSy-x");
    }

    #[test]
    fn falls_back_to_other_keys() {
        let payload = json!({ "token": "AIzaSy-y" });
        assert_eq!(token_from_payload(&payload), "AIzaSy-y");
    }

    #[test]
    fn empty_secret_is_an_error() {
        assert!(token_of(&json!({})).is_err());
    }

    #[test]
    fn tail_counts_characters() {
        assert_eq!(token_tail("AIzaSy"), "zaSy");
        assert_eq!(token_tail("密钥尾巴"), "密钥尾巴");
    }
}
