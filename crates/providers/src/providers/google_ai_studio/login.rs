//! 「添加账号」弹窗里的登录方式（网关 `auth.methods` 的 camelCase 契约）。
//!
//! ── 为什么只有一条 `type: "api"` ────────────────────────────
//! Gemini API Key 是纯静态凭据，没有授权码流程可走。`type: "api"` 这条路
//! **不走 `login.start`**：网关把表单值收成 `payload.inputs` 直接调
//! `account.normalize`，所以这里只需要给出表单字段定义。
//!
//! ── 契约要点（错一条整个弹窗会报「插件返回了无效的登录方式」）────
//! - 顶层必须是 `{ "methods": [...] }`
//! - `methodIndex` 非负且唯一
//! - `type` 只能是 `"oauth"` / `"api"`
//! - `prompts` 必须是数组；`type: "api"` 时不能带 `localOnly` /
//!   `manualCallback` / `embeddedOnly` 为 true
//! - prompt 的 `key` 匹配 `/^[A-Za-z][A-Za-z0-9_-]{0,63}$/`
//! - prompt 的 `type` 只能是 `text` / `select`
//! - `secret: true` 时不能带 `default`

use serde_json::{json, Value};

/// 表单定义。
pub fn login_methods() -> Value {
    json!({
        "methods": [
            {
                "methodIndex": 0,
                "type": "api",
                "label": "粘贴 Gemini API Key",
                "instructions": format!(
                    "到 {} 生成一个 API Key（形如 AIza…），粘贴到下面。\
                     同一把 Key 重复添加会落到同一个账号上。",
                    super::endpoints::KEY_PAGE
                ),
                "prompts": [
                    {
                        "key": "apiKey",
                        "type": "text",
                        "label": "API Key",
                        "placeholder": "AIza…",
                        "secret": true,
                        "optional": false
                    },
                    {
                        "key": "name",
                        "type": "text",
                        "label": "备注名（可选）",
                        "placeholder": "留空则显示 Key 尾号",
                        "optional": true
                    }
                ]
            }
        ]
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    /// 与网关前端同一套校验：key 必须能被当成标识符。
    fn key_is_valid(key: &str) -> bool {
        let bytes = key.as_bytes();
        if bytes.is_empty() || bytes.len() > 64 {
            return false;
        }
        if !bytes[0].is_ascii_alphabetic() {
            return false;
        }
        if !bytes
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'_' || *byte == b'-')
        {
            return false;
        }
        !matches!(key, "__proto__" | "prototype" | "constructor" | "signal")
    }

    #[test]
    fn the_method_list_satisfies_the_gateway_contract() {
        let methods = login_methods();
        let list = methods
            .get("methods")
            .and_then(Value::as_array)
            .expect("顶层必须是 { methods: [...] }");
        assert!(!list.is_empty());

        let mut seen_index = Vec::new();
        for method in list {
            let index = method
                .get("methodIndex")
                .and_then(Value::as_u64)
                .expect("methodIndex 必须是非负整数");
            assert!(!seen_index.contains(&index), "methodIndex 必须唯一");
            seen_index.push(index);

            let kind = method
                .get("type")
                .and_then(Value::as_str)
                .expect("type 必须有");
            assert!(kind == "oauth" || kind == "api", "type 只能是 oauth / api");

            let prompts = method
                .get("prompts")
                .and_then(Value::as_array)
                .expect("prompts 必须是数组");
            assert!(!prompts.is_empty(), "api 方式至少要有一个输入框");

            // type: "api" 不能带这三项为 true。
            for flag in ["localOnly", "manualCallback", "embeddedOnly"] {
                if let Some(value) = method.get(flag) {
                    assert!(value.is_boolean(), "{flag} 存在时必须是 boolean");
                    if kind == "api" {
                        assert_ne!(value.as_bool(), Some(true), "api 方式不能把 {flag} 设为 true");
                    }
                }
            }
            if let Some(input) = method.get("callbackInput") {
                let text = input.as_str().expect("callbackInput 必须是字符串");
                assert!(text == "url" || text == "code", "callbackInput 只能是 url / code");
                if text == "code" {
                    assert_eq!(
                        method.get("manualCallback").and_then(Value::as_bool),
                        Some(true),
                        "callbackInput === \"code\" 时必须 manualCallback === true"
                    );
                }
            }

            let mut seen_key: Vec<String> = Vec::new();
            for prompt in prompts {
                let key = prompt
                    .get("key")
                    .and_then(Value::as_str)
                    .expect("prompt.key 必须有");
                assert!(key_is_valid(key), "prompt.key 不合规: {key}");
                assert!(!seen_key.contains(&key.to_string()), "同一 method 内 key 必须唯一");
                seen_key.push(key.to_string());

                let prompt_type = prompt
                    .get("type")
                    .and_then(Value::as_str)
                    .expect("prompt.type 必须有");
                assert!(
                    prompt_type == "text" || prompt_type == "select",
                    "prompt.type 只能是 text / select"
                );
                if prompt_type == "select" {
                    let options = prompt
                        .get("options")
                        .and_then(Value::as_array)
                        .expect("select 必须带 options");
                    let mut values: Vec<String> = Vec::new();
                    for option in options {
                        let value = option
                            .get("value")
                            .and_then(Value::as_str)
                            .expect("option.value 必须有");
                        assert!(!value.is_empty(), "option.value 不能为空");
                        assert!(!values.contains(&value.to_string()), "option.value 必须唯一");
                        values.push(value.to_string());
                    }
                }
                if prompt.get("secret").and_then(Value::as_bool) == Some(true) {
                    assert!(prompt.get("default").is_none(), "secret 字段不能带 default");
                }
            }
        }
    }

    #[test]
    fn the_form_asks_for_an_api_key() {
        let methods = login_methods();
        let keys: Vec<String> = methods
            .pointer("/methods/0/prompts")
            .and_then(Value::as_array)
            .expect("prompts")
            .iter()
            .filter_map(|prompt| prompt.get("key").and_then(Value::as_str))
            .map(str::to_string)
            .collect();
        assert!(keys.contains(&"apiKey".to_string()));
    }
}
