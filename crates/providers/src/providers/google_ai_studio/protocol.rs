//! OpenAI Chat Completions 请求体 → Gemini `generateContent` 请求体。
//!
//! ── 与 accio 那家的差别 ───────────────────────────────────────
//! accio 打的是自家网关的 Gemini **风格**信封（`system_instruction` 字符串、
//! `args_json` 字符串、`tool_config` 字符串）。这里打的是 Google 官方
//! `generativelanguage.googleapis.com/v1beta`，用的是**标准 REST 形状**：
//! `systemInstruction` 是对象、`functionCall.args` 是 JSON 对象、
//! `functionDeclarations` 直接放进 `tools`。照抄 accio 的字符串化写法会
//! 被上游当未知字段忽略或直接 400。
//!
//! ── 三个必须做的转换 ─────────────────────────────────────────
//! 1. `tool` 消息只有 `tool_call_id`，没有函数名；Gemini 的
//!    `functionResponse` 必须带 `name`。所以要一边扫消息一边记住
//!    `tool_call_id → name` 的对应关系（assistant 的 `tool_calls` 里给的）。
//! 2. OpenAI 的 JSON Schema 里有些键 Gemini 不认（`additionalProperties`、
//!    `$schema`、`strict` 等），留着是硬 400，要递归剥掉。
//! 3. 思考档位不能直接塞 `thinkingBudget`：`ReasoningPatch` 只认顶层字段，
//!    所以绑定先写 body 顶层 `reasoning_effort`，由这里搬进
//!    `generationConfig.thinkingConfig`。**且只对支持思考的模型发**，
//!    否则 2.0/1.5 系会 400。

use serde_json::{json, Map, Value};

/// 一次转换的结果。
pub struct UpstreamBody {
    /// 发出去的请求体。
    pub body: Value,
    /// 是否开了思考（决定要不要期待 `thought: true` 的 part）。
    pub thinking: bool,
}

/// 模型是否吃 `thinkingConfig`。
///
/// Gemini 2.0 / 1.5 没有这个字段，发了就是 400 `Unknown name
/// "thinkingConfig"`。宁可少开思考，也不能让整条请求失败。
pub fn supports_thinking(model: &str) -> bool {
    let name = model.trim().to_ascii_lowercase();
    name.contains("2.5") || name.contains("3.") || name.contains("thinking")
}

/// 档位 → 思考预算（token）。
///
/// 数值取 Gemini 文档里的常用档位：0 关，512 省，1024 低，8192 中，24576 满。
fn thinking_budget(level: &str) -> Option<i64> {
    match level {
        "off" | "none" => Some(0),
        "minimal" => Some(512),
        "low" => Some(1024),
        "medium" => Some(8192),
        "high" => Some(16384),
        "xhigh" | "max" => Some(24576),
        _ => None,
    }
}

/// 这个模型能不能真的把思考关掉。
///
/// `gemini-2.5-pro` 系列**不能**关思考：`thinkingBudget: 0` 会被上游
/// 400 掉（文档写明 pro 的最小预算是 128）。所以要关思考时，对 pro 系
/// 只能退到最小值 —— 让请求成功，而不是让整条请求失败。
fn can_disable_thinking(model: &str) -> bool {
    !model.trim().to_ascii_lowercase().contains("pro")
}

/// pro 系能接受的最小思考预算。
const PRO_MIN_BUDGET: i64 = 128;

/// 剥掉 Gemini 不认的 JSON Schema 键（递归）。
fn sanitize_schema(value: &Value) -> Value {
    match value {
        Value::Object(map) => {
            let mut out = Map::new();
            for (key, item) in map {
                if matches!(
                    key.as_str(),
                    "additionalProperties"
                        | "$schema"
                        | "strict"
                        | "exclusiveMinimum"
                        | "exclusiveMaximum"
                        | "const"
                        | "$defs"
                        | "definitions"
                ) {
                    continue;
                }
                // `title` 是注释性的，Gemini 接受但没用；留着会撑大 schema。
                if key == "title" {
                    continue;
                }
                out.insert(key.clone(), sanitize_schema(item));
            }
            Value::Object(out)
        }
        Value::Array(items) => Value::Array(items.iter().map(sanitize_schema).collect()),
        other => other.clone(),
    }
}

/// OpenAI 的 `data:` 图片 URL → Gemini 的 `inlineData`。
fn image_part(url: &str) -> Option<Value> {
    let trimmed = url.trim();
    let rest = trimmed.strip_prefix("data:")?;
    let (meta, data) = rest.split_once(',')?;
    if !meta.contains("base64") {
        return None;
    }
    let mime = meta.split(';').next().unwrap_or("image/png");
    let mime = if mime.trim().is_empty() { "image/png" } else { mime.trim() };
    Some(json!({
        "inlineData": { "mimeType": mime, "data": data }
    }))
}

/// 把 OpenAI 的 content（字符串 / 数组）摊成 Gemini 的 parts。
fn content_to_parts(content: &Value, parts: &mut Vec<Value>) {
    match content {
        Value::String(text) => {
            if !text.is_empty() {
                parts.push(json!({ "text": text }));
            }
        }
        Value::Array(items) => {
            for item in items {
                match item.get("type").and_then(Value::as_str) {
                    Some("text") | Some("input_text") | Some("output_text") => {
                        if let Some(text) = item.get("text").and_then(Value::as_str) {
                            if !text.is_empty() {
                                parts.push(json!({ "text": text }));
                            }
                        }
                    }
                    Some("image_url") | Some("input_image") => {
                        let url = item
                            .pointer("/image_url/url")
                            .and_then(Value::as_str)
                            .or_else(|| item.get("image_url").and_then(Value::as_str))
                            .or_else(|| item.get("url").and_then(Value::as_str));
                        if let Some(part) = url.and_then(image_part) {
                            parts.push(part);
                        }
                    }
                    _ => {}
                }
            }
        }
        _ => {}
    }
}

/// assistant 的 `tool_calls` → `functionCall` parts，同时登记 id→name。
fn assistant_tool_parts(tool_calls: &Value, parts: &mut Vec<Value>, names: &mut Map<String, Value>) {
    let Some(calls) = tool_calls.as_array() else {
        return;
    };
    for call in calls {
        let name = call
            .pointer("/function/name")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .trim()
            .to_string();
        if name.is_empty() {
            continue;
        }
        let args = match call.pointer("/function/arguments") {
            Some(Value::String(text)) => serde_json::from_str::<Value>(text).unwrap_or(Value::Null),
            Some(other) => other.clone(),
            None => Value::Null,
        };
        let args = if args.is_object() { args } else { json!({}) };
        if let Some(id) = call.get("id").and_then(Value::as_str) {
            names.insert(id.to_string(), Value::String(name.clone()));
        }
        parts.push(json!({ "functionCall": { "name": name, "args": args } }));
    }
}

/// 合并到 `contents`：最后一条同 role 就并进去，否则新开一条。
fn push_content(role: &str, parts: Vec<Value>, contents: &mut Vec<Value>) {
    if parts.is_empty() {
        return;
    }
    if let Some(last) = contents.last_mut() {
        if last.get("role").and_then(Value::as_str) == Some(role) {
            if let Some(existing) = last.get_mut("parts").and_then(Value::as_array_mut) {
                existing.extend(parts);
                return;
            }
        }
    }
    contents.push(json!({ "role": role, "parts": parts }));
}

/// 转换工具定义。
fn tools_of(body: &Value) -> Option<Value> {
    let tools = body.get("tools")?.as_array()?;
    let mut declarations = Vec::new();
    for tool in tools {
        let function = tool.get("function").unwrap_or(tool);
        let name = function
            .get("name")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .trim()
            .to_string();
        if name.is_empty() {
            continue;
        }
        let mut declaration = json!({ "name": name });
        if let Some(description) = function.get("description").and_then(Value::as_str) {
            if !description.is_empty() {
                declaration["description"] = Value::String(description.to_string());
            }
        }
        if let Some(parameters) = function.get("parameters") {
            if parameters.is_object() {
                declaration["parameters"] = sanitize_schema(parameters);
            }
        }
        declarations.push(declaration);
    }
    if declarations.is_empty() {
        return None;
    }
    Some(json!([{ "functionDeclarations": declarations }]))
}

/// 转换 `tool_choice`。
fn tool_config(body: &Value) -> Option<Value> {
    let choice = body.get("tool_choice")?;
    let (mode, allowed) = match choice {
        Value::String(text) => match text.as_str() {
            "none" => ("NONE", None),
            "required" | "any" => ("ANY", None),
            "auto" => ("AUTO", None),
            _ => return None,
        },
        Value::Object(map) => {
            let name = map
                .get("function")
                .and_then(|function| function.get("name"))
                .and_then(Value::as_str)
                .or_else(|| map.get("name").and_then(Value::as_str));
            match name {
                Some(name) if !name.trim().is_empty() => ("ANY", Some(json!([name.trim()]))),
                _ => ("AUTO", None),
            }
        }
        _ => return None,
    };
    let mut config = json!({ "mode": mode });
    if let Some(allowed) = allowed {
        config["allowedFunctionNames"] = allowed;
    }
    Some(json!({ "functionCallingConfig": config }))
}

/// 主转换。
///
/// `effort` 是已归一化的思考档位（`None` = 客户端没提，交给模型默认）。
pub fn build_upstream_body(body: &Value, model: &str, effort: Option<&str>) -> UpstreamBody {
    let mut contents: Vec<Value> = Vec::new();
    let mut system_parts: Vec<String> = Vec::new();
    let mut tool_names: Map<String, Value> = Map::new();

    if let Some(messages) = body.get("messages").and_then(Value::as_array) {
        for message in messages {
            let role = message.get("role").and_then(Value::as_str).unwrap_or("user");
            match role {
                "system" | "developer" => {
                    let mut parts = Vec::new();
                    content_to_parts(message.get("content").unwrap_or(&Value::Null), &mut parts);
                    for part in parts {
                        if let Some(text) = part.get("text").and_then(Value::as_str) {
                            system_parts.push(text.to_string());
                        }
                    }
                }
                "tool" | "function" => {
                    let name = message
                        .get("name")
                        .and_then(Value::as_str)
                        .map(str::to_string)
                        .or_else(|| {
                            message
                                .get("tool_call_id")
                                .and_then(Value::as_str)
                                .and_then(|id| tool_names.get(id))
                                .and_then(Value::as_str)
                                .map(str::to_string)
                        })
                        .unwrap_or_else(|| "tool".to_string());
                    let text = match message.get("content") {
                        Some(Value::String(text)) => text.clone(),
                        Some(other) => other.to_string(),
                        None => String::new(),
                    };
                    // Gemini 要求 response 是对象。
                    let response = json!({ "content": text });
                    push_content(
                        "user",
                        vec![json!({ "functionResponse": { "name": name, "response": response } })],
                        &mut contents,
                    );
                }
                "assistant" => {
                    let mut parts = Vec::new();
                    content_to_parts(message.get("content").unwrap_or(&Value::Null), &mut parts);
                    if let Some(calls) = message.get("tool_calls") {
                        assistant_tool_parts(calls, &mut parts, &mut tool_names);
                    }
                    push_content("model", parts, &mut contents);
                }
                _ => {
                    let mut parts = Vec::new();
                    content_to_parts(message.get("content").unwrap_or(&Value::Null), &mut parts);
                    push_content("user", parts, &mut contents);
                }
            }
        }
    }

    let mut payload = Map::new();
    payload.insert("contents".into(), Value::Array(contents));

    if !system_parts.is_empty() {
        payload.insert(
            "systemInstruction".into(),
            json!({ "parts": [{ "text": system_parts.join("\n\n") }] }),
        );
    }

    if let Some(tools) = tools_of(body) {
        payload.insert("tools".into(), tools);
        if let Some(config) = tool_config(body) {
            payload.insert("toolConfig".into(), config);
        }
    }

    // ── generationConfig ──
    let mut generation = Map::new();
    if let Some(temperature) = body.get("temperature").and_then(Value::as_f64) {
        generation.insert("temperature".into(), json!(temperature));
    }
    if let Some(top_p) = body.get("top_p").and_then(Value::as_f64) {
        generation.insert("topP".into(), json!(top_p));
    }
    let max_tokens = body
        .get("max_completion_tokens")
        .and_then(Value::as_i64)
        .filter(|value| *value > 0)
        .or_else(|| body.get("max_tokens").and_then(Value::as_i64).filter(|value| *value > 0));
    if let Some(max_tokens) = max_tokens {
        generation.insert("maxOutputTokens".into(), json!(max_tokens));
    }
    match body.get("stop") {
        Some(Value::String(text)) if !text.is_empty() => {
            generation.insert("stopSequences".into(), json!([text]));
        }
        Some(Value::Array(items)) => {
            let stops: Vec<Value> = items
                .iter()
                .filter_map(Value::as_str)
                .map(|text| Value::String(text.to_string()))
                .collect();
            if !stops.is_empty() {
                generation.insert("stopSequences".into(), Value::Array(stops));
            }
        }
        _ => {}
    }
    // response_format → responseMimeType / responseSchema
    if let Some(format) = body.get("response_format") {
        match format.get("type").and_then(Value::as_str) {
            Some("json_object") => {
                generation.insert("responseMimeType".into(), json!("application/json"));
            }
            Some("json_schema") => {
                generation.insert("responseMimeType".into(), json!("application/json"));
                if let Some(schema) = format.pointer("/json_schema/schema") {
                    if schema.is_object() {
                        generation.insert("responseSchema".into(), sanitize_schema(schema));
                    }
                }
            }
            _ => {}
        }
    }

    // ── thinkingConfig（只对支持思考的模型发） ──
    let mut thinking = false;
    if let Some(level) = effort.filter(|value| !value.trim().is_empty()) {
        if supports_thinking(model) {
            if let Some(budget) = thinking_budget(level) {
                // pro 系不接受 0：退到最小预算，否则整个请求 400。
                let budget = if budget <= 0 && !can_disable_thinking(model) {
                    PRO_MIN_BUDGET
                } else {
                    budget
                };
                thinking = budget > 0;
                let mut config = json!({ "thinkingBudget": budget });
                if thinking {
                    config["includeThoughts"] = json!(true);
                }
                generation.insert("thinkingConfig".into(), config);
            }
        }
    }

    if !generation.is_empty() {
        payload.insert("generationConfig".into(), Value::Object(generation));
    }

    UpstreamBody {
        body: Value::Object(payload),
        thinking,
    }
}

/// 从 body 顶层读思考档位（绑定写进来的那个字段）。
pub fn client_effort(body: &Value) -> Option<String> {
    crate::model_rules::read_client_level(body)
}

/// 上游 `finishReason` → OpenAI `finish_reason`。
pub fn finish_reason(raw: &str) -> &'static str {
    match raw {
        "STOP" => "stop",
        "MAX_TOKENS" => "length",
        "SAFETY" | "RECITATION" | "BLOCKLIST" | "PROHIBITED_CONTENT" | "SPII" => "content_filter",
        // 上游没能吐出合法函数调用：按正常结束收尾，别让客户端以为要等工具。
        "MALFORMED_FUNCTION_CALL" => "stop",
        _ => "stop",
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn system_messages_become_system_instruction() {
        let body = json!({
            "messages": [
                { "role": "system", "content": "你是助手" },
                { "role": "user", "content": "你好" }
            ]
        });
        let out = build_upstream_body(&body, "gemini-2.5-flash", None);
        assert_eq!(
            out.body.pointer("/systemInstruction/parts/0/text").and_then(Value::as_str),
            Some("你是助手")
        );
        assert_eq!(out.body.pointer("/contents/0/role").and_then(Value::as_str), Some("user"));
        assert_eq!(out.body.pointer("/contents/0/parts/0/text").and_then(Value::as_str), Some("你好"));
    }

    #[test]
    fn tool_results_carry_the_function_name() {
        let body = json!({
            "messages": [
                { "role": "user", "content": "读一下文件" },
                { "role": "assistant", "tool_calls": [
                    { "id": "call_1", "type": "function", "function": { "name": "read", "arguments": "{\"path\":\"a.txt\"}" } }
                ]},
                { "role": "tool", "tool_call_id": "call_1", "content": "内容" }
            ]
        });
        let out = build_upstream_body(&body, "gemini-2.5-flash", None);
        let contents = out.body.get("contents").and_then(Value::as_array).unwrap();
        assert_eq!(contents.len(), 3);
        assert_eq!(contents[1].get("role").and_then(Value::as_str), Some("model"));
        assert_eq!(
            contents[1].pointer("/parts/0/functionCall/name").and_then(Value::as_str),
            Some("read")
        );
        assert_eq!(
            contents[2].pointer("/parts/0/functionResponse/name").and_then(Value::as_str),
            Some("read")
        );
    }

    #[test]
    fn schema_drops_keys_gemini_rejects() {
        let body = json!({
            "messages": [{ "role": "user", "content": "hi" }],
            "tools": [{ "type": "function", "function": {
                "name": "read",
                "parameters": {
                    "type": "object",
                    "additionalProperties": false,
                    "$schema": "http://json-schema.org/draft-07/schema#",
                    "properties": { "path": { "type": "string", "title": "路径" } }
                }
            }}]
        });
        let out = build_upstream_body(&body, "gemini-2.5-flash", None);
        let parameters = out.body.pointer("/tools/0/functionDeclarations/0/parameters").unwrap();
        assert!(parameters.get("additionalProperties").is_none());
        assert!(parameters.get("$schema").is_none());
        assert!(parameters.pointer("/properties/path/title").is_none());
    }

    #[test]
    fn thinking_is_skipped_for_models_without_it() {
        let body = json!({ "messages": [{ "role": "user", "content": "hi" }] });
        let out = build_upstream_body(&body, "gemini-1.5-flash", Some("high"));
        assert!(out.body.pointer("/generationConfig/thinkingConfig").is_none());
        assert!(!out.thinking);
    }

    #[test]
    fn thinking_budget_follows_the_level() {
        let body = json!({ "messages": [{ "role": "user", "content": "hi" }] });
        let out = build_upstream_body(&body, "gemini-2.5-flash", Some("off"));
        assert_eq!(
            out.body.pointer("/generationConfig/thinkingConfig/thinkingBudget").and_then(Value::as_i64),
            Some(0)
        );
        assert!(!out.thinking);

        let out = build_upstream_body(&body, "gemini-2.5-flash", Some("high"));
        assert_eq!(
            out.body.pointer("/generationConfig/thinkingConfig/thinkingBudget").and_then(Value::as_i64),
            Some(16384)
        );
        assert_eq!(
            out.body.pointer("/generationConfig/thinkingConfig/includeThoughts").and_then(Value::as_bool),
            Some(true)
        );
    }

    #[test]
    fn pro_models_never_get_a_zero_budget() {
        // 2.5-pro 不能关思考：0 会被上游 400，必须退到最小预算。
        let body = json!({ "messages": [{ "role": "user", "content": "hi" }] });
        let out = build_upstream_body(&body, "gemini-2.5-pro", Some("off"));
        assert_eq!(
            out.body.pointer("/generationConfig/thinkingConfig/thinkingBudget").and_then(Value::as_i64),
            Some(128)
        );
        assert!(out.thinking, "退到最小预算后仍然是在思考");

        // flash 可以真的关掉。
        let out = build_upstream_body(&body, "gemini-2.5-flash", Some("off"));
        assert_eq!(
            out.body.pointer("/generationConfig/thinkingConfig/thinkingBudget").and_then(Value::as_i64),
            Some(0)
        );
        assert!(!out.thinking);
    }

    #[test]
    fn finish_reasons_are_mapped() {
        assert_eq!(finish_reason("STOP"), "stop");
        assert_eq!(finish_reason("MAX_TOKENS"), "length");
        assert_eq!(finish_reason("SAFETY"), "content_filter");
    }
}
