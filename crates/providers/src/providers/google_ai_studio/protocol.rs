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
//! 2. OpenAI 的 JSON Schema 与 Gemini 的 `Schema` 不是一回事，必须做一次
//!    **白名单**过滤（只留 `ALLOWED_SCHEMA_KEYS`）。黑名单补不全 —— 每漏
//!    一个键就是整条请求 400（`Unknown name "xxx"`），而白名单漏掉的键最多
//!    少一层约束，请求还能成。
//!
//!    这段路有几个坑，每一个都对应过线上 400：
//!    - 只能过滤 **schema 对象**上的键。`properties` 里的键是参数名，一个叫
//!      `title` 的参数被删掉之后 `required` 就指向了不存在的属性，上游回
//!      `required[2]: property is not defined`。
//!    - 清完要把 `required` 里点空的条目一并剔掉（客户端给的 schema 本身
//!      就可能不自洽）。
//!    - **每个节点都必须输出对象**。JSON Schema 允许布尔 schema（`true` /
//!      `false` / `null` 当整个 schema 用），原样透传会在 `anyOf` 里塞进标量，
//!      protobuf 解析报 `Starting an object on a scalar field`。
//!    - `"type": ["string", "null"]` 这种数组型 type 要收成单个枚举值，`null`
//!      改写成 `nullable: true`；`type` 收数组会报 `Invalid value at ...type`。
//!    - `$ref` 必须**就地展开**。Agent 与 MCP 的工具 schema 普遍用 `$defs` +
//!      `$ref` 复用类型，而 `$defs` 本身不在白名单里 —— 只丢不展开就会留下
//!      悬空引用。展开带深度上限兜自引用。
//!    - `allOf` 摊平进本层、`oneOf` 降级成 `anyOf`（Gemini 认后者）；`not` /
//!      `if`+`then`+`else` 之类没有对应概念，白名单外自然丢掉。
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

/// Gemini `Schema` 认的键。
///
/// **用白名单而不是黑名单。** 黑名单永远补不全，每漏一个键就是一次整条请求
/// 400（`Unknown name "xxx"`）；白名单漏掉的键最多少一层约束，请求还能成。
///
/// 这些键只允许出现在 **schema 对象**上。绝不能拿这张表去筛 `properties` 的
/// 键 —— 那里的键是工具参数名，删掉一个就叫「属性不存在」。
const ALLOWED_SCHEMA_KEYS: &[&str] = &[
    "type",
    "format",
    "description",
    "nullable",
    "enum",
    "items",
    "properties",
    "required",
    "minItems",
    "maxItems",
    "minProperties",
    "maxProperties",
    "minimum",
    "maximum",
    "minLength",
    "maxLength",
    "pattern",
    "anyOf",
];

/// Gemini 的 `format` 只认这几种，别的值会报 `Invalid value at ...format`。
const ALLOWED_FORMATS: &[&str] = &[
    "int32",
    "int64",
    "float",
    "double",
    "byte",
    "binary",
    "date-time",
    "enum",
];

/// `$ref` 展开的最大深度。自引用/互引用的 schema 会无限递归，必须兜住。
const MAX_REF_DEPTH: usize = 8;

/// 把 JSON Schema 的 `type` 收成 Gemini 认的单个枚举值。
///
/// JSON Schema 允许 `"type": ["string", "null"]`，而 Gemini 的 `type` 是标量
/// 枚举 —— 直接把数组塞进去就是 `Invalid value at ...type`。数组里出现
/// `"null"` 时改用 `nullable: true`（Gemini 有这个字段）。
fn normalize_type(item: &Value) -> Option<(String, bool)> {
    let names: Vec<String> = match item {
        Value::String(text) => vec![text.trim().to_ascii_lowercase()],
        Value::Array(items) => items
            .iter()
            .filter_map(Value::as_str)
            .map(|text| text.trim().to_ascii_lowercase())
            .collect(),
        _ => return None,
    };
    if names.is_empty() {
        return None;
    }
    let nullable = names.iter().any(|name| name == "null");
    let picked = names
        .iter()
        .find(|name| name.as_str() != "null")
        .cloned()
        .unwrap_or_else(|| String::from("string"));
    let mapped = match picked.as_str() {
        "string" | "number" | "integer" | "boolean" | "array" | "object" => picked,
        // 各种方言里的别名都没有对应枚举值，折到最接近的那个。
        "float" | "double" => String::from("number"),
        "int" | "long" | "short" | "byte" => String::from("integer"),
        "dict" | "map" | "record" => String::from("object"),
        "list" | "tuple" => String::from("array"),
        _ => String::from("string"),
    };
    Some((mapped, nullable))
}

/// 剥掉 Gemini 不认的键，展开 `$ref`，把组合子摊平。
fn sanitize_schema(value: &Value) -> Value {
    let defs = collect_defs(value);
    sanitize_node(value, &defs, 0)
}

/// 收集根 schema 上的 `$defs` / `definitions`，供 `$ref` 展开用。
fn collect_defs(root: &Value) -> Map<String, Value> {
    let mut out = Map::new();
    let Some(map) = root.as_object() else {
        return out;
    };
    for key in ["$defs", "definitions"] {
        if let Some(entries) = map.get(key).and_then(Value::as_object) {
            for (name, schema) in entries {
                out.entry(name.clone()).or_insert_with(|| schema.clone());
            }
        }
    }
    out
}

/// 取 `$ref` 指向的定义名（`#/$defs/Note` → `Note`）。
fn ref_name(reference: &str) -> Option<&str> {
    let name = reference.trim().rsplit('/').next()?.trim();
    if name.is_empty() {
        None
    } else {
        Some(name)
    }
}

/// 展开一层 `$ref`，并把引用旁边的兄弟键合并进去（2020-12 允许）。
fn deref(value: &Value, defs: &Map<String, Value>, depth: usize) -> Value {
    let Value::Object(map) = value else {
        return value.clone();
    };
    let Some(reference) = map.get("$ref").and_then(Value::as_str) else {
        return value.clone();
    };
    // 展开不了的 `$ref` 原样留着，交给下面剥键时丢掉 —— 悬空引用同样是 400。
    let Some(target) = ref_name(reference).and_then(|name| defs.get(name)) else {
        return value.clone();
    };
    if depth > MAX_REF_DEPTH {
        return json!({});
    }
    let resolved = deref(target, defs, depth + 1);
    let Value::Object(mut merged) = resolved else {
        return json!({});
    };
    for (key, item) in map {
        if key == "$ref" {
            continue;
        }
        merged.insert(key.clone(), item.clone());
    }
    Value::Object(merged)
}

/// `allOf` 没有对应概念，把各分支合并成一个对象（属性/required 取并集）。
fn merge_into(target: &mut Map<String, Value>, source: &Value) {
    let Value::Object(source) = source else {
        return;
    };
    for (key, item) in source {
        match key.as_str() {
            "properties" => {
                let Some(incoming) = item.as_object() else {
                    continue;
                };
                let table = target
                    .entry(String::from("properties"))
                    .or_insert_with(|| Value::Object(Map::new()));
                let Value::Object(table) = table else {
                    continue;
                };
                for (name, schema) in incoming {
                    table.entry(name.clone()).or_insert_with(|| schema.clone());
                }
            }
            "required" => {
                let Some(incoming) = item.as_array() else {
                    continue;
                };
                let list = target
                    .entry(String::from("required"))
                    .or_insert_with(|| Value::Array(Vec::new()));
                let Value::Array(list) = list else {
                    continue;
                };
                for name in incoming {
                    if !list.contains(name) {
                        list.push(name.clone());
                    }
                }
            }
            _ => {
                target
                    .entry(key.clone())
                    .or_insert_with(|| item.clone());
            }
        }
    }
}

/// 清掉 `required` 里指向不存在属性的条目。
///
/// 客户端给的 schema 本身就可能不自洽（`required` 里写着没定义的属性），
/// 上游对这种情况是硬 400（`required[2]: property is not defined`）。
fn prune_required(out: &mut Map<String, Value>) {
    let Some(required) = out.get("required").and_then(Value::as_array).cloned() else {
        return;
    };
    let defined: Vec<String> = out
        .get("properties")
        .and_then(Value::as_object)
        .map(|table| table.keys().cloned().collect())
        .unwrap_or_default();
    let kept: Vec<Value> = required
        .iter()
        .filter(|item| {
            item.as_str()
                .is_some_and(|name| defined.iter().any(|known| known == name))
        })
        .cloned()
        .collect();
    if kept.len() == required.len() {
        return;
    }
    if kept.is_empty() {
        out.remove("required");
    } else {
        out.insert("required".into(), Value::Array(kept));
    }
}

/// 递归清洗一个 schema 节点。
///
/// 两条硬约束：
/// 1. 必须区分 **schema 对象**（按键名过滤）和 **`properties` 映射表**
///    （键是参数名，一个都不能删）。搞混了就会把名叫 `title` 的参数整个删掉，
///    而 `required` 里还列着它，上游回 `required[2]: property is not defined`。
/// 2. **每个节点都必须输出对象。** JSON Schema 允许布尔 schema（`true` /
///    `false` / `null` 当整个 schema 用），原样透传就会在 `anyOf` 里塞进标量，
///    protobuf 解析报 `Starting an object on a scalar field`。
fn sanitize_node(value: &Value, defs: &Map<String, Value>, depth: usize) -> Value {
    if depth > MAX_REF_DEPTH {
        return json!({});
    }
    let resolved = deref(value, defs, depth);
    let Value::Object(map) = &resolved else {
        return json!({});
    };

    let mut out = Map::new();

    // 组合子先处理：`allOf` 摊平进本层，`oneOf` / `anyOf` 归一到 `anyOf`。
    // 顺序有讲究 —— 先摊 `allOf`，后面处理 `properties` 时才能往同一槽位里合并。
    if let Some(entries) = map.get("allOf").and_then(Value::as_array) {
        for branch in entries {
            let cleaned = sanitize_node(branch, defs, depth + 1);
            merge_into(&mut out, &cleaned);
        }
    }
    for key in ["oneOf", "anyOf"] {
        let Some(entries) = map.get(key).and_then(Value::as_array) else {
            continue;
        };
        let slot = out
            .entry(String::from("anyOf"))
            .or_insert_with(|| Value::Array(Vec::new()));
        let Value::Array(branches) = slot else {
            continue;
        };
        for branch in entries {
            // 分支必须是对象，否则 protobuf 直接拒。
            branches.push(sanitize_node(branch, defs, depth + 1));
        }
    }

    for (key, item) in map {
        if !ALLOWED_SCHEMA_KEYS.contains(&key.as_str()) {
            continue;
        }
        match key.as_str() {
            "type" => {
                if let Some((name, nullable)) = normalize_type(item) {
                    out.insert(String::from("type"), Value::String(name));
                    if nullable {
                        out.insert(String::from("nullable"), Value::Bool(true));
                    }
                }
            }
            "format" => {
                if let Some(text) = item.as_str() {
                    if ALLOWED_FORMATS.contains(&text) {
                        out.insert(key.clone(), Value::String(text.to_string()));
                    }
                }
            }
            "properties" => {
                let Some(entries) = item.as_object() else {
                    continue;
                };
                // `allOf` 可能已经往这里合并过一批属性，直接覆盖会把它们丢掉。
                let slot = out
                    .entry(String::from("properties"))
                    .or_insert_with(|| Value::Object(Map::new()));
                let Value::Object(table) = slot else {
                    continue;
                };
                for (name, schema) in entries {
                    table.insert(name.clone(), sanitize_node(schema, defs, depth + 1));
                }
            }
            "items" => {
                // JSON Schema 的元组形态（数组）Gemini 不支持，取第一项。
                let schema = match item {
                    Value::Array(items) => items.first().unwrap_or(&Value::Null),
                    other => other,
                };
                out.insert(
                    String::from("items"),
                    sanitize_node(schema, defs, depth + 1),
                );
            }
            // 已在上面按组合子处理过，这里跳过。
            "anyOf" => {}
            "required" => {
                let Some(incoming) = item.as_array() else {
                    continue;
                };
                let slot = out
                    .entry(String::from("required"))
                    .or_insert_with(|| Value::Array(Vec::new()));
                let Value::Array(list) = slot else {
                    continue;
                };
                for name in incoming {
                    let Some(name) = name.as_str() else {
                        continue;
                    };
                    if !list.iter().any(|known| known.as_str() == Some(name)) {
                        list.push(Value::String(name.to_string()));
                    }
                }
            }
            "nullable" => {
                if let Some(flag) = item.as_bool() {
                    out.insert(key.clone(), Value::Bool(flag));
                }
            }
            "enum" => {
                let Some(items) = item.as_array() else {
                    continue;
                };
                if !items.is_empty() {
                    out.insert(key.clone(), Value::Array(items.clone()));
                }
            }
            // 字符串型约束。
            "description" | "pattern" => {
                if let Some(text) = item.as_str() {
                    if !text.is_empty() {
                        out.insert(key.clone(), Value::String(text.to_string()));
                    }
                }
            }
            // 数值型约束。
            _ => {
                if item.is_number() {
                    out.insert(key.clone(), item.clone());
                }
            }
        }
    }

    prune_required(&mut out);
    infer_type(&mut out);
    normalize_enum(&mut out);
    Value::Object(out)
}

/// 收拾 `enum`。
///
/// Gemini 的 `Schema.enum` 在 protobuf 里是 **`repeated string`** —— 塞布尔值
/// 或数字进去会报 `Invalid value at ...enum`。而 JSON Schema 里
/// `{"enum": [true, false]}` 很常见。
///
/// 处理办法：非字符串类型的枚举整个丢掉，只留 `type`。少一层取值约束换来请求
/// 能成 —— 工具参数的取值范围本来就该由调用方自己校验。
fn normalize_enum(out: &mut Map<String, Value>) {
    let is_string = out.get("type").and_then(Value::as_str) == Some("string");
    if is_string {
        return;
    }
    out.remove("enum");
}

/// 补上缺失的 `type`。
///
/// JSON Schema 里 `type` 是可选的（`{"enum": [...]}`、`{"items": {...}}` 都合法），
/// 但 Gemini 的 `Schema` 对这两种形态校验更严 —— 缺 `type` 时它可能把节点当成
/// 空 schema，`enum` / `items` 就被静默忽略，工具参数校验随之失效。按 JSON
/// Schema 的语义反推一个最贴近的类型。
///
/// 有 `anyOf` 时不推断：那种节点本身就是多态，硬塞一个 `type` 反而会收窄语义。
fn infer_type(out: &mut Map<String, Value>) {
    if out.contains_key("type") || out.contains_key("anyOf") {
        return;
    }
    let inferred = if out
        .get("properties")
        .and_then(Value::as_object)
        .is_some_and(|table| !table.is_empty())
    {
        Some("object")
    } else if out.contains_key("items") {
        Some("array")
    } else {
        // `enum` 只有一种值时按它的 JSON 类型走；混类型就按字符串。
        out.get("enum")
            .and_then(Value::as_array)
            .and_then(|items| items.first())
            .map(|first| match first {
                Value::Bool(_) => "boolean",
                Value::Number(number) if number.is_i64() || number.is_u64() => "integer",
                Value::Number(_) => "number",
                _ => "string",
            })
    };
    if let Some(name) = inferred {
        out.insert(String::from("type"), Value::String(String::from(name)));
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
///
/// 每个 part 都要补 `thoughtSignature`：Gemini 对**历史回放**里的
/// `functionCall` 强制要求它，不带就是 400（「Function call is missing a
/// thought_signature in functionCall parts」）。客户端带了就用它的，没带就查
/// 插件缓存，再没有就用官方哨兵 —— 细节见 `signatures` 模块。
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
        let raw_arguments = match call.pointer("/function/arguments") {
            Some(Value::String(text)) => text.clone(),
            Some(other) => other.to_string(),
            None => String::from("{}"),
        };
        let args = match serde_json::from_str::<Value>(&raw_arguments) {
            Ok(value) if value.is_object() => value,
            _ => match call.pointer("/function/arguments") {
                Some(other) if other.is_object() => other.clone(),
                _ => json!({}),
            },
        };
        let call_id = call.get("id").and_then(Value::as_str).unwrap_or_default();
        if !call_id.is_empty() {
            names.insert(call_id.to_string(), Value::String(name.clone()));
        }
        let mut part = Map::new();
        part.insert(
            String::from("functionCall"),
            json!({ "name": name, "args": args }),
        );
        let carried = super::signatures::carried_signature(call);
        super::signatures::fill_part(&mut part, carried.as_deref(), call_id);
        parts.push(Value::Object(part));
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
    fn property_names_that_look_like_schema_keys_are_kept() {
        // Agent 的工具里常有 `title` / `const` 这种参数名。它们在 `properties`
        // 里是**参数名**，不是 schema 关键字，剥掉就会让 `required` 指向空气。
        let body = json!({
            "messages": [{ "role": "user", "content": "hi" }],
            "tools": [{ "type": "function", "function": {
                "name": "create_note",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "title": { "type": "string" },
                        "const": { "type": "string" },
                        "additionalProperties": { "type": "boolean" },
                        "body": { "type": "string" }
                    },
                    "required": ["title", "const", "additionalProperties", "body"]
                }
            }}]
        });
        let out = build_upstream_body(&body, "gemini-2.5-flash", None);
        let parameters = out.body.pointer("/tools/0/functionDeclarations/0/parameters").unwrap();
        for name in ["title", "const", "additionalProperties", "body"] {
            assert!(
                parameters.pointer(&format!("/properties/{name}")).is_some(),
                "属性 {name} 被误删了"
            );
        }
        let required = parameters.get("required").and_then(Value::as_array).unwrap();
        assert_eq!(required.len(), 4, "required 不该被削");
    }

    #[test]
    fn required_entries_without_a_property_are_dropped() {
        // 客户端给的 schema 本身就可能不自洽：`required` 里列着没定义的属性。
        // 上游对这种情况是硬 400（`required[2]: property is not defined`）。
        let body = json!({
            "messages": [{ "role": "user", "content": "hi" }],
            "tools": [{ "type": "function", "function": {
                "name": "read",
                "parameters": {
                    "type": "object",
                    "properties": { "path": { "type": "string" } },
                    "required": ["path", "ghost", "phantom"]
                }
            }}]
        });
        let out = build_upstream_body(&body, "gemini-2.5-flash", None);
        let parameters = out.body.pointer("/tools/0/functionDeclarations/0/parameters").unwrap();
        let required = parameters.get("required").and_then(Value::as_array).unwrap();
        assert_eq!(required, &vec![json!("path")]);
    }

    #[test]
    fn a_schema_whose_required_is_emptied_drops_the_key() {
        let body = json!({
            "messages": [{ "role": "user", "content": "hi" }],
            "tools": [{ "type": "function", "function": {
                "name": "noop",
                "parameters": { "type": "object", "required": ["ghost"] }
            }}]
        });
        let out = build_upstream_body(&body, "gemini-2.5-flash", None);
        let parameters = out.body.pointer("/tools/0/functionDeclarations/0/parameters").unwrap();
        assert!(
            parameters.get("required").is_none(),
            "空的 required 要整个去掉，留着同样会 400"
        );
    }

    #[test]
    fn nested_object_properties_are_cleaned_recursively() {
        let body = json!({
            "messages": [{ "role": "user", "content": "hi" }],
            "tools": [{ "type": "function", "function": {
                "name": "write",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "meta": {
                            "type": "object",
                            "additionalProperties": false,
                            "properties": {
                                "title": { "type": "string", "title": "标题" },
                                "strict": { "type": "boolean" }
                            },
                            "required": ["title", "strict"]
                        }
                    },
                    "required": ["meta"]
                }
            }}]
        });
        let out = build_upstream_body(&body, "gemini-2.5-flash", None);
        let meta = out
            .body
            .pointer("/tools/0/functionDeclarations/0/parameters/properties/meta")
            .unwrap();
        assert!(meta.get("additionalProperties").is_none(), "嵌套层的关键字仍要剥");
        assert!(meta.pointer("/properties/title/title").is_none(), "嵌套层的 title 关键字仍要剥");
        // 但嵌套层的**参数名** title / strict 必须留着。
        assert!(meta.pointer("/properties/title").is_some());
        assert!(meta.pointer("/properties/strict").is_some());
        let required = meta.get("required").and_then(Value::as_array).unwrap();
        assert_eq!(required.len(), 2);
    }

    #[test]
    fn refs_are_expanded_instead_of_leaving_dangling_pointers() {
        // MCP / Agent 的工具 schema 普遍这么写：类型定义塞 `$defs`，参数里
        // 用 `$ref` 引。`$defs` 在禁用表里，只剥不展开就会留下悬空引用。
        let body = json!({
            "messages": [{ "role": "user", "content": "hi" }],
            "tools": [{ "type": "function", "function": {
                "name": "create_note",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "note": { "$ref": "#/$defs/Note" }
                    },
                    "required": ["note"],
                    "$defs": {
                        "Note": {
                            "type": "object",
                            "additionalProperties": false,
                            "properties": {
                                "title": { "type": "string" },
                                "body": { "type": "string" }
                            },
                            "required": ["title"]
                        }
                    }
                }
            }}]
        });
        let out = build_upstream_body(&body, "gemini-2.5-flash", None);
        let parameters = out.body.pointer("/tools/0/functionDeclarations/0/parameters").unwrap();
        assert!(parameters.get("$defs").is_none(), "$defs 必须剥掉");
        let note = parameters.pointer("/properties/note").unwrap();
        assert!(note.get("$ref").is_none(), "$ref 必须展开掉");
        assert!(note.pointer("/properties/title").is_some(), "展开后要带上属性");
        assert!(note.get("additionalProperties").is_none(), "展开出来的层也要剥关键字");
        assert_eq!(note.get("required").and_then(Value::as_array).map(Vec::len), Some(1));
    }

    #[test]
    fn self_referential_refs_stop_at_the_depth_limit() {
        // 链表式的自引用不设上限就会栈溢出。
        let body = json!({
            "messages": [{ "role": "user", "content": "hi" }],
            "tools": [{ "type": "function", "function": {
                "name": "walk",
                "parameters": {
                    "type": "object",
                    "properties": { "node": { "$ref": "#/$defs/Node" } },
                    "$defs": {
                        "Node": {
                            "type": "object",
                            "properties": { "next": { "$ref": "#/$defs/Node" } }
                        }
                    }
                }
            }}]
        });
        let out = build_upstream_body(&body, "gemini-2.5-flash", None);
        let parameters = out.body.pointer("/tools/0/functionDeclarations/0/parameters").unwrap();
        assert!(parameters.pointer("/properties/node/properties").is_some());
    }

    #[test]
    fn all_of_branches_are_merged_into_one_object() {
        let body = json!({
            "messages": [{ "role": "user", "content": "hi" }],
            "tools": [{ "type": "function", "function": {
                "name": "save",
                "parameters": {
                    "allOf": [
                        { "type": "object", "properties": { "id": { "type": "string" } }, "required": ["id"] },
                        { "properties": { "note": { "type": "string" } }, "required": ["note"] }
                    ]
                }
            }}]
        });
        let out = build_upstream_body(&body, "gemini-2.5-flash", None);
        let parameters = out.body.pointer("/tools/0/functionDeclarations/0/parameters").unwrap();
        assert!(parameters.get("allOf").is_none(), "allOf 要摊平");
        assert!(parameters.pointer("/properties/id").is_some());
        assert!(parameters.pointer("/properties/note").is_some());
        let mut required: Vec<String> = parameters
            .get("required")
            .and_then(Value::as_array)
            .map(|items| {
                items
                    .iter()
                    .filter_map(Value::as_str)
                    .map(str::to_string)
                    .collect()
            })
            .unwrap_or_default();
        required.sort();
        assert_eq!(required, vec!["id".to_string(), "note".to_string()]);
    }

    #[test]
    fn one_of_becomes_any_of_and_unsupported_combinators_are_dropped() {
        let body = json!({
            "messages": [{ "role": "user", "content": "hi" }],
            "tools": [{ "type": "function", "function": {
                "name": "pick",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "choice": { "oneOf": [{ "type": "string" }, { "type": "number" }] },
                        "never": { "type": "string", "not": { "const": "x" } }
                    }
                }
            }}]
        });
        let out = build_upstream_body(&body, "gemini-2.5-flash", None);
        let parameters = out.body.pointer("/tools/0/functionDeclarations/0/parameters").unwrap();
        let choice = parameters.pointer("/properties/choice").unwrap();
        assert!(choice.get("oneOf").is_none(), "Gemini 不认 oneOf");
        assert_eq!(
            choice.get("anyOf").and_then(Value::as_array).map(Vec::len),
            Some(2)
        );
        assert!(parameters.pointer("/properties/never/not").is_none(), "not 要丢掉");
    }

    #[test]
    fn all_of_and_sibling_properties_are_both_kept() {
        // `allOf` 字母序在 `properties` 之前，合并完再被同层的 `properties`
        // 覆盖就会静默丢属性。
        let body = json!({
            "messages": [{ "role": "user", "content": "hi" }],
            "tools": [{ "type": "function", "function": {
                "name": "save",
                "parameters": {
                    "type": "object",
                    "allOf": [
                        { "properties": { "fromAllOf": { "type": "string" } }, "required": ["fromAllOf"] }
                    ],
                    "properties": { "sibling": { "type": "string" } },
                    "required": ["sibling"]
                }
            }}]
        });
        let out = build_upstream_body(&body, "gemini-2.5-flash", None);
        let parameters = out.body.pointer("/tools/0/functionDeclarations/0/parameters").unwrap();
        assert!(parameters.pointer("/properties/fromAllOf").is_some(), "allOf 合并的属性丢了");
        assert!(parameters.pointer("/properties/sibling").is_some(), "同层 properties 丢了");
        let mut required: Vec<String> = parameters
            .get("required")
            .and_then(Value::as_array)
            .map(|items| items.iter().filter_map(Value::as_str).map(str::to_string).collect())
            .unwrap_or_default();
        required.sort();
        assert_eq!(required, vec!["fromAllOf".to_string(), "sibling".to_string()]);
    }

    #[test]
    fn boolean_schemas_never_reach_the_anyof_branches() {
        // JSON Schema 允许 `true` / `{}` 当整个 schema 用。原样塞进 anyOf 就是
        // `Starting an object on a scalar field`。
        let body = json!({
            "messages": [{ "role": "user", "content": "hi" }],
            "tools": [{ "type": "function", "function": {
                "name": "pick",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "choice": { "anyOf": [true, { "type": "string" }, null, false] }
                    }
                }
            }}]
        });
        let out = build_upstream_body(&body, "gemini-2.5-flash", None);
        let branches = out
            .body
            .pointer("/tools/0/functionDeclarations/0/parameters/properties/choice/anyOf")
            .and_then(Value::as_array)
            .expect("anyOf 还在");
        assert_eq!(branches.len(), 4, "分支数量不变，但每个都要变成对象");
        for branch in branches {
            assert!(branch.is_object(), "anyOf 分支必须是对象，实际是 {branch}");
        }
    }

    #[test]
    fn array_types_collapse_to_one_enum_value() {
        let body = json!({
            "messages": [{ "role": "user", "content": "hi" }],
            "tools": [{ "type": "function", "function": {
                "name": "f",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "maybe": { "type": ["string", "null"] },
                        "either": { "type": ["integer", "string"] },
                        "weird": { "type": "dict" }
                    }
                }
            }}]
        });
        let out = build_upstream_body(&body, "gemini-2.5-flash", None);
        let props = out
            .body
            .pointer("/tools/0/functionDeclarations/0/parameters/properties")
            .unwrap();
        assert_eq!(props.pointer("/maybe/type").and_then(Value::as_str), Some("string"));
        assert_eq!(
            props.pointer("/maybe/nullable").and_then(Value::as_bool),
            Some(true),
            "null 要转成 nullable"
        );
        assert_eq!(props.pointer("/either/type").and_then(Value::as_str), Some("integer"));
        assert_eq!(props.pointer("/weird/type").and_then(Value::as_str), Some("object"));
        for name in ["maybe", "either", "weird"] {
            assert!(
                props.pointer(&format!("/{name}/type")).map(Value::is_string) == Some(true),
                "{name} 的 type 必须是标量"
            );
        }
    }

    #[test]
    fn unknown_keys_and_formats_are_dropped() {
        let body = json!({
            "messages": [{ "role": "user", "content": "hi" }],
            "tools": [{ "type": "function", "function": {
                "name": "f",
                "parameters": {
                    "type": "object",
                    "x-custom": "nope",
                    "contentMediaType": "image/png",
                    "properties": {
                        "when": { "type": "string", "format": "date-time" },
                        "bad": { "type": "string", "format": "uri-template" },
                        "amount": { "type": "number", "minimum": 0, "exclusiveMinimum": 1 }
                    }
                }
            }}]
        });
        let out = build_upstream_body(&body, "gemini-2.5-flash", None);
        let parameters = out.body.pointer("/tools/0/functionDeclarations/0/parameters").unwrap();
        assert!(parameters.get("x-custom").is_none());
        assert!(parameters.get("contentMediaType").is_none());
        assert_eq!(
            parameters.pointer("/properties/when/format").and_then(Value::as_str),
            Some("date-time")
        );
        assert!(
            parameters.pointer("/properties/bad/format").is_none(),
            "不认识的 format 会报 Invalid value，必须丢"
        );
        assert_eq!(
            parameters.pointer("/properties/amount/minimum").and_then(Value::as_f64),
            Some(0.0)
        );
        assert!(parameters.pointer("/properties/amount/exclusiveMinimum").is_none());
    }

    #[test]
    fn tuple_items_fall_back_to_the_first_schema() {
        let body = json!({
            "messages": [{ "role": "user", "content": "hi" }],
            "tools": [{ "type": "function", "function": {
                "name": "f",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "pair": { "type": "array", "items": [{ "type": "string" }, { "type": "number" }] }
                    }
                }
            }}]
        });
        let out = build_upstream_body(&body, "gemini-2.5-flash", None);
        let items = out
            .body
            .pointer("/tools/0/functionDeclarations/0/parameters/properties/pair/items")
            .unwrap();
        assert!(items.is_object(), "元组 items 要收成单个 schema 对象");
        assert_eq!(items.get("type").and_then(Value::as_str), Some("string"));
    }

    #[test]
    fn every_node_in_a_deep_schema_is_an_object() {
        // 递归类型：数组 → anyOf → 对象 → 数组 …，每一层都必须还是对象。
        let body = json!({
            "messages": [{ "role": "user", "content": "hi" }],
            "tools": [{ "type": "function", "function": {
                "name": "walk",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "tree": {
                            "anyOf": [
                                { "type": "string" },
                                {
                                    "type": "array",
                                    "items": {
                                        "anyOf": [
                                            { "type": "number" },
                                            { "type": "object", "properties": { "leaf": { "type": "boolean" } } }
                                        ]
                                    }
                                }
                            ]
                        }
                    }
                }
            }}]
        });
        let out = build_upstream_body(&body, "gemini-2.5-flash", None);
        let tree = out
            .body
            .pointer("/tools/0/functionDeclarations/0/parameters/properties/tree")
            .unwrap();
        let mut stack = vec![tree];
        while let Some(node) = stack.pop() {
            assert!(node.is_object(), "节点必须是对象，实际是 {node}");
            if let Some(branches) = node.get("anyOf").and_then(Value::as_array) {
                stack.extend(branches);
            }
            if let Some(items) = node.get("items") {
                stack.push(items);
            }
            if let Some(props) = node.get("properties").and_then(Value::as_object) {
                stack.extend(props.values());
            }
        }
    }

    #[test]
    fn missing_types_are_inferred() {
        let body = json!({
            "messages": [{ "role": "user", "content": "hi" }],
            "tools": [{ "type": "function", "function": {
                "name": "f",
                "parameters": {
                    "properties": {
                        "obj": { "properties": { "a": { "type": "string" } } },
                        "arr": { "items": { "type": "string" } },
                        "col": { "enum": [true, false] },
                        "num": { "enum": [1, 2, 3] },
                        "poly": { "anyOf": [{ "type": "string" }, { "type": "number" }] }
                    }
                }
            }}]
        });
        let out = build_upstream_body(&body, "gemini-2.5-flash", None);
        let parameters = out.body.pointer("/tools/0/functionDeclarations/0/parameters").unwrap();
        assert_eq!(parameters.get("type").and_then(Value::as_str), Some("object"));
        assert_eq!(parameters.pointer("/properties/obj/type").and_then(Value::as_str), Some("object"));
        assert_eq!(parameters.pointer("/properties/arr/type").and_then(Value::as_str), Some("array"));
        assert_eq!(parameters.pointer("/properties/col/type").and_then(Value::as_str), Some("boolean"));
        assert_eq!(parameters.pointer("/properties/num/type").and_then(Value::as_str), Some("integer"));
        assert!(
            parameters.pointer("/properties/poly/type").is_none(),
            "多态节点不该被硬塞 type"
        );
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
