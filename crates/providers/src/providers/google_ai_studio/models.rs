//! 模型目录：拉 `GET /v1beta/models`，缓存 10 分钟，拉不到就用静态兜底。
//!
//! ── 为什么要有兜底 ──────────────────────────────────────────
//! 目录是「锦上添花」：拉失败不该让用户看不到任何模型，也不该让刚添加
//! 的账号在界面上一片空白。所以 `list()` 在缓存过期时回退到静态表，
//! 只有 `refresh()` 才会把错误交给上层显示。

use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

use serde_json::{json, Value};

use agent2api_provider_protocol as proto;
use agent2api_provider_sdk::PluginCtx;

use super::credentials;
use super::endpoints::{self, PROVIDER_ID};
use crate::http;
use crate::logging;

struct Catalog {
    models: Vec<Value>,
    fetched_at: i64,
}

fn cache() -> &'static Mutex<HashMap<String, Catalog>> {
    static CACHE: OnceLock<Mutex<HashMap<String, Catalog>>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

fn with_cache<T>(action: impl FnOnce(&mut HashMap<String, Catalog>) -> T) -> T {
    match cache().lock() {
        Ok(mut table) => action(&mut table),
        Err(poisoned) => action(&mut poisoned.into_inner()),
    }
}

/// 静态兜底清单。
///
/// 只放「确定能用 generateContent」的主力型号；真实清单以远程为准。
pub fn fallback_models() -> Vec<Value> {
    let rows: [(&str, &str, i64, i64, bool); 6] = [
        ("gemini-2.5-pro", "Gemini 2.5 Pro", 1_048_576, 65_536, false),
        ("gemini-2.5-flash", "Gemini 2.5 Flash", 1_048_576, 65_536, true),
        ("gemini-2.5-flash-lite", "Gemini 2.5 Flash Lite", 1_048_576, 65_536, false),
        ("gemini-2.0-flash", "Gemini 2.0 Flash", 1_048_576, 8_192, false),
        ("gemini-2.0-flash-lite", "Gemini 2.0 Flash Lite", 1_048_576, 8_192, false),
        ("gemini-1.5-flash", "Gemini 1.5 Flash", 1_048_576, 8_192, false),
    ];
    rows.iter()
        .map(|(id, name, input, output, default)| {
            json!({
                "id": id,
                "name": name,
                "maxInputTokens": input,
                "maxOutputTokens": output,
                "supportsToolCall": true,
                "supportsReasoning": super::protocol::supports_thinking(id),
                "supportsImages": true,
                "isDefault": default,
            })
        })
        .collect()
}

/// 一条上游模型记录 → 我们的模型记录。
fn row_of(entry: &Value) -> Option<Value> {
    let name = entry.get("name").and_then(Value::as_str)?.trim();
    if name.is_empty() {
        return None;
    }
    // 上游叫 `models/gemini-2.5-flash`，客户端要的是裸 id。
    let id = name.strip_prefix("models/").unwrap_or(name).to_string();
    if id.is_empty() {
        return None;
    }
    // 只留能对话的：embedding / aqa / 图像生成这些在 chat 里点了就报错。
    let methods = entry
        .get("supportedGenerationMethods")
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .any(|method| method == "generateContent" || method == "streamGenerateContent")
        })
        .unwrap_or(true);
    if !methods {
        return None;
    }

    let display = entry
        .get("displayName")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|text| !text.is_empty())
        .unwrap_or(&id)
        .to_string();

    let mut record = json!({
        "id": id,
        "name": display,
        "supportsToolCall": true,
        "supportsReasoning": super::protocol::supports_thinking(&id),
        "supportsImages": true,
        "isDefault": id == endpoints::DEFAULT_MODEL,
    });
    if let Some(limit) = entry.get("inputTokenLimit").and_then(Value::as_i64) {
        if limit > 0 {
            record["maxInputTokens"] = json!(limit);
        }
    }
    if let Some(limit) = entry.get("outputTokenLimit").and_then(Value::as_i64) {
        if limit > 0 {
            record["maxOutputTokens"] = json!(limit);
        }
    }
    Some(record)
}

/// 解析一页响应。
fn parse_page(payload: &Value) -> Result<(Vec<Value>, Option<String>), String> {
    let models = payload
        .get("models")
        .and_then(Value::as_array)
        .ok_or_else(|| "Gemini 模型目录格式不认识（没有 models 数组）".to_string())?;
    let rows: Vec<Value> = models.iter().filter_map(row_of).collect();
    let next = payload
        .get("nextPageToken")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|token| !token.is_empty())
        .map(str::to_string);
    Ok((rows, next))
}

/// 读缓存里的清单（不判断新鲜度）。
fn cached(account: &str) -> Option<(Vec<Value>, i64)> {
    with_cache(|table| {
        table
            .get(account)
            .map(|catalog| (catalog.models.clone(), catalog.fetched_at))
    })
}

fn store(account: &str, models: Vec<Value>) {
    with_cache(|table| {
        table.insert(
            account.to_string(),
            Catalog {
                models,
                fetched_at: http::now_ms(),
            },
        );
    });
}

/// 给网关的清单（同步、不联网）。
pub fn list(account: &str) -> proto::ModelList {
    match cached(account) {
        Some((models, fetched_at))
            if !models.is_empty() && http::now_ms() - fetched_at < endpoints::CATALOG_TTL_MS =>
        {
            proto::ModelList {
                models,
                meta: proto::CatalogMeta {
                    remote: true,
                    refreshed_at: fetched_at,
                },
            }
        }
        Some((models, _)) if !models.is_empty() => proto::ModelList {
            models,
            meta: proto::CatalogMeta::default(),
        },
        _ => proto::ModelList {
            models: fallback_models(),
            meta: proto::CatalogMeta::default(),
        },
    }
}

/// 拉一次远程目录。
pub async fn refresh(
    ctx: &PluginCtx,
    account: &str,
    force: bool,
) -> Result<(proto::RefreshOutcome, Vec<Value>), String> {
    if !force {
        if let Some((models, fetched_at)) = cached(account) {
            if !models.is_empty() && http::now_ms() - fetched_at < endpoints::CATALOG_TTL_MS {
                return Ok((proto::RefreshOutcome::unchanged(), models));
            }
        }
    }

    let found = ctx
        .store_get(PROVIDER_ID, account)
        .await
        .map_err(|error| format!("读取账号失败：{error}"))?;
    let token = credentials::token_of(&found.secret)?;

    // ── 代理必须取账号自己的 ──────────────────────────────────────
    // 网关调用 `models.refresh` 时**只带 account 与 force**，不像
    // `conversation` 那样把选路结果放进 `proxy` 字段（见网关
    // `plugin_host__rpc.rs` 的 `MODELS_REFRESH` 分支）。所以这里只能自己
    // 从账号记录里解析 —— `ctx.env.proxy` 是「网关默认出口」，用户把代理
    // 配在账号上时它是空的，直接用就会去直连 generativelanguage.googleapis.com，
    // 表现是「聊天能用、拉模型目录超时」。
    let proxy = super::proxy::of_account(&found)?;

    let client = http::control_client(proxy.as_ref(), &ctx.env.proxy);
    let headers = [
        ("x-goog-api-key".to_string(), token),
        ("Accept".to_string(), "application/json".to_string()),
    ];

    let mut collected: Vec<Value> = Vec::new();
    let mut page_token: Option<String> = None;
    for _ in 0..endpoints::CATALOG_MAX_PAGES {
        let mut url = format!(
            "{}?pageSize={}",
            endpoints::MODELS_URL,
            endpoints::CATALOG_PAGE_SIZE
        );
        if let Some(token) = page_token.as_ref() {
            url.push_str("&pageToken=");
            url.push_str(&urlencoding(token));
        }
        let (status, payload) = http::get_json(&client, &url, &headers)
            .await
            .map_err(|message| format!("拉取模型目录失败：{message}"))?;
        if !(200..300).contains(&status) {
            let message = payload
                .pointer("/error/message")
                .and_then(Value::as_str)
                .unwrap_or("上游拒绝了模型目录请求")
                .to_string();
            return Err(format!("拉取模型目录失败（{status}）：{message}"));
        }
        let (rows, next) = parse_page(&payload)?;
        collected.extend(rows);
        match next {
            Some(token) => page_token = Some(token),
            None => break,
        }
    }

    if collected.is_empty() {
        return Err("Gemini 模型目录为空（保留现有清单）".to_string());
    }
    // 去重（分页边界可能重复），保持首次出现顺序。
    let mut seen = std::collections::HashSet::new();
    collected.retain(|row| {
        row.get("id")
            .and_then(Value::as_str)
            .map(|id| seen.insert(id.to_string()))
            .unwrap_or(false)
    });
    // 默认模型排最前，方便界面直接选中。
    collected.sort_by_key(|row| {
        !row.get("isDefault")
            .and_then(Value::as_bool)
            .unwrap_or(false)
    });

    let count = collected.len();
    logging::verbose(
        "google-ai-studio",
        &format!("模型目录已更新：{count} 个模型"),
    );
    store(account, collected.clone());
    Ok((proto::RefreshOutcome::refreshed(count), collected))
}

/// 最小化的 query 转义（只处理 pageToken 里可能出现的字符）。
fn urlencoding(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for byte in text.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(byte as char);
            }
            other => out.push_str(&format!("%{other:02X}")),
        }
    }
    out
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn strips_the_models_prefix() {
        let row = row_of(&json!({
            "name": "models/gemini-2.5-flash",
            "displayName": "Gemini 2.5 Flash",
            "inputTokenLimit": 1048576,
            "outputTokenLimit": 65536,
            "supportedGenerationMethods": ["generateContent", "countTokens"]
        }))
        .unwrap();
        assert_eq!(row.get("id").and_then(Value::as_str), Some("gemini-2.5-flash"));
        assert_eq!(row.get("isDefault").and_then(Value::as_bool), Some(true));
        assert_eq!(
            row.get("maxOutputTokens").and_then(Value::as_i64),
            Some(65536)
        );
    }

    #[test]
    fn drops_non_chat_models() {
        let row = row_of(&json!({
            "name": "models/text-embedding-004",
            "supportedGenerationMethods": ["embedContent"]
        }));
        assert!(row.is_none());
    }

    #[test]
    fn reads_the_page_token() {
        let (rows, next) = parse_page(&json!({
            "models": [{ "name": "models/gemini-2.5-pro", "supportedGenerationMethods": ["generateContent"] }],
            "nextPageToken": "abc"
        }))
        .unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(next.as_deref(), Some("abc"));
    }

    #[test]
    fn fallback_marks_a_default() {
        let models = fallback_models();
        assert!(models
            .iter()
            .any(|row| row.get("isDefault").and_then(Value::as_bool).unwrap_or(false)));
    }
}
