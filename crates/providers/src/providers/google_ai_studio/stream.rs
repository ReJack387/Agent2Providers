//! Gemini 原生 SSE 帧 → OpenAI chat 帧的翻译。
//!
//! ── 上游帧长这样 ─────────────────────────────────────────────
//! ```text
//! data: {"candidates":[{"content":{"role":"model","parts":[{"text":"你"}]},"index":0}],"modelVersion":"gemini-2.5-flash"}
//! data: {"candidates":[{"content":{"role":"model","parts":[{"text":"想一想","thought":true}]},"index":0}]}
//! data: {"candidates":[{"content":{"role":"model","parts":[{"functionCall":{"name":"read","args":{"path":"a.txt"}}}]},"finishReason":"STOP"}],"usageMetadata":{"promptTokenCount":10,"candidatesTokenCount":5,"totalTokenCount":15}}
//! ```
//!
//! ── 三处与 OpenAI 不同 ──────────────────────────────────────
//! 1. 思考是 part 上的标记 `{"thought":true,"text":…}` → 翻成
//!    `delta.reasoning_content`，不能混进正文。
//! 2. 函数调用是 `functionCall` 对象（`args` 已经是对象，不是字符串），
//!    而且**可能分多帧各给一个调用**；每个调用自己一帧就完，不需要像
//!    accio 那样拼参数碎片。
//! 3. 业务错误写在帧里（`{"error":{…}}`），HTTP 状态常是 200 → 首帧与
//!    流内都要判。
//!
//! 本文件在转发热路径上，**不允许 unwrap / expect / panic**，取值一律走
//! Option 链。

use serde_json::{json, Value};

use crate::sse::SseLine;

/// 一个上游帧里我们关心的字段。
pub struct Frame {
    pub candidates: Vec<Value>,
    pub usage: Option<Value>,
    pub model_version: String,
    pub error: Option<String>,
    /// 提示词被安全策略拦下时的原因（`promptFeedback.blockReason`）。
    ///
    /// 这种帧**没有 candidates**，不单独认出来的话会变成「空回答 + stop」，
    /// 客户端看不出是被拦了。
    pub blocked: Option<String>,
}

/// 解析一行 SSE 的 `data:` 内容。
///
/// 返回 `None` = 这一行不是帧（空行、`[DONE]`、非 JSON）。
pub fn parse_frame(data: &str) -> Option<Frame> {
    let trimmed = data.trim();
    if trimmed.is_empty() || trimmed == "[DONE]" || trimmed == "[done]" {
        return None;
    }
    let value: Value = serde_json::from_str(trimmed).ok()?;
    let object = value.as_object()?;

    // 上游用 200 回错误帧，得在这里就认出来。
    if let Some(error) = object.get("error") {
        let message = error
            .get("message")
            .and_then(Value::as_str)
            .filter(|text| !text.trim().is_empty())
            .unwrap_or("上游返回了一个错误帧");
        return Some(Frame {
            candidates: Vec::new(),
            usage: None,
            model_version: String::new(),
            error: Some(message.to_string()),
            blocked: None,
        });
    }

    let candidates = object
        .get("candidates")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    // 提示词被拦：只有 promptFeedback，没有 candidates。
    let blocked = object
        .get("promptFeedback")
        .and_then(|feedback| feedback.get("blockReason"))
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|reason| !reason.is_empty())
        .map(str::to_string);
    Some(Frame {
        candidates,
        usage: object.get("usageMetadata").cloned(),
        model_version: object
            .get("modelVersion")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string(),
        error: None,
        blocked,
    })
}

/// 翻译出来的一段增量。
pub enum Delta {
    Content(String),
    Reasoning(String),
    ToolCall {
        index: i64,
        id: String,
        name: String,
        arguments: String,
        /// 模型给这次调用打的签名。客户端若原样带回来，下一轮就不用靠缓存兜。
        signature: Option<String>,
    },
}

/// `usageMetadata` → OpenAI `usage`。
///
/// 思考 token 计入 `completion_tokens`（OpenAI 口径）。
pub fn parse_usage(usage: &Value) -> Option<Value> {
    let prompt = usage.get("promptTokenCount").and_then(Value::as_i64);
    let candidates = usage.get("candidatesTokenCount").and_then(Value::as_i64);
    let thoughts = usage.get("thoughtsTokenCount").and_then(Value::as_i64).unwrap_or(0);
    let total = usage.get("totalTokenCount").and_then(Value::as_i64);
    let cached = usage
        .get("cachedContentTokenCount")
        .and_then(Value::as_i64)
        .unwrap_or(0);

    let prompt = prompt?;
    let completion = candidates.unwrap_or(0) + thoughts;
    let total = total.filter(|value| *value > 0).unwrap_or(prompt + completion);

    let mut out = json!({
        "prompt_tokens": prompt,
        "completion_tokens": completion,
        "total_tokens": total,
    });
    if cached > 0 {
        out["prompt_tokens_details"] = json!({ "cached_tokens": cached });
    }
    Some(out)
}

/// 累积状态 + 输出增量。
pub struct Translator {
    pub tool_index: i64,
    pub finish_reason: Option<String>,
    pub usage: Option<Value>,
    pub model_version: String,
    pub saw_tool_call: bool,
    pub emitted: bool,
    /// call id 的随机前缀。
    ///
    /// **call id 必须跨响应唯一。** 客户端会把整段历史一起发回来，两轮里各有一个
    /// 「第 0 个工具调用」，如果 id 都叫 `call_0`，签名缓存就会串键 —— 后一轮的
    /// 签名盖掉前一轮，回放时上游要么报 `Corrupted thought signature`，要么按
    /// 错签名理解上下文。加一段随机前缀就能让每一轮的各次调用天然不撞。
    nonce: String,
}

impl Translator {
    pub fn new() -> Self {
        Self {
            tool_index: 0,
            finish_reason: None,
            usage: None,
            model_version: String::new(),
            saw_tool_call: false,
            emitted: false,
            nonce: crate::ids::new_message_id(),
        }
    }

    /// 吃一帧，吐出要推给客户端的增量。
    pub fn consume(&mut self, frame: &Frame) -> Vec<Delta> {
        let mut deltas = Vec::new();

        if self.model_version.is_empty() && !frame.model_version.is_empty() {
            self.model_version = frame.model_version.clone();
        }
        if let Some(usage) = frame.usage.as_ref() {
            if let Some(parsed) = parse_usage(usage) {
                self.usage = Some(parsed);
            }
        }

        for candidate in &frame.candidates {
            if let Some(reason) = candidate.get("finishReason").and_then(Value::as_str) {
                if !reason.is_empty() {
                    self.finish_reason = Some(super::protocol::finish_reason(reason).to_string());
                }
            }
            let Some(parts) = candidate.pointer("/content/parts").and_then(Value::as_array) else {
                continue;
            };
            for part in parts {
                if let Some(call) = part.get("functionCall") {
                    let name = call
                        .get("name")
                        .and_then(Value::as_str)
                        .unwrap_or_default()
                        .trim()
                        .to_string();
                    if name.is_empty() {
                        continue;
                    }
                    let arguments = match call.get("args") {
                        Some(Value::String(text)) => text.clone(),
                        Some(other) => other.to_string(),
                        None => "{}".to_string(),
                    };
                    let index = self.tool_index;
                    self.tool_index += 1;
                    self.saw_tool_call = true;
                    // 带 nonce，跨响应不撞（见 `Translator::nonce` 的注释）。
                    let id = format!("call_{}_{index}", self.nonce);
                    // 签名必须存下来：下一轮客户端回传工具结果时，上游要求
                    // 历史里的 `functionCall` 带着它，否则 400。
                    let signature = super::signatures::signature_of(part);
                    if let Some(value) = signature.as_deref() {
                        super::signatures::remember(&id, value);
                    }
                    deltas.push(Delta::ToolCall {
                        index,
                        id,
                        name,
                        arguments,
                        signature,
                    });
                    continue;
                }
                let Some(text) = part.get("text").and_then(Value::as_str) else {
                    continue;
                };
                if text.is_empty() {
                    continue;
                }
                if part.get("thought").and_then(Value::as_bool).unwrap_or(false) {
                    deltas.push(Delta::Reasoning(text.to_string()));
                } else {
                    deltas.push(Delta::Content(text.to_string()));
                }
            }
        }

        if !deltas.is_empty() {
            self.emitted = true;
        }
        deltas
    }

    /// 收尾的 `finish_reason`：有工具调用就不能报 `stop`，否则客户端
    /// 会以为模型说完了。
    pub fn final_finish_reason(&self) -> String {
        if self.saw_tool_call {
            return "tool_calls".to_string();
        }
        self.finish_reason.clone().unwrap_or_else(|| "stop".to_string())
    }
}

impl Default for Translator {
    fn default() -> Self {
        Self::new()
    }
}

/// 从一行原始 SSE 文本里取 `data:` 内容（兼容 `event:` / `id:` 行）。
pub fn data_of(line: &str) -> Option<String> {
    SseLine::parse(line).data().map(str::to_string)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn text_becomes_content() {
        let frame = parse_frame(
            r#"{"candidates":[{"content":{"role":"model","parts":[{"text":"你"}]},"index":0}]}"#,
        )
        .unwrap();
        let mut translator = Translator::new();
        let deltas = translator.consume(&frame);
        match deltas.first() {
            Some(Delta::Content(text)) => assert_eq!(text, "你"),
            _ => panic!("应该是正文增量"),
        }
    }

    #[test]
    fn thought_parts_become_reasoning() {
        let frame = parse_frame(
            r#"{"candidates":[{"content":{"role":"model","parts":[{"text":"想一想","thought":true}]}}]}"#,
        )
        .unwrap();
        let mut translator = Translator::new();
        let deltas = translator.consume(&frame);
        match deltas.first() {
            Some(Delta::Reasoning(text)) => assert_eq!(text, "想一想"),
            _ => panic!("应该是思考增量"),
        }
    }

    #[test]
    fn function_calls_get_indexes() {
        let frame = parse_frame(
            r#"{"candidates":[{"content":{"parts":[{"functionCall":{"name":"read","args":{"path":"a.txt"}}}]},"finishReason":"STOP"}]}"#,
        )
        .unwrap();
        let mut translator = Translator::new();
        let deltas = translator.consume(&frame);
        match deltas.first() {
            Some(Delta::ToolCall { index, name, arguments, .. }) => {
                assert_eq!(*index, 0);
                assert_eq!(name, "read");
                assert_eq!(arguments, r#"{"path":"a.txt"}"#);
            }
            _ => panic!("应该是工具调用增量"),
        }
        assert_eq!(translator.final_finish_reason(), "tool_calls");
    }

    #[test]
    fn error_frames_are_detected() {
        let frame = parse_frame(r#"{"error":{"code":400,"message":"API key not valid"}}"#).unwrap();
        assert_eq!(frame.error.as_deref(), Some("API key not valid"));
    }

    #[test]
    fn blocked_prompts_are_detected() {
        // 被拦时没有 candidates，只有 promptFeedback。
        let frame = parse_frame(
            r#"{"promptFeedback":{"blockReason":"PROHIBITED_CONTENT"}}"#,
        )
        .unwrap();
        assert_eq!(frame.blocked.as_deref(), Some("PROHIBITED_CONTENT"));
        assert!(frame.candidates.is_empty());
        assert!(frame.error.is_none());

        // 正常帧不能误报成被拦。
        let frame = parse_frame(
            r#"{"candidates":[{"content":{"parts":[{"text":"好"}]}}]}"#,
        )
        .unwrap();
        assert!(frame.blocked.is_none());
    }

    #[test]
    fn usage_counts_thoughts_as_output() {
        let usage = json!({
            "promptTokenCount": 10,
            "candidatesTokenCount": 5,
            "thoughtsTokenCount": 7,
            "totalTokenCount": 22
        });
        let parsed = parse_usage(&usage).unwrap();
        assert_eq!(parsed.get("prompt_tokens").and_then(Value::as_i64), Some(10));
        assert_eq!(parsed.get("completion_tokens").and_then(Value::as_i64), Some(12));
        assert_eq!(parsed.get("total_tokens").and_then(Value::as_i64), Some(22));
    }

    #[test]
    fn done_and_blank_are_not_frames() {
        assert!(parse_frame("[DONE]").is_none());
        assert!(parse_frame("   ").is_none());
    }
}
