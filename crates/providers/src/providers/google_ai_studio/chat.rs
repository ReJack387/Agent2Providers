//! 会话式转发：打 Gemini 原生 `streamGenerateContent`，把帧翻成 OpenAI chat 帧。
//!
//! ── 为什么是 `conversation` 而不是 `build_chat` ────────────────
//! 上游回的是 `data: {"candidates":[…]}` 裸帧，网关的 `UpstreamKind::Gemini`
//! 认的是 Antigravity 的 `data: {"response":{…}}` 信封，两者不同形。所以
//! 由插件自己读帧、自己翻，申报 `stateful = true`。
//!
//! ── 只写一条流式路径 ─────────────────────────────────────────
//! 网关 `forward_conversation` 恒发 `stream: true`，客户端要非流式时由网关
//! 的 `aggregate_frame_stream` 把这里推的帧聚合成一个 JSON。所以这里不做
//! 非流式分支，也不需要预先把整段回答缓冲到内存（那会毁掉背压）。

use std::collections::{BTreeMap, VecDeque};

use bytes::Bytes;
use futures::{Stream, StreamExt};
use serde_json::{json, Value};

use agent2api_provider_protocol as proto;
use agent2api_provider_sdk::{ConversationSink, PluginCtx};

use super::credentials;
use super::endpoints::{self, PROVIDER_ID};
use super::protocol;
use super::stream::{self, Delta, Translator};
use crate::{http, ids, logging, sse};

/// 入口：任何失败都要先 `head` 再写错误体，否则网关拿不到状态码。
pub async fn run(
    ctx: &PluginCtx,
    request: proto::ConversationRequest,
    mut sink: ConversationSink<'_>,
) -> Result<(), String> {
    match forward(ctx, &request, &mut sink).await {
        Ok(()) => Ok(()),
        Err((status, message)) => {
            logging::verbose(
                PROVIDER_ID,
                &format!("转发失败（{status}）：{message}"),
            );
            head(&mut sink, status).await?;
            let body = error_body(status, &message).to_string();
            sink.send(body.as_bytes()).await
        }
    }
}

async fn head(sink: &mut ConversationSink<'_>, status: u16) -> Result<(), String> {
    let content_type = if status == 200 {
        "text/event-stream"
    } else {
        "application/json"
    };
    sink.head(proto::StreamHead {
        status,
        headers: BTreeMap::from([("content-type".to_string(), content_type.to_string())]),
        upstream: proto::UpstreamKind::Chat,
    })
    .await
}

/// 错误体的形状跟 OpenAI 一致，客户端不用为这家写特例。
fn error_body(status: u16, message: &str) -> Value {
    let kind = match status {
        401 | 403 => "authentication_error",
        429 => "rate_limit_error",
        400 => "invalid_request_error",
        _ => "api_error",
    };
    json!({ "error": { "type": kind, "message": message } })
}

fn sse_frame(payload: &Value) -> Vec<u8> {
    format!("data: {payload}\n\n").into_bytes()
}

/// 一段增量 → chat 帧。
fn delta_frame(
    id: &str,
    model: &str,
    created: i64,
    delta: Value,
    finish: Option<&str>,
) -> Vec<u8> {
    sse_frame(&sse::chat_chunk(id, model, created, delta, finish))
}

/// 收尾的 usage 帧（单独一帧，`choices` 为空，与 OpenAI 的 `stream_options`
/// 行为一致）。
fn usage_frame(id: &str, model: &str, created: i64, usage: &Value) -> Vec<u8> {
    sse_frame(&json!({
        "id": id,
        "object": "chat.completion.chunk",
        "created": created,
        "model": model,
        "choices": [],
        "usage": usage,
    }))
}

/// 上游错误文案 → 给客户端的状态码。
fn classify_message(message: &str) -> u16 {
    let lower = message.to_ascii_lowercase();
    if lower.contains("rate limit")
        || lower.contains("quota")
        || lower.contains("resource_exhausted")
        || lower.contains("exceeded")
        || lower.contains("too many requests")
    {
        return 429;
    }
    if lower.contains("api key not valid")
        || lower.contains("api_key_invalid")
        || lower.contains("permission denied")
        || lower.contains("unauthenticated")
        || lower.contains("invalid api key")
    {
        return 401;
    }
    if lower.contains("context") && (lower.contains("long") || lower.contains("exceed")) {
        return 400;
    }
    if lower.contains("safety") || lower.contains("blocked") || lower.contains("prohibited") {
        return 400;
    }
    502
}

fn upstream_url(model: &str) -> String {
    let encoded = encode_segment(model);
    format!(
        "{}/models/{}:streamGenerateContent?alt=sse",
        endpoints::API_BASE,
        encoded
    )
}

/// 模型名进路径前做最小转义（正常模型名不需要转义，但别让畸形输入拼坏 URL）。
fn encode_segment(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for byte in text.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(byte as char)
            }
            other => out.push_str(&format!("%{other:02X}")),
        }
    }
    out
}

/// 主流程。
async fn forward(
    ctx: &PluginCtx,
    request: &proto::ConversationRequest,
    sink: &mut ConversationSink<'_>,
) -> Result<(), (u16, String)> {
    if request.account.trim().is_empty() {
        return Err((400, "请求里没有指定账号".to_string()));
    }
    let found = ctx
        .store_get(PROVIDER_ID, &request.account)
        .await
        .map_err(|error| (502, format!("读取账号失败：{error}")))?;
    let token = credentials::token_of(&found.secret).map_err(|message| (401, message))?;

    let body = &request.body;
    let model = {
        let wire = request.wire_model.trim();
        if wire.is_empty() {
            body.get("model")
                .and_then(Value::as_str)
                .unwrap_or(endpoints::DEFAULT_MODEL)
                .trim()
                .to_string()
        } else {
            wire.to_string()
        }
    };
    if model.is_empty() {
        return Err((400, "请求里没有指定模型".to_string()));
    }

    let effort = protocol::client_effort(body);
    let outbound = protocol::build_upstream_body(body, &model, effort.as_deref());

    // 网关通常已经把选路结果放进 `request.proxy`；但它为空时不能直接退回
    // 网关默认出口 —— 用户可能把代理配在**账号**上，那样默认出口是空的，
    // 直连会超时。所以再兜一层账号代理。
    let account_proxy = super::proxy::of_account(&found).map_err(|message| (502, message))?;
    let proxy = request.proxy.clone().or(account_proxy);

    let client = http::stream_client(proxy.as_ref(), &ctx.env.proxy);
    let headers = [
        ("x-goog-api-key".to_string(), token),
        ("Accept".to_string(), "text/event-stream".to_string()),
    ];
    let url = upstream_url(&model);
    let response = http::post_stream(
        &client,
        &url,
        &headers,
        &outbound.body,
        "text/event-stream",
    )
    .await
    .map_err(|message| (502, message))?;

    if !response.is_success() {
        let raw = response.error_head();
        let message = extract_error(&raw).unwrap_or_else(|| {
            if raw.trim().is_empty() {
                format!("上游返回了 {}", response.status)
            } else {
                raw
            }
        });
        return Err((classify_message(&message), message));
    }

    let Some(response) = response.response else {
        return Err((502, "上游没有返回响应体".to_string()));
    };

    drive(response, &model, outbound.thinking, sink).await
}

/// 从错误体里抽一句人话。
fn extract_error(raw: &str) -> Option<String> {
    let value: Value = serde_json::from_str(raw.trim()).ok()?;
    let message = value
        .pointer("/error/message")
        .and_then(Value::as_str)
        .or_else(|| value.get("message").and_then(Value::as_str))?;
    let trimmed = message.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

/// 逐帧读上游、逐帧翻、逐帧推。
async fn drive(
    response: reqwest::Response,
    model: &str,
    thinking: bool,
    sink: &mut ConversationSink<'_>,
) -> Result<(), (u16, String)> {
    let id = format!("chatcmpl-{}", ids::new_message_id());
    let created = chrono::Utc::now().timestamp();
    let mut translator = Translator::new();
    let mut lines = crate::sse::LineBuffer::new();
    let mut stream = Box::pin(response.bytes_stream());
    let mut started = false;
    let mut pending: VecDeque<String> = VecDeque::new();
    let mut ended = false;

    if thinking {
        logging::verbose(PROVIDER_ID, "本次请求已开启思考（thought parts 会进 reasoning_content）");
    }

    loop {
        let data = match pending.pop_front() {
            Some(data) => Some(data),
            None => {
                if ended {
                    None
                } else {
                    read_next(&mut stream, &mut lines, &mut pending, &mut ended)
                        .await
                        .map_err(|message| (502, message))?
                }
            }
        };

        let Some(data) = data else {
            break;
        };

        let Some(frame) = stream::parse_frame(&data) else {
            continue;
        };

        // 上游用 200 回错误帧，得在这里转成失败。
        if let Some(message) = frame.error.as_ref() {
            if !started {
                return Err((classify_message(message), message.clone()));
            }
            sink.send(&sse::error_bytes(message))
                .await
                .map_err(|error| (502, error))?;
            sink.send(&sse::done_bytes())
                .await
                .map_err(|error| (502, error))?;
            return Ok(());
        }

        // 提示词被安全策略拦下：只有 promptFeedback，没有 candidates。
        if let Some(reason) = frame.blocked.as_ref() {
            let message = format!("请求被 Gemini 的安全策略拦截（{reason}）");
            if !started {
                return Err((400, message));
            }
            sink.send(&sse::error_bytes(&message))
                .await
                .map_err(|error| (502, error))?;
            sink.send(&sse::done_bytes())
                .await
                .map_err(|error| (502, error))?;
            return Ok(());
        }

        let deltas = translator.consume(&frame);
        if deltas.is_empty() {
            continue;
        }

        // 第一段内容出现时才回 head：让上游的错误有机会先变成状态码。
        if !started {
            head(sink, 200).await.map_err(|error| (502, error))?;
            sink.send(&delta_frame(
                &id,
                model,
                created,
                json!({ "role": "assistant", "content": "" }),
                None,
            ))
            .await
            .map_err(|error| (502, error))?;
            started = true;
        }

        for delta in deltas {
            let payload = match delta {
                Delta::Content(text) => {
                    json!({ "content": text })
                }
                Delta::Reasoning(text) => {
                    json!({ "reasoning_content": text })
                }
                Delta::ToolCall {
                    index,
                    id: call_id,
                    name,
                    arguments,
                } => json!({
                    "tool_calls": [{
                        "index": index,
                        "id": call_id,
                        "type": "function",
                        "function": { "name": name, "arguments": arguments },
                    }]
                }),
            };
            sink.send(&delta_frame(&id, model, created, payload, None))
                .await
                .map_err(|error| (502, error))?;
        }
    }

    // 一个字都没吐（例如上游只给了 finishReason 或空 candidates）。
    if !started {
        head(sink, 200).await.map_err(|error| (502, error))?;
        sink.send(&delta_frame(
            &id,
            model,
            created,
            json!({ "role": "assistant", "content": "" }),
            None,
        ))
        .await
        .map_err(|error| (502, error))?;
    }

    let finish = translator.final_finish_reason();
    sink.send(&delta_frame(&id, model, created, json!({}), Some(&finish)))
        .await
        .map_err(|error| (502, error))?;

    if let Some(usage) = translator.usage.as_ref() {
        sink.send(&usage_frame(&id, model, created, usage))
            .await
            .map_err(|error| (502, error))?;
    }

    sink.send(&sse::done_bytes())
        .await
        .map_err(|error| (502, error))?;
    Ok(())
}

/// 从流里读下一段 `data:` 内容。
///
/// 返回 `Ok(None)` = 流结束。整段读取器只保留半行（`LineBuffer` 自己处理），
/// 不缓存完整响应体。
async fn read_next<S>(
    stream: &mut std::pin::Pin<Box<S>>,
    lines: &mut crate::sse::LineBuffer,
    pending: &mut VecDeque<String>,
    ended: &mut bool,
) -> Result<Option<String>, String>
where
    S: Stream<Item = Result<Bytes, reqwest::Error>> + ?Sized,
{
    loop {
        if let Some(data) = pending.pop_front() {
            return Ok(Some(data));
        }
        if *ended {
            return Ok(None);
        }
        match stream.next().await {
            Some(Ok(chunk)) => {
                for line in lines.push(&chunk) {
                    if let Some(data) = stream::data_of(&line) {
                        if data.trim() == "[DONE]" {
                            *ended = true;
                        } else {
                            pending.push_back(data);
                        }
                    }
                }
            }
            Some(Err(error)) => {
                return Err(format!("读取 Gemini 的响应失败：{}", http::describe(&error)));
            }
            None => {
                *ended = true;
                if let Some(line) = lines.finish() {
                    if let Some(data) = stream::data_of(&line) {
                        if data.trim() != "[DONE]" {
                            pending.push_back(data);
                        }
                    }
                }
            }
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn urls_carry_the_model_and_sse_flag() {
        assert_eq!(
            upstream_url("gemini-2.5-flash"),
            "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:streamGenerateContent?alt=sse"
        );
    }

    #[test]
    fn error_bodies_look_like_openai() {
        let body = error_body(429, "quota");
        assert_eq!(
            body.pointer("/error/type").and_then(Value::as_str),
            Some("rate_limit_error")
        );
    }

    #[test]
    fn quota_messages_map_to_429() {
        assert_eq!(classify_message("Resource has been exhausted (quota)"), 429);
        assert_eq!(classify_message("API key not valid"), 401);
        assert_eq!(classify_message("weird failure"), 502);
    }

    #[test]
    fn extracts_the_upstream_message() {
        let raw = r#"{"error":{"code":400,"message":"API key not valid. Please pass a valid API key.","status":"INVALID_ARGUMENT"}}"#;
        assert_eq!(
            extract_error(raw).as_deref(),
            Some("API key not valid. Please pass a valid API key.")
        );
    }
}
