//! Codex 的会话式转发：chat 请求 → `backend-api/codex/responses` → chat SSE。
//!
//! ── 为什么走 `conversation` ────────────────────────────────
//! 上游说 OpenAI Responses（SSE 事件流），网关的 `UpstreamKind` 只有 Chat /
//! Anthropic / Ndjson / Gemini / 混合快照。插件自己读事件、翻成 chat 帧，就
//! 不用扩协议；账号轮换、冷却、统计仍归网关。
//!
//! ── 非流式请求也按流式发 ────────────────────────────────────
//! 与 AStudio 同一处置：上游只有流式形态，插件统一推 SSE 帧，非流式请求由
//! 网关侧聚合。
//!
//! ── 与 AStudio 的差别 ──────────────────────────────────────
//! 三处：① 要带 `chatgpt-account-id`（多账号同浏览器时上游靠它区分额度池）；
//! ② UA 必须是 Codex 客户端形态（`codex_cli_rs/<ver>`），否则上游按普通
//! ChatGPT 网页流量处理；③ 出网走账号代理，插件自己的控制面请求不走这条。

use std::collections::BTreeMap;

use bytes::Bytes;
use futures::{stream::BoxStream, StreamExt};
use serde_json::{json, Value};

use agent2api_provider_protocol as proto;
use agent2api_provider_sdk::{ConversationSink, PluginCtx};

use super::credentials::CodexCredentials;
use super::oauth;
use super::{accounts, endpoints, models};
use crate::openai_responses::responses;
use crate::sse::{LineBuffer, SseLine};
use crate::{http, ids, logging};

fn sse(payload: &Value) -> Vec<u8> {
    format!("data: {payload}\n\n").into_bytes()
}

fn chunk(model: &str, id: &str, delta: Value, finish: Option<&str>) -> Vec<u8> {
    sse(&json!({
        "id": id,
        "object": "chat.completion.chunk",
        "created": chrono::Utc::now().timestamp(),
        "model": model,
        "choices": [{ "index": 0, "delta": delta, "finish_reason": finish }],
    }))
}

fn usage_chunk(
    model: &str,
    id: &str,
    reason: &str,
    input: i64,
    output: i64,
    cached: i64,
) -> Vec<u8> {
    sse(&json!({
        "id": id,
        "object": "chat.completion.chunk",
        "created": chrono::Utc::now().timestamp(),
        "model": model,
        "choices": [{ "index": 0, "delta": {}, "finish_reason": reason }],
        "usage": {
            "prompt_tokens": input.max(0),
            "completion_tokens": output.max(0),
            "total_tokens": (input + output).max(0),
            "prompt_tokens_details": { "cached_tokens": cached.max(0) },
        },
    }))
}

async fn head(sink: &mut ConversationSink<'_>, status: u16) -> Result<(), String> {
    sink.head(proto::StreamHead {
        status,
        headers: BTreeMap::from([(
            "content-type".to_string(),
            if status == 200 {
                "text/event-stream"
            } else {
                "application/json"
            }
            .to_string(),
        )]),
        upstream: proto::UpstreamKind::Chat,
    })
    .await
}

fn error_body(status: u16, message: &str) -> Value {
    json!({
        "error": {
            "type": if status == 429 { "rate_limit_error" } else { "api_error" },
            "message": message,
        }
    })
}

/// Responses 的 SSE 事件读取器。
struct EventStream {
    stream: BoxStream<'static, Result<Bytes, reqwest::Error>>,
    lines: LineBuffer,
    pending: std::collections::VecDeque<Value>,
    ended: bool,
}

impl EventStream {
    fn new(response: reqwest::Response) -> Self {
        Self {
            stream: Box::pin(response.bytes_stream()),
            lines: LineBuffer::new(),
            pending: std::collections::VecDeque::new(),
            ended: false,
        }
    }

    async fn next(&mut self) -> Result<Option<Value>, String> {
        loop {
            if let Some(value) = self.pending.pop_front() {
                return Ok(Some(value));
            }
            if self.ended {
                return Ok(None);
            }
            match self.stream.next().await {
                Some(Ok(bytes)) => {
                    for line in self.lines.push(&bytes) {
                        self.handle(&line);
                    }
                }
                Some(Err(error)) => {
                    return Err(format!("读取 Codex 的响应失败：{}", http::describe(&error)));
                }
                None => {
                    self.ended = true;
                    if let Some(line) = self.lines.finish() {
                        self.handle(&line);
                    }
                }
            }
        }
    }

    fn handle(&mut self, line: &str) {
        let parsed = SseLine::parse(line);
        let Some(payload) = parsed.data() else {
            return;
        };
        if payload == "[DONE]" {
            self.ended = true;
            return;
        }
        if let Ok(value) = serde_json::from_str::<Value>(payload) {
            self.pending.push_back(value);
        }
    }
}

/// 一次完整转发。
pub async fn run(
    ctx: &PluginCtx,
    request: proto::ConversationRequest,
    mut sink: ConversationSink<'_>,
) -> Result<(), String> {
    match forward(ctx, &request, &mut sink).await {
        Ok(()) => Ok(()),
        Err((status, message)) => {
            logging::verbose("codex", &format!("转发失败（{status}）：{message}"));
            head(&mut sink, status).await?;
            let body = error_body(status, &message).to_string();
            sink.send(body.as_bytes()).await
        }
    }
}

async fn forward(
    ctx: &PluginCtx,
    request: &proto::ConversationRequest,
    sink: &mut ConversationSink<'_>,
) -> Result<(), (u16, String)> {
    let (credentials, channel) = load_credentials(ctx, &request.account).await?;
    let model = resolve_model(&request.body, &request.wire_model)?;
    let mut payload = responses::build_request(&request.body, &model, true);
    // Codex 的 stream 只能是 true：上游不认 false。
    if let Some(object) = payload.as_object_mut() {
        object.insert("stream".to_string(), Value::Bool(true));
    }
    if channel.is_siwc() {
        super::siwc::shape_body(&mut payload);
    }
    let response = post_responses(
        &credentials,
        &channel,
        &payload,
        &model,
        request.proxy.as_ref(),
        &ctx.env.proxy,
    )
    .await?;
    let mut stream = EventStream::new(response);
    let id = format!("chatcmpl-{}", ids::new_message_id());
    let mut tool_index: i64 = -1;
    let mut tool_args_sent = false;
    let mut text_sent = false;
    let mut started = false;
    let mut usage = (0i64, 0i64, 0i64);
    loop {
        let event = match stream.next().await {
            Ok(Some(event)) => event,
            Ok(None) => {
                if !started {
                    return Err((502, "Codex 在开始回答前就结束了响应".to_string()));
                }
                sink.send(&usage_chunk(&model, &id, "stop", usage.0, usage.1, usage.2))
                    .await
                    .map_err(|message| (502, message))?;
                sink.send(b"data: [DONE]\n\n")
                    .await
                    .map_err(|message| (502, message))?;
                return Ok(());
            }
            Err(message) => return Err((502, message)),
        };
        let kind = event.get("type").and_then(Value::as_str).unwrap_or("");
        if kind == "response.created" || kind == "response.in_progress" {
            continue;
        }
        if kind == "error" || kind == "response.failed" {
            let message = event
                .pointer("/response/error/message")
                .and_then(Value::as_str)
                .or_else(|| event.get("message").and_then(Value::as_str))
                .or_else(|| event.pointer("/error/message").and_then(Value::as_str))
                .unwrap_or("Codex 返回了一个错误")
                .to_string();
            let status = classify_message(&message);
            if !started {
                return Err((status, message));
            }
            sink.send(&sse(&error_body(status, &message)))
                .await
                .map_err(|error| (502, error))?;
            sink.send(b"data: [DONE]\n\n")
                .await
                .map_err(|error| (502, error))?;
            return Ok(());
        }
        if kind == "response.completed" || kind == "response.done" || kind == "response.incomplete"
        {
            let (input, output, cached) = responses::usage_of(&event);
            usage = (input, output, cached);
            let reason = if kind == "response.incomplete" {
                "length"
            } else {
                "stop"
            };
            if !started {
                head(sink, 200).await.map_err(|message| (502, message))?;
                sink.send(&chunk(
                    &model,
                    &id,
                    json!({ "role": "assistant", "content": "" }),
                    None,
                ))
                .await
                .map_err(|message| (502, message))?;
            }
            sink.send(&usage_chunk(&model, &id, reason, usage.0, usage.1, usage.2))
                .await
                .map_err(|message| (502, message))?;
            sink.send(b"data: [DONE]\n\n")
                .await
                .map_err(|message| (502, message))?;
            return Ok(());
        }
        if !started {
            head(sink, 200).await.map_err(|message| (502, message))?;
            sink.send(&chunk(
                &model,
                &id,
                json!({ "role": "assistant", "content": "" }),
                None,
            ))
            .await
            .map_err(|message| (502, message))?;
            started = true;
        }
        match kind {
            "response.output_item.added" => {
                let item = event.get("item").cloned().unwrap_or(Value::Null);
                if item.get("type").and_then(Value::as_str) == Some("function_call") {
                    let call_id = item
                        .get("call_id")
                        .and_then(Value::as_str)
                        .or_else(|| item.get("id").and_then(Value::as_str))
                        .unwrap_or("")
                        .to_string();
                    let name = item
                        .get("name")
                        .and_then(Value::as_str)
                        .unwrap_or("")
                        .to_string();
                    tool_index += 1;
                    tool_args_sent = false;
                    sink.send(&chunk(
                        &model,
                        &id,
                        json!({
                            "tool_calls": [{
                                "index": tool_index,
                                "id": call_id,
                                "type": "function",
                                "function": { "name": name, "arguments": "" },
                            }]
                        }),
                        None,
                    ))
                    .await
                    .map_err(|message| (502, message))?;
                }
            }
            "response.output_text.delta" | "response.text.delta" => {
                if let Some(text) = event.get("delta").and_then(Value::as_str) {
                    if !text.is_empty() {
                        text_sent = true;
                        sink.send(&chunk(&model, &id, json!({ "content": text }), None))
                            .await
                            .map_err(|message| (502, message))?;
                    }
                }
            }
            "response.output_text.done" | "response.text.done" => {
                // 只有没收到增量时才用整段（避免重复）。
                if !text_sent {
                    if let Some(text) = event.get("text").and_then(Value::as_str) {
                        if !text.is_empty() {
                            text_sent = true;
                            sink.send(&chunk(&model, &id, json!({ "content": text }), None))
                                .await
                                .map_err(|message| (502, message))?;
                        }
                    }
                }
            }
            "response.reasoning_summary_text.delta"
            | "response.reasoning_text.delta"
            | "response.reasoning.delta" => {
                if let Some(text) = event.get("delta").and_then(Value::as_str) {
                    if !text.is_empty() {
                        sink.send(&chunk(
                            &model,
                            &id,
                            json!({ "reasoning_content": text }),
                            None,
                        ))
                        .await
                        .map_err(|message| (502, message))?;
                    }
                }
            }
            "response.function_call_arguments.delta" => {
                if let Some(args) = event.get("delta").and_then(Value::as_str) {
                    if !args.is_empty() && tool_index >= 0 {
                        tool_args_sent = true;
                        sink.send(&chunk(
                            &model,
                            &id,
                            json!({
                                "tool_calls": [{
                                    "index": tool_index,
                                    "function": { "arguments": args },
                                }]
                            }),
                            None,
                        ))
                        .await
                        .map_err(|message| (502, message))?;
                    }
                }
            }
            "response.function_call_arguments.done" => {
                // 有些实现只在 done 里给完整参数；增量没来过时补一次。
                if let Some(args) = event
                    .get("arguments")
                    .and_then(Value::as_str)
                    .filter(|args| !tool_args_sent && tool_index >= 0 && !args.is_empty())
                {
                    tool_args_sent = true;
                    sink.send(&chunk(
                        &model,
                        &id,
                        json!({
                            "tool_calls": [{
                                "index": tool_index,
                                "function": { "arguments": args },
                            }]
                        }),
                        None,
                    ))
                    .await
                    .map_err(|message| (502, message))?;
                }
            }
            _ => {}
        }
    }
}

/// 一条账号走的是哪条通道。
///
/// 参考实现按 `use_siwc` 决定头集合与请求体清洗规则
/// （`codex_executor_request.go:509-583` 与 `:415-427`），两条通道的语义不同：
/// 普通 OAuth 走 ChatGPT 后端的完整指纹，SIWC 走「直接令牌」的窄集合。
struct Channel {
    /// SIWC 通道的令牌与签发的 client_id（普通 OAuth 为 None）。
    siwc: Option<Value>,
}

impl Channel {
    fn of(secret: &Value) -> Self {
        let siwc = if super::siwc::bound(secret) {
            secret.get("siwc").cloned()
        } else {
            None
        };
        Self { siwc }
    }

    fn is_siwc(&self) -> bool {
        self.siwc.is_some()
    }
}

/// 取凭证（必要时刷新）。
async fn load_credentials(
    ctx: &PluginCtx,
    account: &str,
) -> Result<(CodexCredentials, Channel), (u16, String)> {
    match oauth::ensure_fresh(ctx, account, false).await {
        Ok(credentials) => {
            if credentials.access_token.trim().is_empty() {
                return Err((
                    401,
                    "Codex 账号缺少 access token，无法转发（请重新登录，或等令牌自动刷新后再试）"
                        .to_string(),
                ));
            }
            let record = oauth::read_record(ctx, account)
                .await
                .map_err(|error| (502, error.message))?;
            let channel = Channel::of(&crate::store::secret_view(&record));
            Ok((credentials, channel))
        }
        Err(error) if error.status_code == 401 => Err((401, error.message)),
        Err(error) => {
            // 刷新失败但手上还有未过期的 access token 时照用（与 Antigravity 家一致）。
            let record = oauth::read_record(ctx, account)
                .await
                .map_err(|error| (502, error.message))?;
            let fallback = super::credentials::from_record(Some(&record))
                .map_err(|error| (502, error.message))?;
            if fallback.has_access_token() && !fallback.expiring() {
                let channel = Channel::of(&crate::store::secret_view(&record));
                return Ok((fallback, channel));
            }
            Err((error.status_code.max(400) as u16, error.message))
        }
    }
}

fn resolve_model(body: &Value, wire_model: &str) -> Result<String, (u16, String)> {
    let requested = if wire_model.trim().is_empty() {
        body.get("model").and_then(Value::as_str).unwrap_or("")
    } else {
        wire_model
    }
    .trim();
    if requested.is_empty() {
        return Err((
            400,
            "Codex 请求缺少模型名（请在客户端指定 gpt-* 模型）".to_string(),
        ));
    }
    if !models::is_known_model(requested) {
        return Err((
            400,
            format!("Codex 不认模型「{requested}」（本家只接 gpt-* / o1 / o3 开头的模型名）"),
        ));
    }
    Ok(requested.to_string())
}

/// 发一次 Responses 请求。
///
/// `model` 只用于普通 OAuth 通道的 `X-Codex-Routing-Hint`
/// （参考实现 `applyCodexRoutingHint`），上游真正的模型名在请求体里。
async fn post_responses(
    credentials: &CodexCredentials,
    channel: &Channel,
    body: &Value,
    model: &str,
    proxy: Option<&proto::WireProxy>,
    gateway_proxy: &str,
) -> Result<reqwest::Response, (u16, String)> {
    let client = http::stream_client(proxy, gateway_proxy);
    let session_id = ids::new_conversation_id();
    let headers = if channel.is_siwc() {
        endpoints::siwc_responses_headers(&credentials.access_token, &session_id)
    } else {
        let tier = body
            .get("service_tier")
            .and_then(Value::as_str)
            .unwrap_or_default();
        endpoints::responses_headers(
            &credentials.access_token,
            &credentials.account_id,
            &session_id,
            model,
            tier,
        )
    };
    let mut request = client.post(endpoints::RESPONSES_URL);
    for (key, value) in headers {
        request = request.header(&key, value);
    }
    let response = request
        .body(body.to_string())
        .send()
        .await
        .map_err(|error| (502, format!("连接 Codex 失败：{}", http::describe_chain(&error))))?;
    let status = response.status().as_u16();
    if (200..300).contains(&status) {
        return Ok(response);
    }
    let text = response.text().await.unwrap_or_default();
    let payload: Value = serde_json::from_str(&text).unwrap_or(Value::Null);
    let message = endpoints::upstream_message(&payload);
    let message = if message.is_empty() {
        format!("Codex 返回 HTTP {status}")
    } else {
        message
    };
    let mapped = match status {
        401 | 403 => 401,
        429 => 429,
        other => other,
    };
    Err((mapped, message))
}

/// 错误文案 → HTTP 状态（尽力而为）。
fn classify_message(message: &str) -> u16 {
    let lower = message.to_ascii_lowercase();
    if lower.contains("rate limit")
        || lower.contains("too many requests")
        || lower.contains("quota")
        || lower.contains("balance")
        || lower.contains("credit")
        || lower.contains("usage limit")
        || lower.contains("积分")
        || lower.contains("额度")
    {
        return 429;
    }
    if lower.contains("unauthorized")
        || lower.contains("authentication")
        || lower.contains("invalid token")
    {
        return 401;
    }
    if lower.contains("context")
        || lower.contains("too long")
        || lower.contains("maximum length")
        || lower.contains("too large")
    {
        return 400;
    }
    502
}

/// 账号视图（面板展示用；`accounts` 的包装）。
#[allow(dead_code)]
pub(super) fn view_of(secret: &Value) -> Value {
    accounts::account_view(secret)
}

#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_missing_model_is_rejected() {
        let error = resolve_model(&json!({}), "").unwrap_err();
        assert_eq!(error.0, 400);
    }

    #[test]
    fn a_foreign_model_is_rejected() {
        let error = resolve_model(&json!({ "model": "claude-sonnet-4-6" }), "").unwrap_err();
        assert_eq!(error.0, 400);
        assert!(error.1.contains("Codex 不认模型"));
    }

    #[test]
    fn the_wire_model_wins() {
        let model = resolve_model(&json!({ "model": "gpt-5.2" }), "gpt-5.6-sol").unwrap();
        assert_eq!(model, "gpt-5.6-sol");
    }

    #[test]
    fn quota_messages_map_to_429() {
        assert_eq!(classify_message("You have hit your usage limit"), 429);
        assert_eq!(classify_message("rate limit reached"), 429);
    }

    #[test]
    fn context_messages_map_to_400() {
        assert_eq!(classify_message("context length exceeded"), 400);
    }

    #[test]
    fn anything_else_is_502() {
        assert_eq!(classify_message("something odd"), 502);
    }
}
