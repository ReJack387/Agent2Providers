//! Claude 的聊天转发：chat 请求 → Anthropic `/v1/messages` 请求。
//!
//! ── 为什么报 `UpstreamKind::Anthropic` 而不是自己翻 SSE ──────
//! 上游说的是 Anthropic Messages 协议（`message_start` / `content_block_delta`
//! / `message_stop` 那一套）。网关已经有 `AnthropicToChatStream` 翻译层（ZCode
//! 的套餐池通道就走它），插件只要把**请求**翻对、把 `upstream` 标成
//! `Anthropic`，响应翻译与聚合全在网关侧 —— 这与 Antigravity 报 `Gemini`、
//! Command Code 报 `Ndjson` 是同一个取舍。自己再写一份 SSE 翻译只会让「流式
//! 与非流式」「工具调用增量」「usage 累计」这些细节出现第二套实现。
//!
//! ── 请求转换从哪来 ─────────────────────────────────────────
//! `crate::anthropic::anthropic_outbound::anthropic_request_from_chat` 是仓内
//! 已经调好的 chat → Messages 转换（system 提到顶层、tool 消息变
//! `tool_result` 块、`tool_calls` 变 `tool_use` 块、连续同角色合并、
//! `thinking.budget_tokens` 与 `max_tokens` 的硬约束都在里面）。
//!
//! ── 本家自己的四处补充 ─────────────────────────────────────
//! 1. `max_tokens` 按模型上限夹一次（共享转换给的缺省值是 8192，Claude 的
//!    Sonnet 能到 64000，白放着可惜；同时防止客户端给超上限的值被上游 400）。
//! 2. `stream` 强制与网关的请求一致（共享转换读 body 里的 `stream`，但网关
//!    的 `ChatRequest.stream` 才是权威 —— 两者不一致时会拿到一个非流式响应
//!    去喂流式解析）。
//! 3. 模型名不做改写（Claude 的 id 就是上游 id，没有别名体系）。
//! 4. **身份四元组**：`metadata.user_id` 必须是
//!    `{"device_id":<64 hex>,"account_uuid":<uuid>,"session_id":<uuid>}` 的
//!    **JSON 字符串**，且 `session_id` 必须与 `X-Claude-Code-Session-Id` 头逐字
//!    相等（参考实现 `helps/claude_credential_identity.go:926-973` 的
//!    `rebuildClaudeMetadataUserID` 与 `claude_client_detection.go:341` 的
//!    一致性断言）。两者不一致时上游按「非原生客户端」处理，订阅通道的额度
//!    判定与提示缓存都会退化。见 [`stamp_identity`]。
//!
//! ── 硬约束 ──────────────────────────────────────────────────
//! release 是 `panic=abort`：本文件零 unwrap / expect / panic。

use serde_json::Value;

use agent2api_provider_protocol as proto;
use agent2api_provider_sdk::{ChatPlan, PluginCtx};

use crate::errors::GatewayError;
use crate::ids;

use super::credentials::ClaudeCredentials;
use super::{endpoints, models, oauth};

/// 组装一次聊天请求。
pub(super) async fn build(
    ctx: &PluginCtx,
    account: &str,
    body: &Value,
    wire_model: &str,
    stream: bool,
) -> Result<ChatPlan, GatewayError> {
    let model = resolve_model(body, wire_model);
    if model.is_empty() {
        return Err(GatewayError::with_status(
            400,
            "Claude 请求缺少模型名（请在客户端指定 claude-* 模型）",
        ));
    }
    // 前缀闸门：把非 claude-* 的模型名挡在插件里，而不是让它打到上游换一个
    // 「model not found」—— 那种错误混在转发链路里，用户很难看出是自己选错了家。
    if !models::is_known_model(&model) {
        return Err(GatewayError::with_status(
            400,
            format!("Claude 不认模型「{model}」（本家只接 claude-* 开头的模型名）"),
        ));
    }
    // 凭证：先走 ensure_fresh（临期主动刷 + 单飞 + 比较再写）。
    let credentials = match oauth::ensure_fresh(ctx, account, false).await {
        Ok(credentials) => credentials,
        Err(error) if error.status_code == 401 => return Err(error),
        Err(error) => {
            // 刷新链路本身出问题（网络/代理）时，如果记录里还有未过期的
            // access token，就用它跑这一轮 —— 比直接失败对用户更友好。
            let record = oauth::read_record(ctx, account).await?;
            let fallback = super::credentials::from_record(Some(&record))?;
            if fallback.has_access_token() && !fallback.expiring() {
                fallback
            } else {
                return Err(error);
            }
        }
    };
    let access_token = credentials.access_token.trim().to_string();
    if access_token.is_empty() {
        return Err(GatewayError::with_status(
            401,
            "Claude 账号缺少 access token，无法转发（请重新登录，或等令牌自动刷新后再试）",
        ));
    }
    let mut payload = crate::anthropic::anthropic_outbound::anthropic_request_from_chat(body, &model)
        .map_err(|message| GatewayError::with_status(400, format!("请求体转换失败：{message}")))?;
    clamp_max_tokens(&mut payload, &model);
    force_stream(&mut payload, stream);
    let session_id = stamp_identity(&mut payload, &credentials);
    // 出网由网关按 `ChatPlan` 发起，插件这一层不建 client；刷新链路的代理
    // 已在 `ensure_fresh` 内部按账号配置解析过，转发由网关带同一份配置。
    let headers = endpoints::messages_headers(&access_token, &session_id);
    Ok(ChatPlan {
        url: endpoints::MESSAGES_URL.to_string(),
        headers,
        body: payload,
        upstream: proto::UpstreamKind::Anthropic,
    })
}

/// 写入 `metadata.user_id` 身份四元组，并返回本轮会话 id。
///
/// ── 为什么必须写 ────────────────────────────────────────────
/// 参考实现把 `metadata.user_id` 当作**客户端身份声明**：它是一个 JSON 字符串
/// （不是对象），键顺序固定为 `device_id` → `account_uuid` → `session_id`，其
/// 余键原样追加在后（`helps/claude_credential_identity.go:958-971`）。上游拿它
/// 与 `X-Claude-Code-Session-Id` 头交叉校验（`claude_client_detection.go:341`），
/// 两者不一致就按非原生客户端降级。
///
/// ── 三个字段的来源 ──────────────────────────────────────────
///   - `device_id`：64 位小写 hex。参考实现按账号池持久化
///     （`claude_device_ids` 元数据，池大小 1），这里按账号邮箱/refresh token
///     派生，保证同一账号每次都是同一个值 —— 每次随机会让上游看成新设备。
///   - `account_uuid`：账号的 `accountUuid`，没有就留空串（参考实现也允许空）。
///   - `session_id`：每轮新生成（参考实现 `CachedSessionIDRequired` 也是按请求
///     取，只是缓存到会话结束）。同时写进 `X-Claude-Code-Session-Id` 头。
///
/// 返回值是写进 body 的那个 `session_id`，供 [`endpoints::messages_headers`]
/// 复用 —— 两处必须是同一个字符串。
fn stamp_identity(payload: &mut Value, credentials: &ClaudeCredentials) -> String {
    let device_id = device_id_of(credentials);
    let account_uuid = credentials.account_uuid.trim().to_string();
    let session_id = ids::uuid_v4();
    let Some(object) = payload.as_object_mut() else {
        return session_id;
    };
    let metadata = object
        .entry("metadata".to_string())
        .or_insert_with(|| Value::Object(serde_json::Map::new()));
    if !metadata.is_object() {
        *metadata = Value::Object(serde_json::Map::new());
    }
    if let Some(metadata) = metadata.as_object_mut() {
        // 参考实现会保留下游带的额外键并追加在后；这里同样保留，只覆盖三个
        // 由本插件负责的键。已有 `user_id` 若不是对象形态（老客户端会发
        // `<device>_session_<uuid>` 这种串），直接整体替换 —— 那种形态没有可
        // 复用的键。
        let extras = metadata
            .get("user_id")
            .and_then(Value::as_str)
            .and_then(|raw| serde_json::from_str::<Value>(raw).ok())
            .and_then(|parsed| parsed.as_object().cloned())
            .unwrap_or_default();
        // 键顺序必须与参考实现逐字一致（`helps/claude_credential_identity.go:958-971`）：
        // `device_id` → `account_uuid` → `session_id` → 其余键原序。serde_json
        // 的 Map 默认是 BTreeMap（字母序），所以这里手工拼，不能靠 json! 宏。
        let mut identity = String::from("{\"device_id\":");
        identity.push_str(&quote(&device_id));
        identity.push_str(",\"account_uuid\":");
        identity.push_str(&quote(&account_uuid));
        identity.push_str(",\"session_id\":");
        identity.push_str(&quote(&session_id));
        for (key, value) in extras {
            if matches!(key.as_str(), "device_id" | "account_uuid" | "session_id") {
                continue;
            }
            identity.push(',');
            identity.push_str(&quote(&key));
            identity.push(':');
            identity.push_str(&value.to_string());
        }
        identity.push('}');
        metadata.insert("user_id".to_string(), Value::String(identity));
    }
    session_id
}

/// 把字符串编码成 JSON 字面量（带引号与转义）。
fn quote(raw: &str) -> String {
    Value::String(raw.to_string()).to_string()
}

/// 派生出稳定的 64 位小写 hex 设备 id。
///
/// 参考实现每个账号生成一次 32 字节随机数并持久化（`identity.go` 的
/// `generateDeviceID`）；插件侧不落盘这类辅助字段，改用账号身份做哈希 ——
/// 效果相同（同一账号恒定），且换机/重装后仍是同一个设备。
fn device_id_of(credentials: &ClaudeCredentials) -> String {
    let seed = if !credentials.email.trim().is_empty() {
        format!("claude-device:{}", credentials.email.trim().to_ascii_lowercase())
    } else if !credentials.account_uuid.trim().is_empty() {
        format!("claude-device:{}", credentials.account_uuid.trim())
    } else {
        format!("claude-device:{}", credentials.refresh_token.trim())
    };
    // flight::fingerprint 给的是 SHA-256 前 16 字节的 32 位 hex；再拼一遍自己
    // 得到 64 位，满足上游对 device_id 的长度要求（32 字节 hex）。
    format!("{}{}", crate::flight::fingerprint(&seed), crate::flight::fingerprint(&format!("{seed}:2")))
}


/// 决定这次用哪个模型名。
///
/// `wire_model`（网关解析后的模型名）优先；空则回落到 body 里的 `model`。
fn resolve_model(body: &Value, wire_model: &str) -> String {
    let wire = wire_model.trim();
    if !wire.is_empty() {
        return wire.to_string();
    }
    body.get("model")
        .and_then(Value::as_str)
        .map(str::trim)
        .unwrap_or_default()
        .to_string()
}

/// 把 `max_tokens` 夹到该模型的上限内。
///
/// ── 为什么必须夹 ────────────────────────────────────────────
/// 共享转换的缺省值是 8192（对 Claude 3.5 系列刚好是上限，但对 Sonnet 4.x 太
/// 保守）；而客户端可能给一个超过上限的值 —— 上游对超限的处理是 400，且错误
/// 文案里只说「max_tokens 太大」，用户很难联想到是模型上限。
fn clamp_max_tokens(payload: &mut Value, model: &str) {
    let Some(object) = payload.as_object_mut() else {
        return;
    };
    let limit = model_output_limit(model);
    let current = object
        .get("max_tokens")
        .and_then(Value::as_i64)
        .unwrap_or_default();
    if current <= 0 {
        object.insert("max_tokens".to_string(), Value::from(limit));
        return;
    }
    if current > limit {
        object.insert("max_tokens".to_string(), Value::from(limit));
    }
}

/// 某模型的输出上限（认不出就按 8192 保守处理）。
fn model_output_limit(model: &str) -> i64 {
    let lowered = model.trim().to_ascii_lowercase();
    models::catalog()
        .iter()
        .find(|record| {
            record
                .get("id")
                .and_then(Value::as_str)
                .is_some_and(|id| id.eq_ignore_ascii_case(&lowered))
        })
        .and_then(|record| record.get("maxOutputTokens").and_then(Value::as_i64))
        .filter(|value| *value > 0)
        .unwrap_or(8_192)
}

/// 让请求体的 `stream` 与网关的判定一致。
fn force_stream(payload: &mut Value, stream: bool) {
    if let Some(object) = payload.as_object_mut() {
        object.insert("stream".to_string(), Value::Bool(stream));
    }
}

#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn wire_model_wins_over_the_body() {
        let body = json!({"model": "from-body"});
        assert_eq!(resolve_model(&body, "from-wire"), "from-wire");
        assert_eq!(resolve_model(&body, ""), "from-body");
        assert_eq!(resolve_model(&json!({}), ""), "");
    }

    #[test]
    fn an_overlarge_max_tokens_is_clamped_to_the_model_limit() {
        let mut payload = json!({"max_tokens": 999_999});
        clamp_max_tokens(&mut payload, "claude-3-5-sonnet");
        assert_eq!(payload["max_tokens"], 8_192);
    }

    #[test]
    fn a_missing_max_tokens_gets_the_model_limit() {
        let mut payload = json!({});
        clamp_max_tokens(&mut payload, "claude-sonnet-4-6");
        assert_eq!(payload["max_tokens"], 64_000);
    }

    #[test]
    fn a_reasonable_max_tokens_is_left_alone() {
        let mut payload = json!({"max_tokens": 4_096});
        clamp_max_tokens(&mut payload, "claude-sonnet-4-6");
        assert_eq!(payload["max_tokens"], 4_096);
    }

    #[test]
    fn an_unknown_model_falls_back_to_a_conservative_limit() {
        assert_eq!(model_output_limit("claude-future-9"), 8_192);
    }

    #[test]
    fn the_gateway_stream_flag_is_authoritative() {
        let mut payload = json!({"stream": false});
        force_stream(&mut payload, true);
        assert_eq!(payload["stream"], Value::Bool(true));
        force_stream(&mut payload, false);
        assert_eq!(payload["stream"], Value::Bool(false));
    }

    fn credentials_fixture() -> ClaudeCredentials {
        ClaudeCredentials {
            email: "Someone@Example.com".to_string(),
            account_uuid: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa".to_string(),
            refresh_token: "sk-ant-ort01-x".to_string(),
            ..Default::default()
        }
    }

    #[test]
    fn the_identity_block_is_a_json_string_with_three_leading_keys() {
        let mut payload = json!({"messages": []});
        let session = stamp_identity(&mut payload, &credentials_fixture());
        let raw = payload["metadata"]["user_id"]
            .as_str()
            .expect("metadata.user_id 必须是 JSON 字符串而不是对象");
        // 键顺序只能在原始串上验（反序列化进 serde_json 的 Map 会按字母序重排）。
        assert!(raw.starts_with("{\"device_id\":"), "raw = {raw}");
        let device_end = raw.find(",\"account_uuid\":").expect("缺 account_uuid");
        let account_end = raw.find(",\"session_id\":").expect("缺 session_id");
        assert!(device_end < account_end, "raw = {raw}");
        let parsed: Value = serde_json::from_str(raw).expect("必须是合法 JSON");
        let object = parsed.as_object().expect("必须是对象");
        assert_eq!(object.len(), 3);
        assert_eq!(object["session_id"], Value::String(session.clone()));
        assert_eq!(
            object["account_uuid"],
            Value::String("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa".to_string())
        );
    }

    #[test]
    fn the_device_id_is_sixty_four_lowercase_hex_characters() {
        let mut payload = json!({});
        stamp_identity(&mut payload, &credentials_fixture());
        let raw = payload["metadata"]["user_id"].as_str().unwrap_or_default();
        let parsed: Value = serde_json::from_str(raw).unwrap_or(Value::Null);
        let device = parsed["device_id"].as_str().unwrap_or_default();
        assert_eq!(device.len(), 64);
        assert!(device.chars().all(|ch| ch.is_ascii_hexdigit() && !ch.is_ascii_uppercase()));
    }

    #[test]
    fn the_same_account_keeps_the_same_device_id() {
        let mut first = json!({});
        let mut second = json!({});
        stamp_identity(&mut first, &credentials_fixture());
        stamp_identity(&mut second, &credentials_fixture());
        let device_of = |payload: &Value| {
            payload["metadata"]["user_id"]
                .as_str()
                .and_then(|raw| serde_json::from_str::<Value>(raw).ok())
                .and_then(|parsed| parsed["device_id"].as_str().map(str::to_string))
                .unwrap_or_default()
        };
        assert_eq!(device_of(&first), device_of(&second));
        // 但会话 id 每轮都不同。
        assert_ne!(
            first["metadata"]["user_id"].as_str(),
            second["metadata"]["user_id"].as_str()
        );
    }

    #[test]
    fn extra_keys_on_the_incoming_user_id_survive() {
        let incoming = json!({"parent_session_id": "keep-me"});
        let mut payload = json!({
            "metadata": {"user_id": incoming.to_string()}
        });
        stamp_identity(&mut payload, &credentials_fixture());
        let raw = payload["metadata"]["user_id"].as_str().unwrap_or_default();
        assert!(raw.contains("\"parent_session_id\":\"keep-me\""));
    }

    #[test]
    fn a_legacy_flat_user_id_is_replaced_wholesale() {
        let mut payload = json!({
            "metadata": {"user_id": "devicehex_session_11111111-2222-4333-8444-555555555555"}
        });
        stamp_identity(&mut payload, &credentials_fixture());
        let raw = payload["metadata"]["user_id"].as_str().unwrap_or_default();
        assert!(raw.starts_with("{\"device_id\":"));
        assert!(!raw.contains("_session_"));
    }

    #[test]
    fn a_missing_metadata_object_is_created() {
        let mut payload = json!({});
        stamp_identity(&mut payload, &credentials_fixture());
        assert!(payload["metadata"]["user_id"].is_string());
    }
}
