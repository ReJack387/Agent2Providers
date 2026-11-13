//! Codex（ChatGPT 订阅）提供商。
//!
//! ── 上游三套平面 ────────────────────────────────────────────
//! ```text
//! 登录（OAuth）      数据面（转发）                  目录（静态）
//! auth.openai.com → chatgpt.com/backend-api/codex → models.rs 的静态池
//!   authorize          responses  (SSE 事件流)
//!   token              ↑ chat.rs 读事件、翻成 chat 帧
//!   设备码 usercode/token
//! ```
//!
//! ── 三处取舍 ────────────────────────────────────────────────
//! ① **报 `conversation` 而不是 `build_chat`**：上游是 Responses 的 SSE 事件
//!    流，网关的 `UpstreamKind` 里没有 Responses 这一档（只有 Chat / Anthropic
//!    / Ndjson / Gemini / 混合快照），所以插件自己读事件、翻成 chat 帧。
//!    这与 AStudio 同一处置。
//! ② **目录是静态的、按套餐分档**：上游没有「列出我的可用模型」端点，参考
//!    实现同样按 `plan_type` 分档给静态清单（`GetCodexProModels` 等，且
//!    default 走 Pro）。所以 `model_refresh` 能力位报 false。
//! ③ **回调端口先试 1455 再退让**：参考实现固定 1455、占用即报 `ErrPortInUse`；
//!    插件里那会让装了 Codex CLI 的用户完全无法登录，而 `redirect_uri` 是授权
//!    URL 的参数（不是预登记常量），换端口不影响换码。
//!
//! ── 思考等级 ────────────────────────────────────────────────
//! 上游认 `reasoning.effort`（minimal/low/medium/high）。插件把网关的档位写进
//! 请求体的 `reasoning_effort`，由共享的 `openai_responses::responses` 翻成
//! `reasoning: { effort }`。
//!
//! ── 已知能力差 ──────────────────────────────────────────────
//! - 余额查询未实现：上游没有公开的额度查询端点（参考实现靠 401/429 事后判）。
//! - 无签到 / 无领取：订阅制没有可签到的积分。
//! - `debug_traffic` 未采集。
//! - 上游请求头里 `OpenAI-Beta` / `conversation_id` 无证据可核实，因此不发。

pub mod accounts;
pub mod callback_server;
pub mod chat;
pub mod credentials;
pub mod endpoints;
pub mod login;
pub mod models;
pub mod oauth;
pub mod siwc;

use serde_json::Value;

use agent2api_provider_protocol as proto;
use agent2api_provider_sdk::{ConversationSink, PluginCtx, Provider, ProviderMeta, SendFuture};

use crate::errors::GatewayError;

pub const PROVIDER_ID: &str = "codex";

pub struct CodexProvider;

/// 解析账号的出网代理（**不静默回落直连**）。
pub(crate) fn account_proxy(
    record: &Value,
) -> Result<Option<proto::WireProxy>, GatewayError> {
    match crate::proxy_util::resolve_account_proxy(record.get("proxy")) {
        None => Ok(None),
        Some(crate::proxy_util::ProxyResolution::Resolved(proxy)) => Ok(Some(proxy)),
        Some(crate::proxy_util::ProxyResolution::Failed(reason)) => {
            Err(GatewayError::with_status(400, reason))
        }
    }
}

impl Provider for CodexProvider {
    fn meta(&self) -> ProviderMeta {
        let mut meta = ProviderMeta::new(PROVIDER_ID, "Codex")
            .with_capabilities(proto::Capabilities {
                chat: true,
                stateful: false,
                refresh: true,
                // 上游没有「列出可用模型」端点，清单是静态的（按套餐分档）。
                model_refresh: false,
                // 没有公开的额度查询端点。
                usage: false,
                checkin: false,
                claims: false,
                web_login: true,
                // 插件自己推 chat 帧，模型名不需要网关改写。
                sse_model_rewrite: false,
                sse_strip_newline_chunks: false,
                anonymous_default_session: false,
                // 出网由网关发起，账号代理在 conversation 里显式使用。
                system_proxy_when_unset: false,
                refresh_uses_account: true,
                supports_default_model: true,
                env_credentials: false,
            })
            .with_login(vec![
                proto::LoginMethod::Browser {
                    button: "网页登录".to_string(),
                    hint: Some(
                        "打开 auth.openai.com 授权页，完成后自动收下账号（也可把回调地址整段粘回来）"
                            .to_string(),
                    ),
                },
                proto::LoginMethod::Token {
                    label: "设备码登录".to_string(),
                    placeholder: "留空即可：点「开始」后按提示在浏览器里输入验证码".to_string(),
                    extra_fields: Vec::new(),
                },
                proto::LoginMethod::Token {
                    label: "登录凭据".to_string(),
                    placeholder: "粘贴 Codex refresh token（以 rt_ 开头）或整段回调地址"
                        .to_string(),
                    extra_fields: Vec::new(),
                },
            ])
            .with_models(models::union_catalog())
            .with_account_features(proto::AccountFeatures {
                usage: false,
                credit_detail: false,
                identifier: vec!["email".to_string()],
                long_lived: true,
                email_as_name: true,
                ..Default::default()
            });
        // 与 `pack.json` 的 order 一致：网关按它排列表，0 会掉到最前面。
        meta.order = 34;
        meta
    }

    fn build_chat<'a>(
        &'a self,
        _ctx: &'a PluginCtx,
        _req: proto::ChatRequest,
    ) -> SendFuture<'a, agent2api_provider_sdk::ChatPlan> {
        // 本家走 conversation：上游的 Responses 事件流必须由插件自己翻成 chat 帧。
        Box::pin(async move {
            Err(agent2api_provider_sdk::control_error(
                501,
                "Codex 的转发走会话通道（Responses 事件流由插件翻译），不支持一次性 chat 计划",
                None,
                None,
            ))
        })
    }

    fn conversation<'a>(
        &'a self,
        ctx: &'a PluginCtx,
        request: proto::ConversationRequest,
        sink: ConversationSink<'a>,
    ) -> SendFuture<'a, ()> {
        Box::pin(chat::run(ctx, request, sink))
    }

    fn classify(&self, status: u16, body: &Value) -> proto::ErrorClass {
        let message = endpoints::upstream_message(body);
        let upstream_code = body
            .pointer("/error/code")
            .and_then(Value::as_i64)
            .or_else(|| body.get("code").and_then(Value::as_i64));
        if status == 401
            || status == 403
            || body
                .pointer("/error/type")
                .and_then(Value::as_str)
                .is_some_and(|value| value == "authentication_error")
        {
            return proto::ErrorClass::TokenExpired { message };
        }
        let lower = message.to_ascii_lowercase();
        if status == 429
            || lower.contains("usage limit")
            || lower.contains("rate limit")
            || lower.contains("quota")
            || lower.contains("额度")
        {
            return proto::ErrorClass::QuotaLimited {
                reset_at: None,
                message,
                upstream_code,
                status,
            };
        }
        let status = if (200..300).contains(&status) {
            502
        } else {
            status
        };
        crate::content_block::classify_or_fatal(status, body, message, upstream_code)
    }

    /// 思考档位写进 `reasoning_effort`（共享转换会翻成 `reasoning.effort`）。
    fn reasoning_patch(&self, level: &str, model: &str, body: &Value) -> proto::ReasoningPatch {
        if crate::model_rules::reasoning_is_off(level) {
            return proto::ReasoningPatch::Skip {
                reason: "客户端要求关闭思考".into(),
            };
        }
        if crate::model_rules::read_client_level(body).is_some() {
            return proto::ReasoningPatch::Skip {
                reason: "客户端已指定思考档位".into(),
            };
        }
        if !models::supports_reasoning(model) {
            return proto::ReasoningPatch::Skip {
                reason: format!("Codex 的「{model}」不支持思考档位"),
            };
        }
        if crate::model_rules::reasoning_rank(level).is_none() {
            return proto::ReasoningPatch::Skip {
                reason: "Codex 不认识该思考档位".into(),
            };
        }
        proto::ReasoningPatch::Set {
            field: "reasoning_effort".to_string(),
            value: Value::String(level.to_string()),
        }
    }

    fn ensure_token<'a>(
        &'a self,
        ctx: &'a PluginCtx,
        account: &'a str,
    ) -> SendFuture<'a, String> {
        Box::pin(async move {
            let credentials = oauth::ensure_fresh(ctx, account, false).await?;
            Ok(credentials.access_token)
        })
    }

    fn refresh_token<'a>(
        &'a self,
        ctx: &'a PluginCtx,
        account: &'a str,
    ) -> SendFuture<'a, String> {
        Box::pin(async move {
            let credentials = oauth::ensure_fresh(ctx, account, true).await?;
            Ok(credentials.access_token)
        })
    }

    fn token_expiring<'a>(
        &'a self,
        ctx: &'a PluginCtx,
        account: &'a str,
    ) -> SendFuture<'a, bool> {
        Box::pin(async move {
            let record = match oauth::read_record(ctx, account).await {
                Ok(record) => record,
                Err(_) => return Ok(false),
            };
            let Ok(credentials) = credentials::from_record(Some(&record)) else {
                return Ok(false);
            };
            Ok(credentials.can_refresh() && credentials.expiring())
        })
    }

    fn models<'a>(
        &'a self,
        ctx: &'a PluginCtx,
        account: &'a str,
    ) -> SendFuture<'a, proto::ModelList> {
        Box::pin(async move {
            let plan = plan_of(ctx, account).await;
            Ok(proto::ModelList {
                models: models::catalog(&plan),
                meta: proto::CatalogMeta::default(),
            })
        })
    }

    fn normalize_account<'a>(
        &'a self,
        ctx: &'a PluginCtx,
        input: proto::NormalizeInput,
    ) -> SendFuture<'a, proto::NormalizedAccount> {
        Box::pin(accounts::normalize(ctx, input))
    }

    fn account_view(&self, secret: &Value) -> Result<proto::AccountView, String> {
        Ok(accounts::account_view(secret))
    }

    fn account_identity(&self, secret: &Value) -> Result<String, String> {
        Ok(accounts::identity_of(secret))
    }

    fn login_start<'a>(
        &'a self,
        _ctx: &'a PluginCtx,
        method: &'a str,
        payload: &'a Value,
    ) -> SendFuture<'a, proto::LoginStart> {
        Box::pin(login::login_start(method, payload))
    }

    fn login_poll<'a>(
        &'a self,
        _ctx: &'a PluginCtx,
        flow: &'a str,
    ) -> SendFuture<'a, proto::LoginPoll> {
        Box::pin(login::login_poll(flow))
    }

    fn login_callback<'a>(
        &'a self,
        _ctx: &'a PluginCtx,
        callback: proto::LoginCallback,
    ) -> SendFuture<'a, proto::LoginPoll> {
        Box::pin(async move { login::login_callback(&callback).await })
    }

    fn login_cancel<'a>(&'a self, _ctx: &'a PluginCtx, flow: &'a str) -> SendFuture<'a, ()> {
        Box::pin(async move {
            login::login_cancel(flow).await;
            Ok(())
        })
    }

    /// 管理动作：SIWC 通道绑定 + 登录方式清单。
    ///
    /// SIWC 的两个动作分两步走，理由见 `siwc` 模块头（等用户授权可能超过一次
    /// RPC 的超时，而且参考实现允许手动粘贴回调）。
    ///
    /// * `siwc-start`：入参空；返回 `{url, state, deviceId}`，界面把 `url`
    ///   打开给用户。
    /// * `siwc-finish`：入参 `{state, code}`，`code` 可以是纯授权码或整段
    ///   回调地址；返回 `{bound: true, accountId, clientId, deviceId}`，并把
    ///   `siwc` 子对象写回该账号的 secret。
    /// * `siwc-status`：查当前账号是否已绑定。
    /// * `auth.methods`：界面上的登录方式清单（不实现时网关会整块降级成
    ///   「手动凭证 JSON（兼容入口）」）。
    fn admin_action<'a>(
        &'a self,
        ctx: &'a PluginCtx,
        account: &'a str,
        action: &'a str,
        payload: &'a Value,
    ) -> SendFuture<'a, Value> {
        Box::pin(async move {
            match action {
                "auth.methods" => Ok(login::login_methods()),
                "siwc-start" => siwc_start(ctx, account).await,
                "siwc-finish" => siwc_finish(ctx, account, payload).await,
                "siwc-status" => siwc_status(ctx, account).await,
                other => Err(format!(
                    "Codex 不认识管理动作「{other}」（可用：auth.methods / siwc-start / siwc-finish / siwc-status）"
                )),
            }
        })
    }
}

/// `codex.siwc-start`：生成 SIWC 授权 URL。
async fn siwc_start(ctx: &PluginCtx, account: &str) -> Result<Value, String> {
    let record = oauth::read_record(ctx, account)
        .await
        .map_err(|error| error.message)?;
    let secret = crate::store::secret_view(&record);
    let (url, state) = siwc::begin(&secret).map_err(|error| error.message)?;
    let device_id = secret
        .pointer("/siwc/device_id")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    Ok(serde_json::json!({
        "url": url,
        "state": state,
        "deviceId": device_id,
        "instructions": "在浏览器打开上面的地址完成 ChatGPT 授权；完成后把回调地址整段粘回来。",
    }))
}

/// `codex.siwc-finish`：换码并把 `siwc` 写回账号。
async fn siwc_finish(ctx: &PluginCtx, account: &str, payload: &Value) -> Result<Value, String> {
    let state = payload
        .get("state")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    let code = payload
        .get("code")
        .and_then(Value::as_str)
        .or_else(|| payload.get("url").and_then(Value::as_str))
        .unwrap_or_default()
        .to_string();
    if state.trim().is_empty() {
        return Err("codex.siwc-finish 缺少 state（用 siwc-start 返回的那个）".to_string());
    }
    if code.trim().is_empty() {
        return Err("codex.siwc-finish 缺少 code（粘贴回调地址或其中的 code 参数）".to_string());
    }
    let record = oauth::read_record(ctx, account)
        .await
        .map_err(|error| error.message)?;
    let proxy = account_proxy(&record)
        .map_err(|error| error.message)?;
    let (pending, stored) = siwc::finish(&state, &code, proxy.as_ref())
        .await
        .map_err(|error| error.message)?;
    let client_id = stored
        .get("client_id")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    let secret = crate::store::secret_view(&record);
    let next = siwc::merge_into(&secret, stored);
    let saved = crate::store::save(ctx, account, &secret, &next)
        .await
        .map_err(|error| error.message)?;
    if !saved {
        return Err("账号在绑定期间被改动过，SIWC 结果没有写回，请重新绑定".to_string());
    }
    crate::logging::log(
        "[Codex]",
        &format!("SIWC 通道已绑定（client {client_id}，device {}）", pending.device_id),
    );
    Ok(serde_json::json!({
        "bound": true,
        "clientId": client_id,
        "deviceId": pending.device_id,
    }))
}

/// `codex.siwc-status`：报告是否已绑定。
async fn siwc_status(ctx: &PluginCtx, account: &str) -> Result<Value, String> {
    let record = oauth::read_record(ctx, account)
        .await
        .map_err(|error| error.message)?;
    let secret = crate::store::secret_view(&record);
    Ok(serde_json::json!({
        "bound": siwc::bound(&secret),
        "deviceId": secret.pointer("/siwc/device_id").cloned().unwrap_or(Value::Null),
        "clientId": secret.pointer("/siwc/client_id").cloned().unwrap_or(Value::Null),
    }))
}

/// 读账号的套餐档位（取不到就按 `free` 之外的空串处理，让 `models::catalog` 走 default）。
async fn plan_of(ctx: &PluginCtx, account: &str) -> String {
    let record = match oauth::read_record(ctx, account).await {
        Ok(record) => record,
        Err(_) => return String::new(),
    };
    match credentials::from_record(Some(&record)) {
        Ok(credentials) => credentials.plan_type,
        Err(_) => String::new(),
    }
}

#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#[cfg(test)]
mod tests {
    use super::*;

    fn provider() -> CodexProvider {
        CodexProvider
    }

    #[test]
    fn meta_declares_the_expected_capabilities() {
        let meta = provider().meta();
        assert_eq!(meta.id, PROVIDER_ID);
        assert!(meta.capabilities.chat);
        assert!(meta.capabilities.refresh);
        // 上游没有「列出可用模型」端点，也没有额度查询端点。
        assert!(!meta.capabilities.model_refresh);
        assert!(!meta.capabilities.usage);
        assert!(meta.capabilities.supports_default_model);
        assert!(!meta.capabilities.system_proxy_when_unset);
    }

    #[test]
    fn meta_offers_both_login_paths() {
        let meta = provider().meta();
        assert_eq!(meta.login_methods.len(), 3);
        assert!(matches!(
            meta.login_methods.first(),
            Some(proto::LoginMethod::Browser { .. })
        ));
    }

    #[test]
    fn meta_has_a_default_catalog() {
        let meta = provider().meta();
        assert!(!meta.default_models.is_empty());
        assert!(meta
            .default_models
            .iter()
            .any(|model| model.get("id").and_then(Value::as_str) == Some(models::DEFAULT_MODEL)));
    }

    #[test]
    fn a_usage_limit_is_quota_limited() {
        let class = provider().classify(429, &serde_json::json!({ "error": { "message": "usage limit reached" } }));
        assert!(matches!(class, proto::ErrorClass::QuotaLimited { .. }));
    }

    #[test]
    fn an_authentication_error_is_token_expired() {
        let class = provider().classify(
            401,
            &serde_json::json!({ "error": { "type": "authentication_error", "message": "bad token" } }),
        );
        assert!(matches!(class, proto::ErrorClass::TokenExpired { .. }));
    }

    #[test]
    fn reasoning_is_set_for_a_reasoning_model() {
        let patch = provider().reasoning_patch("high", "gpt-5.6-sol", &serde_json::json!({}));
        assert!(matches!(patch, proto::ReasoningPatch::Set { .. }));
    }

    #[test]
    fn reasoning_is_skipped_when_the_client_already_chose() {
        let patch = provider().reasoning_patch(
            "high",
            "gpt-5.6-sol",
            &serde_json::json!({ "reasoning_effort": "low" }),
        );
        assert!(matches!(patch, proto::ReasoningPatch::Skip { .. }));
    }
}
