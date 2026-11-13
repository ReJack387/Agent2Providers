//! Google AI Studio（Gemini API Key 直连）。
//!
//! ── 这家是什么 ──────────────────────────────────────────────
//! Google AI Studio 的 API Key 可以直连 `generativelanguage.googleapis.com`
//! 的 Gemini 接口，按 token 计费，不涉及任何 OAuth 授权码流程。所以这里的
//! 登录方式只有一条「粘贴 API Key」（`type: "api"`），没有网页登录。
//!
//! ── 为什么 `stateful = true` ─────────────────────────────────
//! 上游回的是 Gemini 原生 SSE（`data: {"candidates":[…]}` 裸帧），而网关的
//! `UpstreamKind::Gemini` 翻译层吃的是 Antigravity 的 v1internal 信封
//! （`data: {"response":{…}}`）。两者不同形，硬报 Gemini 会翻不出来，所以
//! 由插件自己读帧、翻成 OpenAI chat 帧后推给网关 —— 这是会话式转发的定义。
//! 好处是只写一条流式路径：客户端要非流式时，网关的
//! `aggregate_frame_stream` 会把这里推的帧聚合成一个 JSON。
//!
//! ── 能力位为什么这么填 ──────────────────────────────────────
//! - `refresh: false` —— API Key 没有续期概念，失效只能重新生成
//! - `model_refresh: true` —— `GET /v1beta/models` 能列出真实可用型号
//! - `usage: false` / `checkin: false` —— 额度要另外接 Cloud Billing，
//!   免费层没有可查的余额接口，签到更不存在
//! - `web_login: false` —— 没有网页登录流程
//! - `supports_default_model: true` —— 用户可以在网关里指定默认型号
//! - `system_proxy_when_unset: false` —— Google 域名在国内需要显式配代理，
//!   跟随系统代理会让人误以为「配了代理却没生效」

pub mod accounts;
pub mod chat;
pub mod credentials;
pub mod endpoints;
pub mod login;
pub mod models;
pub mod protocol;
pub mod proxy;
pub mod signatures;
pub mod stream;

use agent2api_provider_protocol as proto;
use agent2api_provider_sdk::{
    ConversationSink, PluginCtx, Provider, ProviderMeta, SendFuture,
};
use serde_json::Value;

/// provider id（`pack.json` 里也要写同一个）。
pub const PROVIDER_ID: &str = endpoints::PROVIDER_ID;

/// 思考等级绑定写进的 body 顶层字段。
///
/// `ReasoningPatch::Set` 只认 body **顶层**字段，所以不能直接写
/// `generationConfig.thinkingConfig.thinkingBudget`；先写这里，再由
/// `protocol::build_upstream_body` 搬进 Gemini 的 `generationConfig`。
const REASONING_FIELD: &str = "reasoning_effort";

/// Google AI Studio 适配器。
pub struct GoogleAiStudioProvider;

impl Provider for GoogleAiStudioProvider {
    fn meta(&self) -> ProviderMeta {
        let mut meta = ProviderMeta::new(PROVIDER_ID, "Google AI Studio")
            .with_capabilities(proto::Capabilities {
                chat: true,
                // 上游是原生 Gemini SSE，网关的 Gemini 翻译层不认，自己翻
                stateful: true,
                // API Key 没有续期接口
                refresh: false,
                model_refresh: true,
                usage: false,
                checkin: false,
                claims: false,
                web_login: false,
                sse_model_rewrite: false,
                sse_strip_newline_chunks: false,
                anonymous_default_session: false,
                system_proxy_when_unset: false,
                refresh_uses_account: true,
                supports_default_model: true,
                env_credentials: false,
            })
            .with_login(vec![proto::LoginMethod::Token {
                label: "粘贴 Gemini API Key".into(),
                placeholder: "AIza…".into(),
                extra_fields: vec![proto::LoginField {
                    key: "name".into(),
                    label: "备注名（可选）".into(),
                    placeholder: "留空则显示 Key 尾号".into(),
                    optional: true,
                    multiline: false,
                }],
            }])
            .with_models(models::fallback_models())
            .with_account_features(proto::AccountFeatures {
                usage: false,
                credit_detail: false,
                credit_expiry: false,
                usage_detail: false,
                edition: false,
                identifier: vec!["uid".into()],
                expiry: Vec::new(),
                long_lived: false,
                claim: false,
                plan_channel: false,
                email_as_name: false,
                concurrency_default: None,
                default_limiters: None,
            });
        meta.order = 35;
        meta
    }

    fn provider_id(&self) -> String {
        PROVIDER_ID.to_string()
    }

    fn conversation<'a>(
        &'a self,
        ctx: &'a PluginCtx,
        req: proto::ConversationRequest,
        sink: ConversationSink<'a>,
    ) -> SendFuture<'a, ()> {
        Box::pin(async move { chat::run(ctx, req, sink).await })
    }

    fn normalize_account<'a>(
        &'a self,
        ctx: &'a PluginCtx,
        input: proto::NormalizeInput,
    ) -> SendFuture<'a, proto::NormalizedAccount> {
        Box::pin(async move { accounts::normalize(ctx, input).await })
    }

    fn account_view(&self, secret: &Value) -> Result<Value, String> {
        Ok(accounts::public(secret))
    }

    fn account_identity(&self, secret: &Value) -> Result<String, String> {
        Ok(accounts::identity(secret))
    }

    /// 模型目录：空账号时取第一条已存账号，避免界面初次加载空白。
    fn models<'a>(
        &'a self,
        ctx: &'a PluginCtx,
        account: &'a str,
    ) -> SendFuture<'a, proto::ModelList> {
        Box::pin(async move {
            let account_id = if account.trim().is_empty() {
                match ctx.store_list(PROVIDER_ID).await {
                    Ok(accounts) => accounts
                        .first()
                        .map(|found| found.id.clone())
                        .unwrap_or_default(),
                    Err(_) => String::new(),
                }
            } else {
                account.to_string()
            };
            Ok(models::list(&account_id))
        })
    }

    fn refresh_models<'a>(
        &'a self,
        ctx: &'a PluginCtx,
        account: &'a str,
        force: bool,
    ) -> SendFuture<'a, proto::RefreshOutcome> {
        Box::pin(async move {
            if account.trim().is_empty() {
                return Ok(proto::RefreshOutcome::unchanged());
            }
            match models::refresh(ctx, account, force).await {
                Ok((outcome, _)) => Ok(outcome),
                Err(message) => Ok(proto::RefreshOutcome::failed(message)),
            }
        })
    }

    /// 绑定写进来的思考档位。
    ///
    /// 三段让位逻辑与 accio 同款：关闭态不写、客户端已指定不写、超出通用
    /// 档位表不写。
    fn reasoning_patch(&self, level: &str, _model: &str, body: &Value) -> proto::ReasoningPatch {
        if crate::model_rules::reasoning_is_off(level) {
            return proto::ReasoningPatch::Skip {
                reason: "该等级语义是关闭思考，不需要下发".into(),
            };
        }
        if crate::model_rules::read_client_level(body).is_some() {
            return proto::ReasoningPatch::Skip {
                reason: "客户端请求体里已指定思考等级，绑定让位".into(),
            };
        }
        if crate::model_rules::reasoning_rank(level).is_none() {
            return proto::ReasoningPatch::Skip {
                reason: "该等级不在通用档位表内".into(),
            };
        }
        proto::ReasoningPatch::Set {
            field: REASONING_FIELD.into(),
            value: Value::String(level.to_string()),
        }
    }

    /// 错误分类。
    ///
    /// 本家走 `conversation`，所以 `classify` 主要供网关的
    /// `CLASSIFY` 调用（例如模型探测）使用；`conversation` 内部另有一份
    /// 文案 → 状态码的映射（`chat::classify_message`）。
    fn classify(&self, status: u16, body: &Value) -> proto::ErrorClass {
        let message = body
            .pointer("/error/message")
            .and_then(Value::as_str)
            .or_else(|| body.get("message").and_then(Value::as_str))
            .unwrap_or_default()
            .to_string();
        let lower = message.to_ascii_lowercase();
        let upstream_code = body
            .pointer("/error/code")
            .and_then(Value::as_i64)
            .or_else(|| body.get("code").and_then(Value::as_i64));

        if status == 401 || status == 403 || lower.contains("api key not valid") {
            return proto::ErrorClass::TokenExpired { message };
        }
        if status == 429
            || lower.contains("resource_exhausted")
            || lower.contains("quota")
            || lower.contains("rate limit")
        {
            return proto::ErrorClass::QuotaLimited {
                reset_at: None,
                message,
                upstream_code,
                status: 429,
            };
        }
        // 内容策略拦截不罚号，交给共用工具判断文案特征。
        if crate::content_block::matched(status, body) {
            return crate::content_block::classify_or_fatal(status, body, message, upstream_code);
        }
        proto::ErrorClass::Fatal {
            status,
            message,
            upstream_code,
        }
    }

    /// 动态登录方式（网关「添加账号」弹窗按它渲染）。
    fn admin_action<'a>(
        &'a self,
        _ctx: &'a PluginCtx,
        _account: &'a str,
        action: &'a str,
        _payload: &'a Value,
    ) -> SendFuture<'a, Value> {
        Box::pin(async move {
            match action {
                "auth.methods" => Ok(login::login_methods()),
                other => Err(agent2api_provider_sdk::unsupported(format!(
                    "Google AI Studio 不支持管理动作「{other}」"
                ))),
            }
        })
    }
}
