//! Claude（Anthropic 的 Claude Code 订阅通道）适配实现：账号 / token 刷新 /
//! 模型清单 / 聊天转发 / 网页登录。
//!
//! ── 上游长什么样 ────────────────────────────────────────────
//! ```text
//!   站点     全球统一（没有地区参数）
//!   鉴权     Claude OAuth 2.0 + PKCE（授权码 + loopback 回调；也支持粘贴
//!            refresh token）→ Authorization: Bearer {access_token}
//!   推理     POST https://api.anthropic.com/v1/messages
//!            协议 = Anthropic Messages（message_start / content_block_delta /
//!            message_stop），不是 chat completions
//!   换码     POST https://platform.claude.com/v1/oauth/token（JSON body）
//!   刷新     POST https://platform.claude.com/v1/oauth/token（JSON body）
//!   账号面   GET  /api/oauth/profile  +  /api/oauth/claude_cli/roles（尽力读）
//! ```
//! 三处容易踩的点（都在 `endpoints.rs` 与 `oauth.rs` 的注释里展开）：
//!   1. 换码端点**不是** `api.anthropic.com`，是 `platform.claude.com`；
//!   2. 授权 URL 的 scope 比刷新多一个 `org:create_api_key`，两者不能混用；
//!   3. refresh token 是**一次性**的 —— 网络抖动不能重放，否则账号直接废掉。
//!
//! ── 为什么 `stateful = false` ───────────────────────────────
//! 上游是「一次 HTTP 请求 = 一次生成」，只是协议是 Anthropic Messages。插件
//! 报 `UpstreamKind::Anthropic`，网关据此选 `AnthropicToChatStream` 翻译层 ——
//! 与 Antigravity 报 `Gemini`、ZCode 套餐池走 Anthropic 是同一处置。没有多步
//! 会话协议，用 `conversation` 只会把账号轮换 / 限额冷却 / 退避重试在插件里
//! 重写一遍。
//!
//! ── 交付边界 ────────────────────────────────────────────────
//! ```text
//!   ✅ 账号：网页授权（loopback 回调）+ 粘贴 refresh token（真刷新校验）
//!   ✅ token 刷新：提前 4 小时主动刷 + 单飞 + 比较再写
//!   ✅ 模型清单：静态表（Claude 没有可用的远程目录接口，见 models.rs）
//!   ✅ 聊天转发：chat → Messages 转换（复用 crate::anthropic 的共享实现）
//! ```
//!
//! ── 已知能力差（如实记录）──────────────────────────────────
//!   1. **余额查询未实现**：Claude 的额度接口（`/api/oauth/usage` 一类）没有
//!      可核实的公开形态，参考实现的快照里也没有 —— 与其猜一个端点然后让
//!      界面显示错误读数，不如不申报（`usage: false`）。
//!   2. **没有签到 / 领取**：订阅制，上游没有这类动作。
//!   3. **调试抓包**（`HostEnv.debug_traffic`）插件侧没有采集器 —— 抓包开关
//!      对本家无效。
//!   4. **设备标识**（`claude_device_ids`）未实现：参考实现在 metadata 里存
//!      一份 64 位 hex 设备 id 并在推理时带上；本插件没有对应的请求头证据
//!      （Go 快照里没有 `/v1/messages` 的头构造），故不发明。
//!
//! ── 子模块分工 ──────────────────────────────────────────────
//! ```text
//!   endpoints.rs      OAuth 端点 / client_id / scope / 三套请求头 / 常量
//!   credentials.rs    凭证形态 + 到期判定（提前 4 小时）+ 稳定身份
//!   oauth.rs          PKCE / 换码 / 刷新（单飞 + 比较再写）/ profile 尽力读
//!   models.rs         静态模型清单 + 前缀放行 + 思考档判定
//!   callback_server.rs  网页登录的本机回调监听器（一次登录一个随机端口）
//!   login.rs          网页登录流程 + 粘贴式归一化与校验
//!   accounts.rs       账号归一化 / 公开视图 / 稳定身份
//!   chat.rs           Provider 数据面：chat → Messages 请求构造
//! ```
//!
//! ── 硬约束 ──────────────────────────────────────────────────
//! release 是 `panic=abort`：本目录零 unwrap/expect/panic。

pub mod accounts;
pub mod callback_server;
pub mod chat;
pub mod credentials;
pub mod endpoints;
pub mod login;
pub mod models;
pub mod oauth;

use serde_json::Value;

use agent2api_provider_protocol as proto;
use agent2api_provider_protocol::WireProxy as ResolvedProxy;
use agent2api_provider_sdk::{
    ChatPlan, PluginCtx, Provider, ProviderMeta, SendFuture,
};

use crate::errors::GatewayError;

/// provider id（落盘契约，与网关内置家同名）。
pub const PROVIDER_ID: &str = "claude";

/// 本家适配器（无状态）。
pub struct ClaudeProvider;

/// 解析账号记录里的出网代理配置。
///
/// `Some(Resolved)` → 用它；`Some(Failed)` → 报 400（**不静默回落直连**：
/// 用户配了代理就是要走代理，悄悄直连会让请求从错误的出口打出去）。
pub(crate) fn account_proxy(record: &Value) -> Result<Option<ResolvedProxy>, GatewayError> {
    match crate::proxy_util::resolve_account_proxy(record.get("proxy")) {
        None => Ok(None),
        Some(crate::proxy_util::ProxyResolution::Resolved(proxy)) => Ok(Some(proxy)),
        Some(crate::proxy_util::ProxyResolution::Failed(reason)) => {
            Err(GatewayError::with_status(400, reason))
        }
    }
}

impl Provider for ClaudeProvider {
    fn meta(&self) -> ProviderMeta {
        let mut meta = ProviderMeta::new(PROVIDER_ID, "Claude")
            .with_capabilities(proto::Capabilities {
                chat: true,
                // Anthropic Messages 是「一次请求一次生成」，没有多步会话协议
                stateful: false,
                // 有 refresh token 就能续期
                refresh: true,
                // 静态清单，没有远程目录
                model_refresh: false,
                // 额度接口没有可核实的形态，不申报（见模块头「已知能力差」）
                usage: false,
                checkin: false,
                claims: false,
                // 网页授权 + loopback 回调
                web_login: true,
                // 上游原样回 Claude 的模型名，不需要改写
                sse_model_rewrite: false,
                sse_strip_newline_chunks: false,
                anonymous_default_session: false,
                system_proxy_when_unset: false,
                refresh_uses_account: true,
                // 客户端不指定模型时用 `claude-sonnet-4-6`
                supports_default_model: true,
                env_credentials: false,
            })
            .with_login(vec![
                proto::LoginMethod::Browser {
                    button: "网页登录".to_string(),
                    hint: Some(
                        "打开 claude.ai 授权页，完成后自动收下账号（也可把回调地址整段粘回来）"
                            .to_string(),
                    ),
                },
                proto::LoginMethod::Token {
                    label: "登录凭据".to_string(),
                    placeholder: "粘贴 Claude refresh token（以 sk-ant-ort 开头）或整段回调地址"
                        .to_string(),
                    extra_fields: Vec::new(),
                },
            ])
            .with_models(models::catalog())
            .with_account_features(proto::AccountFeatures {
                usage: false,
                credit_detail: false,
                // Claude 的稳定标识是 email（组织名只做展示）
                identifier: vec!["email".to_string()],
                long_lived: true,
                email_as_name: true,
                ..Default::default()
            });
        // 与 `pack.json` 的 order 一致：网关按它排列表，0 会掉到最前面。
        meta.order = 33;
        meta
    }

    fn build_chat<'a>(
        &'a self,
        ctx: &'a PluginCtx,
        req: proto::ChatRequest,
    ) -> SendFuture<'a, ChatPlan> {
        Box::pin(async move {
            chat::build(ctx, &req.account, &req.body, &req.wire_model, req.stream)
                .await
                .map_err(|error| error.into_message())
        })
    }

    fn classify(&self, status: u16, body: &Value) -> proto::ErrorClass {
        let raw = endpoints::upstream_message(body);
        let message = if raw.is_empty() {
            format!("上游返回 {status}")
        } else {
            format!("上游返回 {status}：{raw}")
        };
        let upstream_code = body
            .pointer("/error/code")
            .and_then(Value::as_i64)
            .or_else(|| body.get("code").and_then(Value::as_i64));
        // Anthropic 的鉴权失败是 401 + `error.type == "authentication_error"`
        let authentication = body.pointer("/error/type").and_then(Value::as_str)
            == Some("authentication_error");
        if status == 401 || authentication {
            return proto::ErrorClass::TokenExpired { message };
        }
        if status == 429 {
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

    /// 思考档：Claude 用 `thinking.budget_tokens`，共享转换已经按
    /// `reasoning_effort` 折算好了 —— 这里不再二次注入。
    fn reasoning_patch(&self, level: &str, model: &str, body: &Value) -> proto::ReasoningPatch {
        if crate::reasoning::is_thinking_off(level) {
            return proto::ReasoningPatch::Skip {
                reason: "Claude 关闭思考要显式写 thinking.type=disabled，共享转换已按 body 处理"
                    .to_string(),
            };
        }
        if crate::reasoning::read_client_level(body).is_some() {
            return proto::ReasoningPatch::Skip {
                reason: "客户端请求体里已指定思考等级，绑定让位".to_string(),
            };
        }
        if !models::supports_thinking(model) {
            return proto::ReasoningPatch::Skip {
                reason: "该 Claude 模型不支持思考档（Haiku 系列）".to_string(),
            };
        }
        if crate::reasoning::effort_rank(level).is_none() {
            return proto::ReasoningPatch::Skip {
                reason: "该等级不在通用档位表内，Claude 不注入未知档位".to_string(),
            };
        }
        // 写回 `reasoning_effort`：共享转换读的就是这个字段，它再折算成
        // `thinking.budget_tokens`。不直接写 thinking，避免两处各算一遍。
        proto::ReasoningPatch::Set {
            field: "reasoning_effort".to_string(),
            value: Value::String(level.to_string()),
        }
    }

    fn ensure_token<'a>(&'a self, ctx: &'a PluginCtx, account: &'a str) -> SendFuture<'a, String> {
        Box::pin(async move {
            let credentials = oauth::ensure_fresh(ctx, account, false)
                .await
                .map_err(|error| error.into_message())?;
            Ok(credentials.access_token)
        })
    }

    fn refresh_token<'a>(
        &'a self,
        ctx: &'a PluginCtx,
        account: &'a str,
    ) -> SendFuture<'a, String> {
        Box::pin(async move {
            let credentials = oauth::ensure_fresh(ctx, account, true)
                .await
                .map_err(|error| error.into_message())?;
            Ok(credentials.access_token)
        })
    }

    fn token_expiring<'a>(
        &'a self,
        ctx: &'a PluginCtx,
        account: &'a str,
    ) -> SendFuture<'a, bool> {
        Box::pin(async move {
            let record = oauth::read_record(ctx, account).await?;
            let credentials = credentials::from_record(Some(&record))?;
            Ok(credentials.can_refresh() && credentials.expiring())
        })
    }

    fn models<'a>(
        &'a self,
        _ctx: &'a PluginCtx,
        _account: &'a str,
    ) -> SendFuture<'a, proto::ModelList> {
        Box::pin(async {
            Ok(proto::ModelList {
                models: models::catalog(),
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

    fn account_view(&self, secret: &Value) -> Result<Value, String> {
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

    /// 管理动作：只有 `auth.methods` 需要实现，其余照默认报不支持。
    ///
    /// 不实现 `auth.methods` 时网关会整块降级成「手动凭证 JSON（兼容入口）」，
    /// 用户只能自己拼凭证对象 —— 界面上那句「插件未实现 auth.methods (501)」
    /// 就是从这里来的。
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
                    "Claude 不支持管理动作「{other}」"
                ))),
            }
        })
    }

    fn login_poll<'a>(&'a self, _ctx: &'a PluginCtx, flow: &'a str) -> SendFuture<'a, proto::LoginPoll> {
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
        Box::pin(async move { login::login_cancel(flow).await })
    }
}

#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#[cfg(test)]
mod tests {
    use super::*;

    fn provider() -> ClaudeProvider {
        ClaudeProvider
    }

    #[test]
    fn the_meta_declares_a_chat_only_anthropic_upstream() {
        let meta = provider().meta();
        assert_eq!(meta.id, PROVIDER_ID);
        assert_eq!(meta.label, "Claude");
        assert!(meta.capabilities.chat);
        assert!(!meta.capabilities.stateful, "没有多步会话协议");
        assert!(meta.capabilities.refresh, "有 refresh token 就能续期");
        assert!(
            !meta.capabilities.model_refresh,
            "静态清单，没有远程目录可刷"
        );
        assert!(!meta.capabilities.usage, "额度接口未实现，不申报");
        assert!(meta.capabilities.web_login);
    }

    #[test]
    fn both_login_entries_are_offered() {
        let meta = provider().meta();
        let has_browser = meta
            .login_methods
            .iter()
            .any(|method| matches!(method, proto::LoginMethod::Browser { .. }));
        let has_token = meta
            .login_methods
            .iter()
            .any(|method| matches!(method, proto::LoginMethod::Token { .. }));
        assert!(has_browser, "网页授权是主入口");
        assert!(has_token, "打不开 claude.ai 的用户要有后路");
    }

    #[test]
    fn the_default_catalog_is_not_empty() {
        let meta = provider().meta();
        assert!(!meta.default_models.is_empty());
        assert!(meta
            .default_models
            .iter()
            .all(|record| record.get("id").is_some()));
    }

    #[test]
    fn a_rate_limit_is_quota_limited_not_fatal() {
        let class = provider().classify(429, &serde_json::json!({"error": {"message": "slow down"}}));
        assert!(class.rotates_account(), "429 要能换账号");
    }

    #[test]
    fn an_authentication_error_expires_the_token() {
        let class = provider().classify(
            403,
            &serde_json::json!({"error": {"type": "authentication_error"}}),
        );
        assert!(matches!(class, proto::ErrorClass::TokenExpired { .. }));
    }

    #[test]
    fn haiku_gets_no_thinking_patch() {
        let patch = provider().reasoning_patch("high", "claude-3-5-haiku", &serde_json::json!({}));
        assert!(matches!(patch, proto::ReasoningPatch::Skip { .. }));
    }

    #[test]
    fn a_sonnet_thinking_patch_targets_reasoning_effort() {
        let patch = provider().reasoning_patch("high", "claude-sonnet-4-6", &serde_json::json!({}));
        match patch {
            proto::ReasoningPatch::Set { field, value } => {
                assert_eq!(field, "reasoning_effort");
                assert_eq!(value, Value::String("high".to_string()));
            }
            other => panic!("expected Set, got {other:?}"),
        }
    }
}
