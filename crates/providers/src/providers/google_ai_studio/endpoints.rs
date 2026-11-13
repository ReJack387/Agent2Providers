//! Google AI Studio（Gemini API）的固定常量。
//!
//! ── 接口清单 ──────────────────────────────────────────────────
//! - 模型调用：`POST {API_BASE}/models/{model}:streamGenerateContent?alt=sse`
//!   （`generateContent` 是整包响应，插件走流式那条，`alt=sse` 才回 SSE 帧）
//! - 模型目录：`GET  {API_BASE}/models?pageSize=…`（分页靠 `nextPageToken`）
//! - 鉴权：请求头 `x-goog-api-key: <API_KEY>`。放在头里而不是 `?key=`，
//!   避免密钥出现在 URL 里被上游访问日志与网关日志抄走。
//!
//! ── 为什么不用 `UpstreamKind::Gemini` ─────────────────────────
//! 网关那个 Gemini 翻译层吃的是 Antigravity 的 v1internal 信封
//! （`data: {"response":{…}}`），而 AI Studio 原生帧是
//! `data: {"candidates":[…]}` 的裸帧。两者不是同一种形状，所以本家
//! 自己把原生帧翻成 OpenAI chat 帧（`stateful = true`）。

/// provider id（`pack.json` 里也要写同一个）。
pub const PROVIDER_ID: &str = "google-ai-studio";

/// Gemini API 的 v1beta 根地址。
pub const API_BASE: &str = "https://generativelanguage.googleapis.com/v1beta";

/// 模型目录地址（分页参数在 `models.rs` 里拼）。
pub const MODELS_URL: &str = "https://generativelanguage.googleapis.com/v1beta/models";

/// 领取 API Key 的页面，写进登录说明给用户看。
pub const KEY_PAGE: &str = "https://aistudio.google.com/apikey";

/// 模型目录里挑不出可用项时的兜底模型。
pub const DEFAULT_MODEL: &str = "gemini-2.5-flash";

/// 目录缓存有效期：10 分钟（与仓库里其它家的 TTL 一致）。
pub const CATALOG_TTL_MS: i64 = 10 * 60 * 1000;

/// 单次目录拉取的页数上限（防止 `nextPageToken` 死循环）。
pub const CATALOG_MAX_PAGES: usize = 8;

/// 单页条数。
pub const CATALOG_PAGE_SIZE: u32 = 200;
