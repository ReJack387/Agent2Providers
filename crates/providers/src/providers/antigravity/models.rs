//! Antigravity 模型目录：`POST {base}:fetchAvailableModels` + 内置兜底清单。
//!
//! ── 上游形态（规格 §5.1）──────────────────────────────────────
//! ```text
//! POST {base}/v1internal:fetchAvailableModels
//! body   {"project": "<pid>"}（没有 pid 时 `{}`；上游忽略这个字段）
//! header Authorization: Bearer <token>、User-Agent: vscode/1.X.X (Antigravity/{ver})
//! resp   {"models": { "<model_id>": { quotaInfo: {remainingFraction, resetTime},
//!                                      displayName, supportsImages, supportsThinking,
//!                                      thinkingBudget, recommended, maxTokens,
//!                                      maxOutputTokens, supportedMimeTypes } },
//!          "deprecatedModelIds": { "<old>": {"newModelId": "<new>"} } }
//! ```
//! 模型是**以 id 为键的对象**（不是数组）—— 解析时要按 Map 遍历，别按数组读。
//!
//! ── 接哪些模型：三个家族（2026-10 放开 Claude/GPT）────────────
//! 同一个端点除 Gemini 外还下发 `claude-sonnet-4-6` / `claude-opus-4-6-*` /
//! `gpt-oss-120b-medium`（规格 §5.3）。本家曾经**只接 Gemini**（按 `gemini-`
//! 前缀白名单过滤），issue #288 之后放开到三个家族：
//!   - `gemini-*`、`claude-*`、`gpt-oss-*` 三种前缀的条目进广告清单与缓存；
//!   - 其余的一律不收 —— 「前缀白名单」而不是「黑名单排除已知的」，上游将来
//!     再下发别的家族（veo 之类）时默认仍是「不接」，而不是误广告一个没实现的通道。
//! 上游对**所有账号**（免费号与 Pro 号）下发的是同一份全量目录（Manager
//! `models/quota.rs` 的注释：两档拿到的 33 个模型完全相同），所以「账号里没有
//! Claude」不是档位问题，而是本仓此前自己把它过滤掉了 —— 放开后能否真正调用
//! 由上游按订阅档判定，不归本仓预判。
//!
//! Claude 的两条额外要求（规格 §5.3 与坑清单，都在别处落地）：
//!   1. 请求要带 `anthropic-beta` 头（见 `endpoints::content_headers` 的
//!      `claude` 分支）；
//!   2. 思考预算用 Claude 家族的默认档（1024，Manager `SPEC_CLAUDE_*`），
//!      不是 Gemini 的 32768（见 [`fallback_thinking_budget`]）。
//!
//! ── 兜底清单的 id 与「发给上游的名字」是两回事（映射表）──────
//! 规格 §5.2 的 id 是**本家对外的名字**：`gemini-3.6-flash` 发出去时上游要的是
//! `gemini-3.6-flash-tiered`，`gemini-3.1-pro-high` 对应上游真名
//! `gemini-pro-agent`（`gemini-3-pro-high` 同理）。映射表见
//! [`upstream_model_id`]（出处：Manager `CLAUDE_TO_GEMINI` 的 Gemini 部分 +
//! `is_bare_gemini_v36_or_above_flash` 的 tiered 规则；9router registry 的 id
//! 集合交叉验证）。**对不上的 id 原样透传** —— 远程
//! `fetchAvailableModels` 下发的 id 本身就是上游真名（规格 §5.2 末句 /
//! §8.11），不该被这张表改写。
//! Claude 的**旧 id 重定向**也在同一张表里（`claude-opus-4-5-thinking` →
//! `claude-opus-4-6-thinking` 这类，Manager `CLAUDE_TO_GEMINI` 逐条）：上游把
//! 上一代 Claude 统一重定向到 4.6，重定向规则因此要跟着走。**注意本仓与
//! Manager 的结构差异**：单一上游的 Manager 会把旧名原样收进来再改写，而本仓
//! 的模型门是「广告视图里没有就 404」，旧代 id 不在广告里 —— 那几条规则是
//! 清单漂移时的兜底，不是「写旧名就能用」的承诺（详见 `UPSTREAM_ALIASES` 的
//! 文档）。
//! 图片模型的组合后缀（`-2k/-4k` × 六个比例）在规格里只给了后缀集合、
//! 没给拼接形态，**不猜**：兜底清单只放 `gemini-3-pro-image` 与
//! `gemini-3.1-flash-image` 两条基础 id（TODO 见报告）。
//!
//! ── 三个环境轮流打（规格 §3.1 / §7.15）────────────────────────
//! `sandbox → daily → prod`：429 / 5xx / 传输失败就换下一个；4xx（403/404 之类）
//! 不换 —— 那是「这次请求本身不对」，换域名只会白撞。403 且带
//! `x-goog-user-project` 时按规格坑 #3 去掉该头再试一次。
//!
//! ── 缓存 ────────────────────────────────────────────────────
//! **只有内存**（迁移时去掉了网关那份 `catalog_cache` 落盘：插件侧没有落盘表，
//! 而落盘缓存的价值是「重启后首屏就有清单」—— 插件重启的代价是首轮真打一次
//! 上游，可接受）。本家**没有地区之分**（规格 §6），因此单格。
//! 自动路径 10 分钟 TTL；用户手动「刷新模型清单」时 `force = true` 绕过。
//!
//! ── 硬约束 ──────────────────────────────────────────────────
//! release 是 `panic=abort`：本文件零 unwrap/expect/panic。

use std::sync::{Mutex, OnceLock};
use std::time::Duration;

use serde_json::{json, Map, Value};

use crate::http as egress;
use agent2api_provider_protocol::WireProxy as ResolvedProxy;

use super::endpoints;

/// 自动路径的缓存 TTL（与别家的 5~10 分钟同档；目录不是热点数据）
const TTL_MS: i64 = 10 * 60 * 1000;

/// 单次目录请求超时
const REQUEST_TIMEOUT_MS: u64 = 20_000;

/// 本家对外 id → 上游模型 id 的**精确**别名表（规格 §5.2 括号里的真名；
/// Manager `CLAUDE_TO_GEMINI` 逐条）。
///
/// ```text
///   ── Gemini（规格 §5.2）────────────────────────────────────
///   gemini-3.6/3.7/3.8-flash  → <同 id>-tiered    （无后缀 Flash 走自适应档）
///   gemini-3.1-pro-high       → gemini-pro-agent  （Manager 表逐字）
///   gemini-3-pro-high         → gemini-pro-agent  （同上）
///   gemini-2.5-flash-lite     → gemini-2.5-flash  （Manager 表逐字；9router
///                               registry 不含这条 id，属两个参考的差异）
///   ── Claude 旧代 → 4.6 的重定向（Manager 表逐条）───────────
///   上游把上一代 Claude 统一重定向到 4.6（规格 §5.3 的括注：
///   `claude-opus-4-5*` / `claude-3-5-sonnet*` 被重定向到 4.6）。这张表照抄
///   Manager 的 `CLAUDE_TO_GEMINI` 那一组，作用与 Gemini 那几条**完全相同**：
///   **清单里出现过的 id** 在发送前改写成上游真名。
///   ⚠️ 别把这句读成「客户端写旧名字就能用」—— 本仓与 Manager 的单上游形态
///   有一处结构差异，值得写清楚：**网关的模型门是「广告视图里没有就 404」**
///   （`api::pipeline::resolve_model` 的 ③），而广告视图 = 本家清单（远程目录
///   过滤三家 + 兜底清单 + 用户登记的自定义模型）。远程目录下发的 id 就是上游
///   真名、且只有 4.6 一代，所以**点名旧代 id 会被 404 挡下**，走不到这张表。
///   它们的实际用途是**让旧名字在进了清单之后仍能发对**：
///     · 用户在模型管理里把某个旧代 id 登记成自定义模型（那是为「上游灰度、
///       目录没广告但能路由」准备的入口）时，改写规则已经在位；
///     · 远程目录哪天又下发回旧 id 时同理。
///   也就是说这几条是**改写规则**而不是**广告承诺** —— 后者只有兜底清单里
///   那三条新代 Claude。
///   **表里有映射的那几条 id 因此不进兜底清单**：旧名属于兼容项，不是本家主动
///   广告的模型。
/// ```
///
/// 表里没有的一律原样透传（见模块头：远程目录下发的 id 就是上游真名）。
const UPSTREAM_ALIASES: [(&str, &str); 21] = [
    ("gemini-3.6-flash", "gemini-3.6-flash-tiered"),
    ("gemini-3.7-flash", "gemini-3.7-flash-tiered"),
    ("gemini-3.8-flash", "gemini-3.8-flash-tiered"),
    ("gemini-3.1-pro-high", "gemini-pro-agent"),
    ("gemini-3-pro-high", "gemini-pro-agent"),
    ("gemini-2.5-flash-lite", "gemini-2.5-flash"),
    // Claude 4.5 / 4 系 → 4.6（`-thinking` 变体保留思考属性）
    ("claude-sonnet-4-5", "claude-sonnet-4-6"),
    ("claude-sonnet-4-5-thinking", "claude-sonnet-4-6-thinking"),
    ("claude-sonnet-4-5-20250929", "claude-sonnet-4-6-thinking"),
    ("claude-opus-4", "claude-opus-4-6-thinking"),
    ("claude-opus-4-5-thinking", "claude-opus-4-6-thinking"),
    ("claude-opus-4-5-20251101", "claude-opus-4-6-thinking"),
    // Claude 4.6 的**点分写法与裸名**：`claude-opus-4.6(-thinking)` 是客户端
    // 常见的另一种写法；裸 `claude-opus-4-6` 上游同样要 `-thinking` 那个真名
    ("claude-opus-4-6", "claude-opus-4-6-thinking"),
    ("claude-opus-4.6", "claude-opus-4-6-thinking"),
    ("claude-opus-4.6-thinking", "claude-opus-4-6-thinking"),
    ("claude-opus-4-6-20260201", "claude-opus-4-6-thinking"),
    // Claude 3.5 / Haiku 一代 → 最近的可用款
    ("claude-3-5-sonnet-20241022", "claude-sonnet-4-6"),
    ("claude-3-5-sonnet-20240620", "claude-sonnet-4-6"),
    ("claude-haiku-4", "claude-sonnet-4-6"),
    ("claude-haiku-4-5-20251001", "claude-sonnet-4-6"),
    ("claude-3-haiku-20240307", "claude-sonnet-4-6"),
];

/// 对外 id（或上游真名）→ 真正发给 v1internal 的模型 id。
///
/// 顺序：精确别名表 → 「无后缀 `gemini-<x.y>-flash`（x.y ≥ 3.6）加 `-tiered`」
/// 的动态规则（Manager `is_bare_gemini_v36_or_above_flash` 的语义）→
/// 原样返回。大小写不敏感匹配（客户端常发小写），但**返回值保留调用方给的
/// 原始大小写**（与 Manager `format!("{}-tiered", original_model)` 同口径）。
pub fn upstream_model_id(id: &str) -> String {
    let trimmed = id.trim();
    if trimmed.is_empty() {
        return String::new();
    }
    let lowered = trimmed.to_ascii_lowercase();
    for (alias, target) in UPSTREAM_ALIASES {
        if lowered == alias {
            return target.to_string();
        }
    }
    if let Some(tiered) = tiered_flash_id(trimmed, &lowered) {
        return tiered;
    }
    trimmed.to_string()
}

/// 「无后缀、版本 ≥ 3.6 的 `gemini-<x.y>-flash`」→ 追加 `-tiered`；
/// 其余（已有档位/变体后缀、版本不够、不是 flash）返回 None。
///
/// 逐条对齐 Manager `is_bare_gemini_v36_or_above_flash`：先排除一切已知后缀
/// （`-high` / `-medium` / `-low` / `-extra-low` / `-tiered` / `-preview` /
/// `-agent` / `-thinking` / `-image`），再解析 `gemini-` 之后的版本段
/// （取到第一个非数字非点号的字符为止）要求 ≥ 3.6。
fn tiered_flash_id(original: &str, lowered: &str) -> Option<String> {
    for suffix in [
        "-high", "-medium", "-low", "-extra-low", "-tiered", "-preview", "-agent", "-thinking",
        "-image",
    ] {
        if lowered.contains(suffix) {
            return None;
        }
    }
    if !lowered.contains("flash") {
        return None;
    }
    let rest = lowered.strip_prefix("gemini-")?;
    let version: String = rest
        .chars()
        .take_while(|ch| ch.is_ascii_digit() || *ch == '.')
        .collect();
    let version = version.trim_end_matches('.').parse::<f64>().ok()?;
    if version < 3.6 {
        return None;
    }
    Some(format!("{original}-tiered"))
}

/// 按 id 取**目录条目**（远程清单优先，其次内置兜底）。
///
/// 取值链：给定 id 直查 → 它映射出的上游真名再查一次。两个方向都需要：
/// 调用方可能拿着**对外 id**（内置兜底清单的键），也可能拿着**上游真名**
/// （远程目录的键，规格 §8.11 说明线上下发的可能是真名）。
pub fn entry(id: &str) -> Option<Value> {
    let trimmed = id.trim();
    if trimmed.is_empty() {
        return None;
    }
    let models = list();
    for candidate in [trimmed.to_string(), upstream_model_id(trimmed)] {
        if candidate.is_empty() {
            continue;
        }
        if let Some(item) = models
            .iter()
            .find(|item| item.get("id").and_then(Value::as_str) == Some(candidate.as_str()))
        {
            return Some(item.clone());
        }
    }
    None
}

/// 目录条目里的一个数值键（远程清单的 `thinkingBudget` / `maxOutputTokens`；
/// 内置兜底没有这些键 → None）
pub fn entry_number(id: &str, key: &str) -> Option<i64> {
    entry(id).and_then(|item| item.get(key).and_then(Value::as_i64))
}

/// 目录条目里的一个布尔键（`supportsThinking` / `supportsImages`）
pub fn entry_bool(id: &str, key: &str) -> Option<bool> {
    entry(id).and_then(|item| item.get(key).and_then(Value::as_bool))
}

/// 内置兜底清单（规格 §5.2 的 Gemini id **逐字** + §5.3 的 Claude / GPT-OSS）。
///
/// 键是**对外的模型 id**（转发时要映射成上游真名，见模块头）；
/// 值是展示名（上游 `displayName` 拉不到时的界面文案，不影响转发）。
///
/// ── Claude / GPT-OSS 这几条为什么也要在这里 ──────────────────
/// 兜底清单是「远程目录一次都没拉到」时的唯一文案来源（首次启动、离线、
/// 静态兜底清单：远程目录**拉不到时**用的那一份，也是「新模型先能被选到」的
/// 保险。上游 4xx）。若只列 Gemini，刚装好还没刷过目录的用户在模型管理里就看不到
/// Claude —— 而他对这个功能的期待恰恰是「加了账号就该有 Claude」
/// （issue #288）。id 取自规格 §5.3 与 Manager 的 `CLAUDE_TO_GEMINI` 键集：
/// `claude-sonnet-4-6(-thinking)` / `claude-opus-4-6-thinking` /
/// `gpt-oss-120b-medium` 都是**上游真名**（三家走同一 v1internal 端点，
/// model 直接填这些 id，不经映射表改写）。
/// **旧代 Claude 不进兜底清单**（`claude-opus-4-5*` / `claude-3-5-sonnet*`）：
/// 它们在映射表里被重定向到 4.6，属于「客户端配置里的历史名字仍要能用」的
/// 兼容项，不是本家主动广告的模型。
///
/// ── gemini-4 家族（Argon / Carbon）为什么必须在这里 ──────────
/// 这一份是**唯一的静态清单**：目录探测一旦失败，界面上的模型就只剩它。
/// 上游已经下发了 gemini-4 家族，但本仓的清单里此前**一条 gemini-4 都没有**
/// —— 探测没通时用户就完全选不到这个模型，这正是「协议版本太老、用不了
/// gemini-4-argon」的直接表现。
///
/// ── 为什么是 `-high` 后缀而不是裸名（这条踩过坑）──────────
/// 完整 Go 源码 `D:\Work\CLIProxyAPI-main\internal\registry\models\models.json`
/// 的 `antigravity` 数组里，gemini-4 家族只有**两个 id**：
///
/// ```text
///   gemini-4-argon-high    display_name: "Gemini 4 Argon"    description: "Gemini 4 Argon (High)"
///   gemini-4-carbon-high   display_name: "Gemini 4 Carbon"   description: "Gemini 4 Carbon (High)"
/// ```
///
/// **裸名 `gemini-4-argon` 属于 `gemini` 与 `vertex` 两家的清单，不属于
/// antigravity。** 往本家广告裸名会让用户选中一个上游不认的 id，直接 404
/// （实测 `gemini-4-argon` 与 `gemini-4-argon-trial` 都 404）。
///
/// 两个 `-high` 条目的注册表元数据（决定本文件的 supportsThinking /
/// maxOutputTokens 取值）：
///
/// ```text
///   context_length: 1048576   max_completion_tokens: 1048576
///   thinking: { min: 1, max: 65535, dynamic_allowed: true,
///               levels: ["low", "medium", "high"] }
///   supportedInputModalities: ["text", "image", "audio", "video"]
/// ```
///
/// 注意 `thinking.levels` 非空 —— 这是**新式档位模型**，上游要的是
/// `thinkingLevel: "high"` 字符串而不是 `thinkingBudget: <数字>`
/// （Go `internal/thinking/provider/antigravity/apply.go` 的 `applyLevelFormatDoc`）。
/// 发送侧的适配见 `protocol::antigravity_outbound` 的 `thinking_level`。
///
/// 只收录参考实现里**出现过确切名字**的 id，不自行发明 `-low` / `-thinking`
/// 之类变体：猜错的后缀会让上游 404，比不广告更糟。
const FALLBACK_MODELS: [(&str, &str); 31] = [
    ("gemini-4-argon-high", "Gemini 4 Argon"),
    ("gemini-4-carbon-high", "Gemini 4 Carbon"),
    ("gemini-3-flash", "Gemini 3 Flash"),
    ("gemini-3.5-flash", "Gemini 3.5 Flash"),
    ("gemini-3.5-flash-high", "Gemini 3.5 Flash High"),
    ("gemini-3.5-flash-low", "Gemini 3.5 Flash Low"),
    ("gemini-3.5-flash-extra-low", "Gemini 3.5 Flash Extra Low"),
    ("gemini-3.6-flash", "Gemini 3.6 Flash"),
    ("gemini-3.7-flash", "Gemini 3.7 Flash"),
    ("gemini-3.8-flash", "Gemini 3.8 Flash"),
    ("gemini-3.7-flash-low", "Gemini 3.7 Flash Low"),
    ("gemini-3.7-flash-medium", "Gemini 3.7 Flash Medium"),
    ("gemini-3.7-flash-high", "Gemini 3.7 Flash High"),
    ("gemini-3.1-pro-low", "Gemini 3.1 Pro Low"),
    ("gemini-3.1-pro-high", "Gemini 3.1 Pro High"),
    ("gemini-pro-agent", "Gemini Pro Agent"),
    ("gemini-3.1-pro-preview", "Gemini 3.1 Pro Preview"),
    ("gemini-3-pro-low", "Gemini 3 Pro Low"),
    ("gemini-3-pro-high", "Gemini 3 Pro High"),
    ("gemini-3-pro-preview", "Gemini 3 Pro Preview"),
    ("gemini-2.5-flash", "Gemini 2.5 Flash"),
    ("gemini-2.5-flash-lite", "Gemini 2.5 Flash Lite"),
    ("gemini-2.5-flash-thinking", "Gemini 2.5 Flash Thinking"),
    ("gemini-2.0-flash", "Gemini 2.0 Flash"),
    ("gemini-2.0-flash-exp", "Gemini 2.0 Flash Exp"),
    ("gemini-3-pro-image", "Gemini 3 Pro Image"),
    ("gemini-3.1-flash-image", "Gemini 3.1 Flash Image"),
    ("claude-sonnet-4-6", "Claude Sonnet 4.6"),
    ("claude-sonnet-4-6-thinking", "Claude Sonnet 4.6 Thinking"),
    ("claude-opus-4-6-thinking", "Claude Opus 4.6 Thinking"),
    ("gpt-oss-120b-medium", "GPT-OSS 120B Medium"),
];

/// 进程内缓存（首次访问时从落盘缓存读回）
struct CatalogState {
    models: Vec<Value>,
    fetched_at: i64,
    /// 这份清单是不是**远程拉到**的（落盘缓存装回来的也算 —— 它当初就是远程的）
    remote: bool,
}

static STATE: OnceLock<Mutex<Option<CatalogState>>> = OnceLock::new();

/// 取状态句柄（毒锁按「继续用」处理：这份缓存是可重建的展示数据，
/// 不值得让进程挂掉）
fn state() -> &'static Mutex<Option<CatalogState>> {
    STATE.get_or_init(|| Mutex::new(None))
}

/// 在锁内执行一段取值（毒锁按「继续用」处理 —— 这份缓存可重建）
fn with_state<R>(f: impl FnOnce(&mut Option<CatalogState>) -> R) -> R {
    let mutex = state();
    let mut guard = mutex.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    f(&mut guard)
}

/// 这个 id 是不是本家对外提供的模型：**三个家族**（Gemini / Claude / GPT-OSS）。
///
/// 判据是**前缀白名单**（不是「排除已知的黑名单」）：上游将来再下发别的家族
/// （veo 之类）时，默认仍是「不接」，而不是误广告一个没实现的通道。
/// 三个前缀的出处见模块头：Gemini 是原生家族，Claude 与 GPT-OSS 是同端点下发的
/// 第三方模型（规格 §5.3）。
pub fn is_offered_model(id: &str) -> bool {
    let lowered = id.trim().to_ascii_lowercase();
    lowered.starts_with("gemini-") || lowered.starts_with("claude-") || lowered.starts_with("gpt-oss-")
}

/// 这个 id 是不是 Claude 家族（判据取**上游真名**，见 `adapter::build_chat_request`
/// 的调用点）。
///
/// 唯一消费方是「要不要带 `anthropic-beta`」（规格 §5.3：那个头仅 Claude）。
/// 与 [`is_offered_model`] 同一前缀判法 —— 家族的认定在对外 id 与上游真名上
/// 逐字相同（映射表只改中间的版本段，不改前缀）。
pub fn is_claude_model(id: &str) -> bool {
    id.trim().to_ascii_lowercase().starts_with("claude-")
}

/// 该 id 是否支持思考（兜底清单的判据；远程清单用上游自己的 `supportsThinking`）。
///
/// - **Gemini**：3 系与 4 系全体 + 名字里带 `thinking` 的（2.5 那一支）给 true；
///   其余（2.0、2.5 普通档）保守 false。
/// - **Claude**：本家在 Antigravity 下提供的 Claude 全部支持 extended thinking
///   （`claude-sonnet-4-6` 与 `-thinking` 变体、`claude-opus-4-6-thinking`；
///   规格 §5.3 与 Manager 的 `SPEC_CLAUDE_*` 都给 1024 起的思考预算）。带
///   `-thinking` 后缀的更是从名字就能看出来。
/// - **GPT-OSS**：`gpt-oss-120b-medium` 是推理模型（Manager
///   `SPEC_GPT_OSS_120B` 给 8192 预算），故 true。
///
/// ── 为什么要把 4 系单列出来 ──────────────────────────────────
/// 原先只判 `gemini-3`，于是 `gemini-4-argon` 这类新模型会落进 false 分支 ——
/// 界面不给思考档开关、`reasoning_patch` 也无从下手。4 系与 3 系是同一代
/// 推理架构的延伸（上游目录里的 `supportsThinking` 才是权威值，这里只是
/// **目录没给时**的兜底），按家族前缀判比按具体版本号判更不容易漏。
fn fallback_thinking_supported(id: &str) -> bool {
    let lowered = id.to_ascii_lowercase();
    if lowered.starts_with("claude-") || lowered.starts_with("gpt-oss-") {
        return true;
    }
    lowered.starts_with("gemini-3")
        || lowered.starts_with("gemini-4")
        || lowered.contains("pro-agent")
        || lowered.contains("thinking")
}

/// 兜底清单里的「是否推荐为默认」：规格 §5.2 把 `gemini-3-flash` 标为推荐入口
fn fallback_is_default(id: &str) -> bool {
    id == "gemini-3-flash"
}

/// 兜底清单里的**档位模型**（`thinkingLevel` 字符串格式的那一族）。
///
/// ── 为什么 gemini-4 家族是档位模型而不是预算模型 ────────────
/// 上游的思考配置有两种互斥形态，由模型自己在注册表里声明：
///
/// ```text
///   预算格式   thinking: { min: 1, max: 65535, dynamic_allowed: true }
///              → 客户端发 thinkingBudget: <数字>
///   档位格式   thinking: { ..., levels: ["low","medium","high"] }
///              → 客户端发 thinkingLevel: "high"
/// ```
///
/// `gemini-4-argon-high` 与 `gemini-4-carbon-high` 的注册表条目
/// （`D:\Work\CLIProxyAPI-main\internal\registry\models\models.json`）都带
/// `levels: ["low","medium","high"]`，因此属于**档位格式**。Go 的
/// `internal/thinking/provider/antigravity/apply.go:82` 正是按
/// `config.Mode == ModeLevel`（= `len(support.Levels) > 0`）分流到
/// `applyLevelFormatDoc` 的。
///
/// 远程清单会在条目里带 `thinkingLevels`（见 [`map_entry`] 对
/// `thinking.levels` 的搬运），所以这里只负责**兜底清单**那 31 条 —— 目录
/// 拉不到时仍然知道 gemini-4 该发档位格式。
///
/// 返回的数组按**从低到高**排列，`last()` 即最高档。
pub fn fallback_thinking_levels(id: &str) -> &'static [&'static str] {
    let lowered = id.trim().to_ascii_lowercase();
    if lowered.starts_with("gemini-4-") {
        return &["low", "medium", "high"];
    }
    &[]
}

/// 该模型支持的思考档位（远程条目优先，兜底清单其次）；空 = 走预算格式。
///
/// 远程清单的 `thinkingLevels` 是权威值（上游自己声明的 `levels`）；
/// 拿不到才回落 [`fallback_thinking_levels`]。
pub fn thinking_levels(id: &str) -> Vec<String> {
    if let Some(item) = entry(id) {
        if let Some(levels) = item.get("thinkingLevels").and_then(Value::as_array) {
            let collected: Vec<String> = levels
                .iter()
                .filter_map(Value::as_str)
                .map(|level| level.trim().to_ascii_lowercase())
                .filter(|level| !level.is_empty())
                .collect();
            if !collected.is_empty() {
                return collected;
            }
        }
    }
    fallback_thinking_levels(id)
        .iter()
        .map(|level| (*level).to_string())
        .collect()
}

/// 目录条目**没给** `thinkingBudget` 时的家族默认预算（0 = 不注入
/// `thinkingConfig`，见 `protocol::antigravity_outbound` 的 `thinking_budget`）。
///
/// 三档各有出处，**不要统一成一个数**：
///   · **Gemini**：`None` → 调用方回落到 [`DEFAULT_THINKING_BUDGET`]（32768，
///     规格 §3.3 官方客户端样例值）；
///   · **Claude**：`Some(1024)`。Manager `SPEC_CLAUDE_SONNET_46` /
///     `SPEC_CLAUDE_OPUS_46` 都写 1024，注释说明这是 Anthropic SDK 的规范最小值
///     —— **不能沿用 Gemini 的 32768**，Claude 的思考预算与输出预算是同一池子，
///     给大了会把回答挤没（实测口径见 Manager 的 `infer_tier`：`1024` 是
///     Anthropic 默认档，不是「最低档」）；
///   · **GPT-OSS**：`Some(8192)`（Manager `SPEC_GPT_OSS_120B` 逐字）。
pub fn fallback_thinking_budget(id: &str) -> Option<i64> {
    let lowered = id.trim().to_ascii_lowercase();
    if lowered.starts_with("claude-") {
        return Some(1_024);
    }
    if lowered.starts_with("gpt-oss-") {
        return Some(8_192);
    }
    None
}

/// 把一个上游目录条目映射成聚合层认的形态。
///
/// 键名对照 `core/models/shape.rs::list_item`：`id` / `name` /
/// `maxInputTokens` / `maxOutputTokens` / `supportsImages` / `supportsVideo` /
/// `supportsReasoning` / `supportsToolCall` / `isDefault`。
/// 另有三个**非聚合层**的键（聚合层原样忽略未知键）：`quota`（规格 §5 的
/// `remainingFraction` / `resetTime`）、`supportsThinking`、`thinkingBudget` ——
/// 留给下一步做思考档映射与界面配额显示。
fn map_entry(id: &str, info: &Value) -> Option<Value> {
    if !is_offered_model(id) {
        return None;
    }
    let display_name = info
        .get("displayName")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|text| !text.is_empty())
        .unwrap_or(id);
    let mut item = Map::new();
    item.insert("id".to_string(), Value::String(id.to_string()));
    item.insert("name".to_string(), Value::String(display_name.to_string()));
    let image_generation = super::image_generation::is_image_model(id);
    if image_generation {
        item.insert("kind".to_string(), Value::String("image".to_string()));
        item.insert("output_modalities".to_string(), serde_json::json!(["image"]));
        item.insert("supports_image_editing".to_string(), Value::Bool(true));
    }
    item.insert("supportsToolCall".to_string(), Value::Bool(!image_generation));
    // 输入图片：目录有 `supportsImages` 就照它；没有（内置兜底 / 字段缺失）按
    // Gemini 家族的多模态能力给 true（规格 §4.3 的 `inlineData` 就是它）。
    // 视频位**没有依据**，一律 false（报错方向只能选「少报」）。
    item.insert(
        "supportsImages".to_string(),
        Value::Bool(
            info.get("supportsImages")
                .and_then(Value::as_bool)
                .unwrap_or(true),
        ),
    );
    item.insert("supportsVideo".to_string(), Value::Bool(false));
    let thinking = info
        .get("supportsThinking")
        .and_then(Value::as_bool)
        .unwrap_or_else(|| fallback_thinking_supported(id));
    item.insert("supportsReasoning".to_string(), Value::Bool(thinking));
    item.insert("supportsThinking".to_string(), Value::Bool(thinking));
    item.insert(
        "isDefault".to_string(),
        Value::Bool(
            !image_generation && info.get("recommended")
                .and_then(Value::as_bool)
                .unwrap_or_else(|| fallback_is_default(id)),
        ),
    );
    for (source, target) in [("maxTokens", "maxInputTokens"), ("maxOutputTokens", "maxOutputTokens")] {
        if let Some(value) = info.get(source).and_then(Value::as_i64) {
            if value > 0 {
                item.insert(target.to_string(), Value::from(value));
            }
        }
    }
    if let Some(budget) = info.get("thinkingBudget").and_then(Value::as_i64) {
        if budget > 0 {
            item.insert("thinkingBudget".to_string(), Value::from(budget));
        }
    } else if let Some(budget) = fallback_thinking_budget(id) {
        // 上游**没给** budget 时的家族默认档（Claude 1024 / GPT-OSS 8192，
        // 出处见 [`fallback_thinking_budget`]）。写进条目而不是留在发送侧判断：
        // `protocol::antigravity_outbound` 的取值链本来就是「条目 → 家族默认」，
        // 这里补上之后那条链对三家是同一条，发送侧不必认识家族名。
        // Gemini 不走这一支（返回 None）—— 它的兜底 32768 在发送侧，
        // 且那个值对 Claude 是错的。
        item.insert("thinkingBudget".to_string(), Value::from(budget));
    }
    // 思考档位（`thinking.levels`）：非空说明这是**档位格式**模型，
    // 发送侧要发 `thinkingLevel: "<档位>"` 而不是 `thinkingBudget: <数字>`。
    // 见 [`thinking_levels`] 与 `protocol::antigravity_outbound::thinking_level`。
    //
    // 上游的字段名是 `thinking.levels`（`models.json` 的注册表条目形态）；
    // 这里同时接受扁平的 `thinkingLevels`，因为远程 `fetchAvailableModels`
    // 的条目形态与注册表不完全一致，两种都见过。
    let levels = info
        .pointer("/thinking/levels")
        .and_then(Value::as_array)
        .or_else(|| info.get("thinkingLevels").and_then(Value::as_array));
    if let Some(levels) = levels {
        let collected: Vec<Value> = levels
            .iter()
            .filter_map(Value::as_str)
            .map(|level| level.trim().to_ascii_lowercase())
            .filter(|level| !level.is_empty())
            .map(Value::String)
            .collect();
        if !collected.is_empty() {
            item.insert("thinkingLevels".to_string(), Value::Array(collected));
        }
    }
    // 配额（规格 §5 / §5.4）：原样搬运 `remainingFraction` 与 `resetTime`
    if let Some(quota) = info.get("quotaInfo") {
        if quota.is_object() {
            item.insert("quota".to_string(), quota.clone());
        }
    }
    // 可见性：上游目录是**超集**，官方客户端只展示其中一部分。
    // 上游自报的内部模型（`isInternal`）优先 —— 那个标记比世代判据更直接。
    let visibility = if is_internal_entry(info) {
        "hidden"
    } else {
        visibility_of(id)
    };
    item.insert(
        "visibility".to_string(),
        Value::String(visibility.to_string()),
    );
    Some(Value::Object(item))
}

/// 上游 `isInternal` 显式标记的内部模型直接算不可见。
///
/// 上游目录里有这个字段（9router / 10router 的解析器都用它过滤，
/// `Acankao/9router/src/app/api/providers/[id]/models/route.js:44`），但
/// 它**不覆盖** 2.5 / 2.0 那批 —— 那批带的是正常的 `quotaInfo` 与
/// `displayName`，只是官方选择器不列。所以两个判据要并用。
fn is_internal_entry(info: &Value) -> bool {
    info.get("isInternal").and_then(Value::as_bool).unwrap_or(false)
}

/// 该 id 在**官方客户端里是否可见**（`"shown"` / `"hidden"` / `"undeclared"`）。
///
/// ── 判据为什么是「世代」而不是「上游说了什么」──────────────────
/// 官方 Antigravity 文档的模型选择器只列 9 条（Gemini 3.8 / 3.7 / 3.6 Flash、
/// Gemini 3.1 Pro、Claude Sonnet 5.5 / Opus 5.5 / Sonnet 4.6 / Opus 4.6、
/// GPT-OSS-120b；<https://antigravity.google/docs/models>）。而
/// `fetchAvailableModels` 下发的是**全量静态目录** —— Manager 实测免费号与
/// Pro 号都拿到**同样的 33 个**模型（`Acankao/Antigravity-Manager/
/// src-tauri/src/models/quota.rs:203`），9router / 10router 的「重要模型清单」
/// 同样不含 2.5 / 2.0 系列（`open-sse/services/usage/google.js:171-186`）。
/// 2.5 那一支在本家是**后台任务**的降级模型（Manager 的标题生成 / 摘要用它），
/// 不是给用户选的。
///
/// 因此：`gemini-2.x` 与 `gemini-2.0-flash-exp` 一律 `hidden`；其余
/// `gemini-3*` / `claude-*` / `gpt-oss-*` 都是 `shown`。**只按世代判**，
/// 不按具体 id 列白名单 —— 上游加了新的 3.x 时不用改这里。
///
/// `undeclared` 留给「上游条目自己说不清」的情形（当前没用上；语义与
/// Trae 的「缺省 = 可见」同一纪律：没有依据就不下判断）。
fn visibility_of(id: &str) -> &'static str {
    let lowered = id.trim().to_ascii_lowercase();
    // `gemini-2.5-*` / `gemini-2.0-*`：官方选择器不列（见上面论证）
    if lowered.starts_with("gemini-2.") {
        return "hidden";
    }
    if lowered.starts_with("gemini-") || lowered.starts_with("claude-") || lowered.starts_with("gpt-oss-") {
        return "shown";
    }
    "undeclared"
}

/// 解析 `fetchAvailableModels` 的响应：`{models: {"<id>": {…}}}`。
///
/// 也接受 `models` 是**数组**的形态（防御性：字段形态若变，至少不整份丢），
/// 数组里的条目要从自己的 `id` 字段取名字。
pub fn parse_models(payload: &Value) -> Vec<Value> {
    let Some(models) = payload.get("models") else {
        return Vec::new();
    };
    if let Some(rows) = models.as_array() {
        return rows
            .iter()
            .filter_map(|row| {
                let id = row
                    .get("id")
                    .and_then(Value::as_str)
                    .map(str::trim)
                    .filter(|text| !text.is_empty())?;
                map_entry(id, row)
            })
            .collect();
    }
    let Some(object) = models.as_object() else {
        return Vec::new();
    };
    object
        .iter()
        .filter_map(|(id, info)| map_entry(id, info))
        .collect()
}

/// 内置兜底清单的聚合层形态（永远非空）。
///
/// 条目本体走 [`map_entry`]（能力位的默认值与兜底判据只有一份），展示名用
/// [`FALLBACK_MODELS`] 里那份人读的名字（远程拉不到时这是界面上唯一的文案）。
fn fallback_models() -> Vec<Value> {
    FALLBACK_MODELS
        .iter()
        .filter_map(|(id, name)| {
            let mut item = map_entry(id, &Value::Null)?;
            if let Some(object) = item.as_object_mut() {
                object.insert("name".to_string(), Value::String((*name).to_string()));
            }
            Some(item)
        })
        .collect()
}

/// 当前模型清单（内存 → 落盘缓存 → 内置兜底；永远非空）
pub fn list() -> Vec<Value> {
    with_state(|slot| {
        slot.as_ref()
            .map(|state| state.models.clone())
            .filter(|models| !models.is_empty())
            .unwrap_or_else(fallback_models)
    })
}

/// 这份清单是否来自**远程拉取**（`catalog::refresh_meta` 的「来源」列判据）
pub fn remote_refreshed() -> bool {
    with_state(|slot| slot.as_ref().map(|state| state.remote).unwrap_or(false))
}

/// 最近一次成功刷新的时刻（毫秒；没刷过为 0）—— 界面「更新日期」列读它
pub fn last_refreshed_at() -> i64 {
    with_state(|slot| slot.as_ref().map(|state| state.fetched_at).unwrap_or(0))
}

/// 一次目录请求的中间结果（供环境轮询判断要不要换下一条基址）
enum Attempt {
    /// 拿到了可用清单
    Models(Vec<Value>),
    /// 这次不成（原因），可以换下一条基址
    Retry(String),
    /// 这次不成，且换域名也没用（4xx 之外的确定失败）
    Fatal(String),
}

/// 打一次目录请求（单条基址）。
///
/// ── 与 Go 参考实现逐字对齐的三处 ────────────────────────────
///   1. **只发三个头**（[`endpoints::probe_headers`]）：Content-Type /
///      Authorization / User-Agent，UA 是 Hub 家族的
///      `antigravity/hub/{ver} {os}/{arch}`。不发 `x-client-name` /
///      `x-client-version` / `x-goog-user-project` / `x-goog-api-client`；
///   2. **project 只放在请求体里**（body 只有一个 `project` 键，没 project 时
///      就是空对象 `{}`），不转成头；
///   3. 401/403 视作**账号级**失败，不再换域名白撞（参考实现把它归成
///      AuthError）；429/5xx 才换下一条基址。
async fn fetch_once(
    base: &str,
    access_token: &str,
    project_id: &str,
    proxy: Option<&ResolvedProxy>,
) -> Attempt {
    let url = endpoints::fetch_available_models_url(base);
    let body = if project_id.trim().is_empty() {
        json!({})
    } else {
        json!({ "project": project_id.trim() })
    };
    let response = match send_probe_json(&url, access_token, &body, proxy).await {
        Ok(response) => response,
        Err(reason) => return Attempt::Retry(reason),
    };
    if response.status == 401 || response.status == 403 {
        // 账号级失败：换环境也是同一个 token，白撞一次只会多一条日志。
        // 403 在参考实现里同样归 AuthError（鉴权/权限问题，不是环境差异）。
        let detail = upstream_message(&response.payload);
        let summary = if detail.is_empty() {
            format!("目录接口返回 HTTP {}", response.status)
        } else {
            format!("目录接口返回 HTTP {}：{detail}", response.status)
        };
        return Attempt::Fatal(summary);
    }
    if (200..300).contains(&response.status) {
        return parse_payload(&response.payload);
    }
    let detail = upstream_message(&response.payload);
    let summary = if detail.is_empty() {
        format!("目录接口返回 HTTP {}", response.status)
    } else {
        format!("目录接口返回 HTTP {}：{detail}", response.status)
    };
    // 429 / 5xx 换下一条基址；其余 4xx 是请求本身的问题，换域名白撞
    if response.status == 429 || response.status >= 500 {
        Attempt::Retry(summary)
    } else {
        Attempt::Fatal(summary)
    }
}

/// 一次 HTTP 结果（目录请求只需要状态 + 解析后的 body）。
///
/// `pub(super)`：`balance.rs` 的额度摘要复用同一条请求口径 —— 同一台主机
/// （v1internal 的同一组基址）、同一组头、同一超时；两处各写一份必然分叉。
pub(super) struct HttpOutcome {
    pub(super) status: u16,
    pub(super) payload: Value,
}

/// 发一次**目录探测** JSON POST：只有三个头（[`endpoints::probe_headers`]）。
///
/// 与 [`send_json`] 分开是刻意的：那个是「非 content 方法」的通用口径
/// （IDE 家族 UA + `x-goog-user-project`），额度摘要与 project 发现仍用它；
/// 而目录探测必须逐字对齐 Go 参考实现的三头形态，否则上游给的指纹对不上
/// （详见 [`fetch_once`] 的注释）。
async fn send_probe_json(
    url: &str,
    access_token: &str,
    body: &Value,
    proxy: Option<&ResolvedProxy>,
) -> Result<HttpOutcome, String> {
    let client = super::client_for(proxy);
    let headers = endpoints::probe_headers(access_token);
    let mut builder = client
        .post(url)
        .header("Accept", "application/json")
        .timeout(Duration::from_millis(REQUEST_TIMEOUT_MS));
    for (key, value) in &headers {
        builder = builder.header(key, value);
    }
    let response = builder
        .body(body.to_string())
        .send()
        .await
        .map_err(|error| egress::describe_chain(&error))?;
    let status = response.status().as_u16();
    let text = response.text().await.unwrap_or_default();
    let payload: Value = serde_json::from_str(&text).unwrap_or(Value::Null);
    Ok(HttpOutcome { status, payload })
}

/// 发一次 JSON POST（头集合与超时统一在这里）。
///
/// `pub(super)`：`balance.rs` 的额度摘要直接复用它 —— 同一台主机、同一组头、
/// 同一超时，两处各写一份必然分叉（该文件不再自建请求口径）。
pub(super) async fn send_json(
    url: &str,
    access_token: &str,
    project_id: &str,
    body: &Value,
    proxy: Option<&ResolvedProxy>,
) -> Result<HttpOutcome, String> {
    // 本家统一的出口口径：账号显式配了代理就用它，否则跟随系统代理
    // （理由见 `super::client_for` 的文档）
    let client = super::client_for(proxy);
    let headers = endpoints::admin_headers(access_token, project_id);
    let mut builder = client
        .post(url)
        .header("Accept", "application/json")
        .timeout(Duration::from_millis(REQUEST_TIMEOUT_MS));
    for (key, value) in &headers {
        builder = builder.header(key, value);
    }
    let response = builder
        .body(body.to_string())
        .send()
        .await
        .map_err(|error| egress::describe_chain(&error))?;
    let status = response.status().as_u16();
    let text = response.text().await.unwrap_or_default();
    let payload: Value = serde_json::from_str(&text).unwrap_or(Value::Null);
    Ok(HttpOutcome { status, payload })
}

/// 成功响应 → 清单。
///
/// 空清单（或一个 Gemini 都没有）算**「这次没拿到」而不是「这次拿到了空目录」**：
/// 环境基址之间可能有差异（某个环境对该账号限流 / 尚未同步），换下一条再试一次
/// 比直接把「空目录」当成结论更稳 —— 三条都空时最终仍会如实报失败并保留现有清单。
fn parse_payload(payload: &Value) -> Attempt {
    let models = parse_models(payload);
    if models.is_empty() {
        return Attempt::Retry("目录接口返回的清单为空或不含可识别的模型".to_string());
    }
    Attempt::Models(models)
}

/// 上游错误文案（`error.message` / `message` 兜底）
fn upstream_message(payload: &Value) -> String {
    payload
        .get("error")
        .and_then(|error| error.get("message"))
        .and_then(Value::as_str)
        .or_else(|| payload.get("message").and_then(Value::as_str))
        .map(str::trim)
        .unwrap_or("")
        .to_string()
}

/// 拉一次模型目录并落地（内存 + 持久化缓存）。
///
/// `force = false`（自动路径）时 10 分钟 TTL 内早退为 `unchanged()`；
/// `force = true`（用户手动刷新）真打上游。
///
/// 失败时**保留现有清单**（远程清单优先，其次内置兜底）并返回 `failed(原因)`：
/// 手动路径据此如实汇报，自动路径只打日志。
pub async fn refresh(
    access_token: &str,
    project_id: &str,
    proxy: Option<&ResolvedProxy>,
    force: bool,
) -> ModelRefreshOutcome {
    let now = crate::logging::now_ms();
    if !force {
        let fresh = with_state(|slot| {
            slot.as_ref()
                .map(|state| state.remote && now - state.fetched_at < TTL_MS)
                .unwrap_or(false)
        });
        if fresh {
            return ModelRefreshOutcome::unchanged();
        }
    }
    if access_token.trim().is_empty() {
        return ModelRefreshOutcome::failed(
            "Antigravity 账号没有可用的 access token（无法拉取模型目录）",
        );
    }
    let mut last_error = String::new();
    // 目录这条链路用 `MODEL_CATALOG_BASE_URLS`（daily → prod → sandbox），
    // **不是**聊天用的 `V1_BASE_URLS`（sandbox 优先）：sandbox 是预发环境，
    // 清单可能比 daily 旧，先打它会把旧清单当成权威结果缓存 10 分钟。
    for base in endpoints::MODEL_CATALOG_BASE_URLS {
        match fetch_once(base, access_token, project_id, proxy).await {
            Attempt::Models(models) => {
                let count = models.len();
                with_state(|slot| {
                    *slot = Some(CatalogState {
                        models: models.clone(),
                        fetched_at: now,
                        remote: true,
                    });
                });
                return ModelRefreshOutcome::refreshed(count);
            }
            Attempt::Retry(reason) => {
                last_error = reason;
                crate::logging::verbose(
                    "[Models]",
                    &format!("Antigravity 目录换下一个环境重试（{base}）：{last_error}"),
                );
            }
            Attempt::Fatal(reason) => {
                return ModelRefreshOutcome::failed(format!("{reason}（保留现有清单）"));
            }
        }
    }
    let detail = if last_error.is_empty() {
        "所有环境均不可用".to_string()
    } else {
        last_error
    };
    ModelRefreshOutcome::failed(format!(
        "Antigravity 模型目录刷新失败：{detail}（保留现有清单）"
    ))
}

/// 模型目录刷新结果（协议里的 `RefreshOutcome` 的本地别名）。
///
/// 名字沿用网关那份，是为了让搬来的 `refresh` 逐字不动（它的返回值形态
/// `unchanged / refreshed / failed` 与协议一一对应）。
pub use agent2api_provider_protocol::RefreshOutcome as ModelRefreshOutcome;

#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// 兜底清单里必须看得见 gemini-4 家族 —— 这是「界面上选不到 gemini-4-argon」
    /// 的直接判据：探测没通时用户只剩这份清单，它没有就等于完全没有。
    ///
    /// **必须是 `-high` 后缀的两个 id**：完整 Go 源码
    /// `internal/registry/models/models.json` 的 antigravity 数组里只有
    /// `gemini-4-argon-high` 与 `gemini-4-carbon-high`，裸名属于 gemini / vertex
    /// 两家（广告裸名 = 让用户选中一个上游不认的 id → 404）。
    #[test]
    fn the_fallback_catalog_offers_the_gemini_4_family() {
        let models = fallback_models();
        let ids: Vec<&str> = models
            .iter()
            .filter_map(|item| item.get("id").and_then(Value::as_str))
            .collect();
        assert!(
            ids.contains(&"gemini-4-argon-high"),
            "兜底清单缺 gemini-4-argon-high：{ids:?}"
        );
        assert!(ids.contains(&"gemini-4-carbon-high"), "兜底清单缺 gemini-4-carbon-high");
        // 裸名不属于本家，绝不能出现（会 404）
        assert!(
            !ids.contains(&"gemini-4-argon"),
            "兜底清单不该广告裸名 gemini-4-argon（那是 gemini/vertex 的 id）"
        );
    }

    /// gemini-4 家族的条目要能被界面正常展示（不是 hidden、不是 undeclared）。
    #[test]
    fn a_gemini_4_entry_is_shown_and_carries_its_metadata() {
        let entry = entry("gemini-4-argon-high").expect("gemini-4-argon-high 应在清单里");
        assert_eq!(entry["id"], json!("gemini-4-argon-high"));
        assert_eq!(entry["name"], json!("Gemini 4 Argon"));
        assert_eq!(entry["visibility"], json!("shown"));
        assert_eq!(entry["supportsThinking"], json!(true));
        assert_eq!(entry["supportsReasoning"], json!(true));
        assert_eq!(entry["supportsToolCall"], json!(true));
    }

    /// 思考档位要认 gemini-4（原先只判 gemini-3，4 系会落进 false）。
    #[test]
    fn thinking_is_supported_for_the_gemini_4_family() {
        assert!(fallback_thinking_supported("gemini-4-argon-high"));
        assert!(fallback_thinking_supported("gemini-4-carbon-high"));
        // 家族判据不应误伤别家
        assert!(fallback_thinking_supported("claude-sonnet-4-6"));
        assert!(fallback_thinking_supported("gpt-oss-120b-medium"));
    }

    /// gemini-4 家族是**档位格式**模型（`thinkingLevel` 字符串），
    /// 老式 gemini-3 是预算格式（`thinkingBudget` 数字）。
    ///
    /// 判据出处：注册表里 gemini-4 的 `thinking.levels = ["low","medium","high"]`，
    /// Go 的 `applyLevelFormatDoc` 按 `len(Levels) > 0` 分流。
    #[test]
    fn the_gemini_4_family_uses_level_thinking() {
        assert_eq!(
            fallback_thinking_levels("gemini-4-argon-high"),
            &["low", "medium", "high"]
        );
        assert_eq!(
            fallback_thinking_levels("gemini-4-carbon-high"),
            &["low", "medium", "high"]
        );
        // 兜底清单条目上也要能读到（发送侧走 entry 查，不是查常量）
        assert_eq!(
            thinking_levels("gemini-4-argon-high"),
            vec!["low".to_string(), "medium".to_string(), "high".to_string()]
        );
        // 老式预算模型没有档位，发送侧要回落到 thinkingBudget
        assert!(thinking_levels("gemini-3-flash").is_empty());
        assert!(thinking_levels("claude-sonnet-4-6").is_empty());
    }

    /// 远程条目带 `thinking.levels` 时要搬成 `thinkingLevels`（上游权威值优先）。
    #[test]
    fn a_remote_entry_can_declare_its_thinking_levels() {
        let parsed = parse_models(&json!({
            "models": {
                "gemini-4-argon-high": {
                    "displayName": "Gemini 4 Argon",
                    "thinking": { "levels": ["LOW", "medium", " high "] }
                }
            }
        }));
        assert_eq!(parsed.len(), 1);
        assert_eq!(
            parsed[0]["thinkingLevels"],
            json!(["low", "medium", "high"]),
            "档位要小写去空白后原序搬运"
        );
    }

    /// gemini-4 不在别名表里，模型名必须原样透传给上游（不能凭猜测改写成
    /// `-tiered` 之类的后缀 —— 猜错就是 404）。
    #[test]
    fn a_gemini_4_model_id_passes_through_untouched() {
        assert_eq!(upstream_model_id("gemini-4-argon-high"), "gemini-4-argon-high");
        assert_eq!(upstream_model_id("gemini-4-carbon-high"), "gemini-4-carbon-high");
    }

    /// 远程目录里出现 gemini-4 时也要能落成条目（对象与数组两种形态）。
    #[test]
    fn a_remote_catalog_can_publish_the_gemini_4_family() {
        let object_form = json!({
            "models": {
                "gemini-4-argon-high": { "displayName": "Gemini 4 Argon", "recommended": true },
                "gemini-4-carbon-high": { "displayName": "Gemini 4 Carbon" }
            }
        });
        let parsed = parse_models(&object_form);
        assert_eq!(parsed.len(), 2);
        assert!(parsed.iter().any(|item| item["id"] == json!("gemini-4-argon-high")));

        let array_form = json!({
            "models": [{ "id": "gemini-4-argon-high" }]
        });
        let parsed = parse_models(&array_form);
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0]["id"], json!("gemini-4-argon-high"));
    }

    /// 目录探测请求必须走 Hub 家族的三头口径，且 project 只出现在请求体里。
    #[test]
    fn the_probe_headers_are_the_hub_family_three() {
        let headers = crate::providers::antigravity::endpoints::probe_headers("token-1");
        let names: Vec<&str> = headers.iter().map(|(name, _)| name.as_str()).collect();
        assert_eq!(
            names,
            vec!["Content-Type", "Authorization", "User-Agent"],
            "探测请求只该发这三个头：{names:?}"
        );
        // 不发这些（参考实现明确不发，发了就是另一套指纹）
        for banned in ["x-client-name", "x-client-version", "x-goog-user-project", "x-goog-api-client"] {
            assert!(
                !names.iter().any(|name| name.eq_ignore_ascii_case(banned)),
                "探测请求不该带 {banned}"
            );
        }
        let user_agent = headers
            .iter()
            .find(|(name, _)| name == "User-Agent")
            .map(|(_, value)| value.as_str())
            .unwrap_or_default();
        assert!(
            user_agent.to_ascii_lowercase().starts_with("antigravity/hub/"),
            "探测 UA 必须是 Hub 家族形态，实际 {user_agent}"
        );
        assert!(
            user_agent.contains("aidev_client"),
            "Hub UA 必须带 aidev_client 元数据段，实际 {user_agent}"
        );
    }

    /// **数据面**（聊天转发）的头集合也必须与探测一致：三个头、Hub 家族 UA。
    ///
    /// Go 的 `antigravity_executor_request.go:111-113` 只设 Content-Type /
    /// Authorization / User-Agent，UA 走 `misc.AntigravityUserAgent()`（Hub 家族）。
    /// 本仓原先数据面用 IDE 家族 UA + 两个 `x-client-*`，上游把它当老客户端，
    /// gemini-4 一律 404。
    #[test]
    fn the_content_headers_are_also_the_hub_family_three() {
        let headers = crate::providers::antigravity::endpoints::content_headers("token-1");
        let names: Vec<&str> = headers.iter().map(|(name, _)| name.as_str()).collect();
        assert_eq!(
            names,
            vec!["Content-Type", "Authorization", "User-Agent"],
            "数据面请求也只该发这三个头：{names:?}"
        );
        let user_agent = headers
            .iter()
            .find(|(name, _)| name == "User-Agent")
            .map(|(_, value)| value.as_str())
            .unwrap_or_default();
        assert!(
            user_agent.to_ascii_lowercase().starts_with("antigravity/hub/"),
            "数据面 UA 也必须是 Hub 家族，实际 {user_agent}"
        );
        // Claude 分支只多一个 anthropic-beta，其余不变
        let claude = crate::providers::antigravity::endpoints::claude_content_headers("token-1");
        let claude_names: Vec<&str> = claude.iter().map(|(name, _)| name.as_str()).collect();
        assert_eq!(
            claude_names,
            vec!["Content-Type", "Authorization", "User-Agent", "anthropic-beta"]
        );
    }

    /// Hub 版本号必须达到上游的 2.23.0 门槛，否则新模型一律 404。
    ///
    /// 出处：Go `internal/misc/antigravity_version.go` 的注释原文 ——
    /// 「Cloud Code rejects newer models for clients below 2.23.0, so this floor
    /// must stay at or above that version」，以及测试
    /// `TestAntigravityFallbackVersionMeetsBackendFloor`。
    #[test]
    fn the_hub_version_clears_the_backend_floor() {
        let version = crate::providers::antigravity::endpoints::HUB_VERSION;
        let mut parts = version.split('.');
        let major: u32 = parts.next().unwrap_or("0").parse().unwrap_or(0);
        let minor: u32 = parts.next().unwrap_or("0").parse().unwrap_or(0);
        assert!(
            major > 2 || (major == 2 && minor >= 23),
            "Hub 版本 {version} 低于上游 2.23.0 门槛，新模型会被 404"
        );
    }

    /// 已知版本的 Hub UA 要带对应的 changelist（Go `antigravityHubChangelists`）。
    #[test]
    fn the_hub_user_agent_carries_the_changelist() {
        let user_agent = crate::providers::antigravity::endpoints::hub_user_agent();
        // 2.29.0 → cl=1013060670（Go 常量表逐字）
        assert!(
            user_agent.contains("cl=1013060670"),
            "2.29.0 的 Hub UA 应带 cl=1013060670，实际 {user_agent}"
        );
        assert!(
            user_agent.contains("os_type=darwin; arch=arm64"),
            "Hub UA 应带 Go 的平台元数据段，实际 {user_agent}"
        );
    }

    /// 目录基址必须 daily 优先：sandbox 是预发环境，清单可能更旧。
    #[test]
    fn the_catalog_probe_tries_daily_before_sandbox() {
        let bases = crate::providers::antigravity::endpoints::MODEL_CATALOG_BASE_URLS;
        assert!(
            bases[0].contains("daily-cloudcode-pa.googleapis.com"),
            "目录探测第一条基址应是 daily，实际 {}",
            bases[0]
        );
        let sandbox = bases
            .iter()
            .position(|base| base.contains("sandbox"))
            .expect("sandbox 仍在备选里");
        assert!(sandbox > 0, "sandbox 不该排在第一条");
    }
}
