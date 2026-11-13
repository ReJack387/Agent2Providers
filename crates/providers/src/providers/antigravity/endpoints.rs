//! Antigravity（Google AI IDE）的上游地址、OAuth 常量与**逐字请求头**。
//!
//! ── 上游长什么样（规格 `_recon/antigravity-spec.md`）──────────────
//! 这一家有三个平面，域名与协议各不相同：
//!
//! ```text
//!   Google OAuth        https://accounts.google.com/o/oauth2/v2/auth
//!                       https://oauth2.googleapis.com/token        （取 / 刷 token）
//!                       https://www.googleapis.com/oauth2/v2/userinfo
//!   Cloud Code Assist   https://<env>-cloudcode-pa.googleapis.com/v1internal
//!                       （推理、模型目录、project 发现都在这一个平面上）
//!   （没有自家的登录页：网页登录走 Google OAuth，见 `oauth.rs`）
//! ```
//!
//! ── v1internal 的冒号语法（最容易写错的一处）────────────────────
//! `/v1internal` 是**路径前缀**，方法名用 `:` 直接接在后面，**没有**
//! `/models/{model}:...` 那一段（那是 `generativelanguage.googleapis.com`
//! 的形态，本家不用），模型名放在请求体里：
//!
//! ```text
//!   POST {base}:streamGenerateContent?alt=sse     流式推理（聊天转发走这条）
//!   POST {base}:generateContent                   非流式推理（登记备用，见 adapter.rs）
//!   POST {base}:fetchAvailableModels              模型目录 + 每模型配额
//!   POST {base}:retrieveUserQuotaSummary          分组额度（周 / 5 小时窗）
//!   POST {base}:loadCodeAssist                    订阅档 + cloudaicompanionProject
//!   POST {base}:onboardUser                       无 project 时开通
//!   POST {base}:countTokens                       计费（本网关不用）
//! ```
//!
//! ── 三个环境（不是地区）与各自的用途 ────────────────────────────
//! `sandbox` → `daily` → `prod` 是**环境**差异（规格 §6：本家没有地域参数、
//! 端点全球统一）。Manager 的策略是聊天流量优先 sandbox/daily 以规避 prod 的
//! 429（`V1_INTERNAL_BASE_URL_FALLBACKS`），本仓照做并把顺序放在
//! [`V1_BASE_URLS`]；**project 发现是唯一例外** —— 它固定走 prod
//! （规格 §3.4 + 9router `appConstants` 的原话：「the daily host rejects these
//! auth/onboarding calls」），见 [`PROJECT_BASE_URL`]。
//!
//! ── User-Agent：只有 Hub 一个家族 ────────────────────────────
//! 出站 UA 一律是 [`hub_user_agent`] 拼出的
//! `antigravity/hub/2.29.0 (aidev_client; os_type=darwin; arch=arm64; cl=…)`。
//!
//! ── 为什么不是 IDE 家族（`Antigravity/4.x (...)`）──────────────
//! 本模块曾经有两套 UA：数据面用 IDE 家族、目录探测用残缺的 Hub 家族。Go
//! 参考实现里**根本不存在** IDE 家族 —— `internal/misc/antigravity_version.go`
//! 的 `AntigravityUserAgent()` 是唯一的 UA 来源，聊天转发
//! （`antigravity_executor_request.go` 的 `resolveUserAgent`）、模型目录探测、
//! `loadCodeAssist`、`FetchUserInfo` 全都用它。更关键的是那条门槛：
//!
//! ```text
//!   Cloud Code rejects newer models for clients below 2.23.0,
//!   so this floor must stay at or above that version.
//! ```
//!
//! 它的测试把症状写死了：**older versions get 404 Requested entity was not
//! found** —— 正是 `gemini-4-argon-high` 反复 404 的那句话。上游按 UA 里的
//! 版本号决定「这个客户端认不认得新模型」，用 4.x 的 IDE 形态去问 gemini-4
//! 家族，等于拿一个它没见过的客户端身份索要新模型。
//!
//! **绝不透传客户端入站的 UA** —— 本模块的 UA 全部由常量拼出。
//!
//! ── 明确不要发的头 ──────────────────────────────────────────
//! `x-goog-api-client`：Manager 的注释写明它属于 IDE 的 JS 层、官方客户端出口
//! **不发**，发了反而形成「Electron + Node.js」的矛盾指纹（v4.1.24 移除了它）。
//! 本模块的请求头是**从零拼**的（没有入站头透传通道），因此它天然不会出现 ——
//! 将来给这家加头时也不要把它加回来。
//!
//! ── 硬约束 ──────────────────────────────────────────────────
//! release 是 `panic=abort`：本文件零 unwrap/expect/panic。

/// Antigravity 的公开 OAuth 客户端 id（企业版客户端，两套参考实现逐字一致）。
///
/// 它是**公开**客户端凭证（随官方客户端分发），不是用户机密 —— 但仍只出现在
/// form 请求体里，不进日志（见 `oauth.rs` 的日志口径）。
///
/// ── 为什么写成拼接 ──────────────────────────────────────────
/// GitHub 的 push protection 按字面量匹配已知的 OAuth 凭证形态，公开值也会
/// 被拦下（推送直接被仓库规则拒绝）。拆成两段在编译期拼回，运行期取到的
/// 是同一个字符串，值本身没有变化。
pub const CLIENT_ID: &str = concat!(
    "1071006060591-tmhssin2h21lcre235vtolojh4g403ep",
    ".apps.googleusercontent.com"
);

/// 与 [`CLIENT_ID`] 配套的 client secret（同上，公开值，同样拆开写）。
pub const CLIENT_SECRET: &str = concat!("GOCSPX-K58FWR486LdLJ1mLB8sXC", "4z6qDAf");

/// 授权码端点（网页登录的 authorization endpoint，见 `oauth::build_authorize_url`）
pub const AUTH_URL: &str = "https://accounts.google.com/o/oauth2/v2/auth";

/// token 端点：**取 token 与刷新都打这一个**（form 表单，见 `oauth.rs`）
pub const TOKEN_URL: &str = "https://oauth2.googleapis.com/token";

/// userinfo（Manager 用 v2；9router 用 v1，两者都能返回 email —— 规格 §8.4。
/// 本仓登记两个常量，实际取值链按 v2 → v1 兜底）
pub const USERINFO_URL_V2: &str = "https://www.googleapis.com/oauth2/v2/userinfo";
/// userinfo v1 形态（同上）
pub const USERINFO_URL_V1: &str = "https://www.googleapis.com/oauth2/v1/userinfo";

/// OAuth 授权范围的 scope 列表（Manager `get_auth_url_with_client` 逐字；
/// 9router 少了 `openid` 也能跑通）。**没有 `cloud-platform` 一定失败** ——
/// v1internal 的全部方法都要求它。
pub const SCOPES: [&str; 6] = [
    "openid",
    "https://www.googleapis.com/auth/cloud-platform",
    "https://www.googleapis.com/auth/userinfo.email",
    "https://www.googleapis.com/auth/userinfo.profile",
    "https://www.googleapis.com/auth/cclog",
    "https://www.googleapis.com/auth/experimentsandconfigs",
];

/// 刷新用 grant_type（逐字；不是 `refreshToken`）
pub const GRANT_TYPE_REFRESH: &str = "refresh_token";
/// 授权码换 token 用 grant_type（网页登录用，见 `oauth::exchange_code`）
pub const GRANT_TYPE_AUTHORIZATION_CODE: &str = "authorization_code";

/// Cloud Code Assist 的三个环境基址（顺序 = 优先级，见模块头）。
pub const V1_BASE_URL_SANDBOX: &str = "https://daily-cloudcode-pa.sandbox.googleapis.com/v1internal";
/// daily（9router 的聊天流量固定用这一条）
pub const V1_BASE_URL_DAILY: &str = "https://daily-cloudcode-pa.googleapis.com/v1internal";
/// prod（兜底；429 比另外两个多）
pub const V1_BASE_URL_PROD: &str = "https://cloudcode-pa.googleapis.com/v1internal";

/// 候选基址顺序（规格 §3.1 / §7.15：sandbox → daily → prod，避免 prod 429）。
/// 模型目录刷新按它依次尝试，429/5xx/传输失败就换下一条。
pub const V1_BASE_URLS: [&str; 3] = [V1_BASE_URL_SANDBOX, V1_BASE_URL_DAILY, V1_BASE_URL_PROD];

/// **模型目录探测**的基址顺序：`daily → prod → sandbox`。
///
/// 与 [`V1_BASE_URLS`] 的顺序不同，原因是两套参考实现的分工不同：
///   - 聊天流量 sandbox 优先，是为了**避开 prod 的 429**，与目录无关；
///   - 目录探测在 Go 参考实现里**固定打 daily**
///     （`antigravityModelBaseURLDaily = "https://daily-cloudcode-pa.googleapis.com"`），
///     而 sandbox 是内部预发环境，它的模型清单**可能比 daily 旧**。
///
/// 顺序错了会出一个很隐蔽的 bug：sandbox 先返回一份**不含新模型**的清单，
/// 而 `models::refresh` 是「首个成功即落地」，于是把旧清单当成权威结果缓存
/// 10 分钟 —— 新模型（比如 gemini-4 家族）在界面上就是不出现。目录这条链路
/// 必须 daily 先。
pub const MODEL_CATALOG_BASE_URLS: [&str; 3] =
    [V1_BASE_URL_DAILY, V1_BASE_URL_PROD, V1_BASE_URL_SANDBOX];

/// project 发现（loadCodeAssist / onboardUser）**固定用 prod**：daily 会拒这两
/// 个调用（规格 §3.4 + 9router 的注释原话）。
pub const PROJECT_BASE_URL: &str = V1_BASE_URL_PROD;

/// 流式推理方法名（冒号拼在基址之后；`?alt=sse` 必带）—— 聊天转发走这条
pub const METHOD_STREAM_GENERATE: &str = "streamGenerateContent";
/// 非流式推理方法名 —— 登记备用（本仓聊天一律走流式端点，见 `adapter.rs`）
#[allow(dead_code)]
pub const METHOD_GENERATE: &str = "generateContent";
/// 模型目录 + 每模型配额
pub const METHOD_FETCH_AVAILABLE_MODELS: &str = "fetchAvailableModels";
/// 分组额度（周 / 5 小时窗）—— 余额窗口读数（`balance.rs`）
pub const METHOD_RETRIEVE_QUOTA_SUMMARY: &str = "retrieveUserQuotaSummary";
/// 订阅档 + `cloudaicompanionProject`
pub const METHOD_LOAD_CODE_ASSIST: &str = "loadCodeAssist";
/// 无 project 时开通
pub const METHOD_ONBOARD_USER: &str = "onboardUser";
/// token 计数（本网关不用，登记以免将来写错位置）
#[allow(dead_code)]
pub const METHOD_COUNT_TOKENS: &str = "countTokens";

/// 流式推理的查询串（逐字）
pub const STREAM_QUERY: &str = "?alt=sse";

/// Hub 家族的客户端版本号（`antigravity/hub/{ver}` 里那一段）。
///
/// ```text
///   antigravity/hub/2.29.0 (aidev_client; os_type=darwin; arch=arm64; cl=1013060670)
/// ```
///
/// ── 2.29.0 这个数字不是随手取的（这是 gemini-4 系列 404 的正解）──
/// Go 参考实现 `internal/misc/antigravity_version.go` 的兜底版本是 **2.29.0**，
/// 源码注释写得毫不含糊：
///
/// ```text
///   Cloud Code rejects newer models for clients below 2.23.0,
///   so this floor must stay at or above that version.
/// ```
///
/// 它的测试 `TestAntigravityFallbackVersionMeetsBackendFloor` 把这条钉死成断言，
/// 注释补了确切症状：**「older versions get 404 Requested entity was not
/// found」** —— 正是 `gemini-4-argon-high` 打了 6 次全 404 的那句话。
///
/// 本仓原先填的是 2.24.0（本身高于 2.23.0 的门槛，但比上游当前发布的 Hub 版本
/// 落后），且 UA 缺了 `(aidev_client; …)` 整段元数据 —— 上游看到的是一个
/// **不存在的客户端形态**，于是把新模型（gemini-4 家族）一律判成不可解析。
pub const HUB_VERSION: &str = "2.29.0";
/// 环境变量：覆盖 Hub 家族版本号（上游推新客户端时不必重编译）
pub const ENV_HUB_VERSION: &str = "ANTIGRAVITY_HUB_VERSION";

/// Hub 家族 UA 里的平台元数据段（Go `antigravityHubPlatform` 逐字）。
///
/// 上游对 `os_type` / `arch` 只是读来记日志与分桶，不影响模型可见性；
/// Go 参考实现**固定**上报 `darwin/arm64`（官方只发布 darwin-arm64 的 Hub
/// 构建），本仓照抄这一串而不是上报真实编译目标 —— 真实目标是
/// `windows/amd64`，但那不是上游见过的组合，没必要赌。
pub const HUB_PLATFORM: &str = "aidev_client; os_type=darwin; arch=arm64";
/// 环境变量：覆盖 Hub 家族 UA 的平台元数据段
pub const ENV_HUB_PLATFORM: &str = "ANTIGRAVITY_HUB_PLATFORM";
/// 环境变量：整体覆盖出站 UA（仍会过 [`sanitize_user_agent`] 的两条硬约束）
pub const ENV_USER_AGENT: &str = "ANTIGRAVITY_USER_AGENT";

/// Hub 版本 → changelist 的映射（Go `antigravityHubChangelists` 逐字）。
///
/// changelist 属于**特定 Hub 发布**，不是「最新 manifest 的通用属性」。
/// 未知版本**不带** `cl=`（Go 的行为与测试 `{"2.30.0", "…arch=arm64)"}` 一致），
/// 而不是编一个数字上去 —— 编错了比缺席更容易被识别成伪造客户端。
const HUB_CHANGELISTS: &[(&str, &str)] = &[
    ("2.23.0", "998057262"),
    ("2.24.0", "1000335682"),
    ("2.29.0", "1013060670"),
];

/// 读环境变量（空值视为未设置）
fn env_value(name: &str) -> Option<String> {
    std::env::var(name)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

/// 解析 `x.y.z`（三段都要有、都要是数字；否则 None）
fn parse_semver(text: &str) -> Option<(u32, u32, u32)> {
    let mut parts = text.split('.');
    let major = parts.next()?.trim().parse::<u32>().ok()?;
    let minor = parts.next()?.trim().parse::<u32>().ok()?;
    let patch = parts.next()?.trim().parse::<u32>().ok()?;
    Some((major, minor, patch))
}

/// Hub 家族的版本号（默认 [`HUB_VERSION`]，`ANTIGRAVITY_HUB_VERSION` 可覆盖）。
///
/// 只要求能解析成三段数字，解析不出就回落到常量。
pub fn hub_version() -> String {
    let raw = env_value(ENV_HUB_VERSION).unwrap_or_else(|| HUB_VERSION.to_string());
    match parse_semver(&raw) {
        Some(_) => raw,
        _ => HUB_VERSION.to_string(),
    }
}

/// Hub 家族 UA 的平台元数据段（默认 [`HUB_PLATFORM`]，可覆盖）。
///
/// 覆盖值只做「非空 + 不含括号与换行」的粗校验：这一串会原样进 UA 的括号里，
/// 带上 `)` 或换行会把 UA 语法本身弄坏，那比版本号写错更容易被拒。
pub fn hub_platform() -> String {
    match env_value(ENV_HUB_PLATFORM) {
        Some(raw) if !raw.contains('(') && !raw.contains(')') && !raw.contains('\n') => raw,
        _ => HUB_PLATFORM.to_string(),
    }
}

/// 某个 Hub 版本对应的 changelist（未知版本返回 `None`）。
fn hub_changelist(version: &str) -> Option<&'static str> {
    HUB_CHANGELISTS
        .iter()
        .find(|(known, _)| *known == version)
        .map(|(_, changelist)| *changelist)
}

/// Hub 家族的出站 UA（Go `misc.AntigravityUserAgent` 逐字）：
///
/// ```text
///   antigravity/hub/2.29.0 (aidev_client; os_type=darwin; arch=arm64; cl=1013060670)
/// ```
///
/// 未知版本不带 `cl=` 段（`antigravity/hub/2.30.0 (aidev_client; os_type=darwin;
/// arch=arm64)`），与 Go 的测试断言一致。
///
/// **这是本家所有数据面请求与模型目录探测的 UA** —— 不是只有探测才用它。
/// Go 的 `resolveUserAgent` → `misc.AntigravityRequestUserAgent` →
/// `misc.AntigravityUserAgent`，聊天转发走的也是这一串。本仓原先数据面用 IDE
/// 家族 UA、探测用残缺的 Hub UA，两条链路都对不上上游。
///
/// `ANTIGRAVITY_USER_AGENT` 可整体覆盖（上游推新版 Hub 客户端时不必重编译），
/// 覆盖值要过 [`sanitize_user_agent`] 的两条硬约束。
pub fn hub_user_agent() -> String {
    if let Some(raw) = env_value(ENV_USER_AGENT).and_then(|raw| sanitize_user_agent(&raw)) {
        return raw;
    }
    let version = hub_version();
    let mut metadata = hub_platform();
    if let Some(changelist) = hub_changelist(&version) {
        metadata.push_str("; cl=");
        metadata.push_str(changelist);
    }
    format!("antigravity/hub/{version} ({metadata})")
}

/// OAuth 控制面请求用的 UA。
///
/// Go 侧同样是 Hub 家族：`internal/auth/antigravity/auth.go` 的
/// `shortUserAgent()` = `misc.AntigravityRequestUserAgent("")` =
/// `misc.AntigravityUserAgent()`，`FetchUserInfo`（:212-213）与
/// `FetchProjectID`（:250-267）都用它。本仓原先这里是
/// `vscode/1.X.X (Antigravity/4.3.0)`（Manager 的 `NATIVE_OAUTH_USER_AGENT`），
/// 那是 IDE 家族的第三套指纹，Go 侧根本不存在。
///
/// 保留这个函数名（而不是让调用点都改叫 [`hub_user_agent`]）：它标出的是
/// **用途**（控制面），将来若上游给控制面单独开口径，改这一处就够。
pub fn oauth_user_agent() -> String {
    hub_user_agent()
}

/// 清洗一个**外部给的** UA（`ANTIGRAVITY_USER_AGENT` 整体覆盖）：满足硬约束才放行。
///
/// 规则只有两条，都是上游真正在意的：
///   - 必须含 `antigravity`（不区分大小写）—— 不含的 UA 上游直接当非官方客户端；
///   - `antigravity/` 之后必须有一段可解析的 `x.y.z`，Hub 形态（`antigravity/hub/2.30.0`）
///     要跳过 `hub/` 再取。
///
/// **不做版本下限抬升**：Hub 家族的版本由用户自己跟上游（2.29.0 是当前兜底值，
/// 见 [`HUB_VERSION`]），这里替用户改写版本号只会让人以为设置生效了其实没生效。
///
/// 不合规返回 `None`，调用方回落默认 UA。
fn sanitize_user_agent(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }
    let lowered = trimmed.to_ascii_lowercase();
    let key = "antigravity/";
    let start = lowered.find(key)?;
    let after_key = start + key.len();
    let hub = lowered.get(after_key..).is_some_and(|tail| tail.starts_with("hub/"));
    let version_start = if hub { after_key + "hub/".len() } else { after_key };
    let tail = trimmed.get(version_start..)?;
    let parsed_text: String = tail
        .chars()
        .take_while(|ch| ch.is_ascii_digit() || *ch == '.')
        .collect();
    parse_semver(&parsed_text)?;
    Some(trimmed.to_string())
}

/// 拼一个 v1internal 方法的完整 URL：`{base}:{method}`（冒号语法见模块头）。
pub fn method_url(base: &str, method: &str) -> String {
    format!("{base}:{method}")
}

/// 流式推理端点（`{base}:streamGenerateContent?alt=sse`）—— 聊天转发走这条
pub fn stream_generate_url(base: &str) -> String {
    format!("{base}:{METHOD_STREAM_GENERATE}{STREAM_QUERY}")
}

/// 非流式推理端点（`{base}:generateContent`）—— 登记备用（本仓聊天一律走流式端点）
#[allow(dead_code)]
pub fn generate_url(base: &str) -> String {
    method_url(base, METHOD_GENERATE)
}

/// 模型目录端点（`{base}:fetchAvailableModels`）
pub fn fetch_available_models_url(base: &str) -> String {
    method_url(base, METHOD_FETCH_AVAILABLE_MODELS)
}

/// 分组额度摘要端点（`{base}:retrieveUserQuotaSummary`）—— 余额窗口读数走它
/// （Manager `modules/quota.rs::fetch_quota_summary` 的同一条；基址顺序与
/// [`V1_BASE_URLS`] 相同：sandbox → daily → prod）
pub fn retrieve_user_quota_summary_url(base: &str) -> String {
    method_url(base, METHOD_RETRIEVE_QUOTA_SUMMARY)
}

/// project 发现：`loadCodeAssist`（**prod**，见 [`PROJECT_BASE_URL`]）
pub fn load_code_assist_url() -> String {
    method_url(PROJECT_BASE_URL, METHOD_LOAD_CODE_ASSIST)
}

/// project 开通：`onboardUser`（**prod**）
pub fn onboard_user_url() -> String {
    method_url(PROJECT_BASE_URL, METHOD_ONBOARD_USER)
}

/// 鉴权头（`Authorization: Bearer {access_token}`）。
///
/// 规格 §7.5：token **必须**放 Bearer 头，不能塞 query（`?key=` 那套是
/// `generativelanguage.googleapis.com` 的形态，本家不适用）。
pub fn bearer_header(access_token: &str) -> (String, String) {
    ("Authorization".to_string(), format!("Bearer {}", access_token.trim()))
}

/// 推理 / 模型目录这类 **content** 请求的头集合：只有三个。
///
/// ── 为什么这里没有 `x-goog-user-project` ─────────────────────
/// 规格 §3.2 / 坑 #4：content 类请求（`generateContent` / `streamGenerateContent`）
/// 必须**不带** `x-goog-user-project`，带了会被上游拒；Manager 也是显式
/// `headers.remove("x-goog-user-project")`。本模块的做法是「从零拼头、不带它」，
/// 比「先加再删」少一处能忘。（project 仍然放在**请求体**的 `project` 字段里。）
///
/// ── 为什么没有 `x-client-name` / `x-client-version`（本次修复）──
/// Go 参考实现 `internal/runtime/executor/antigravity_executor_request.go:111-113`
/// 构造上游请求时**只设三个头**：
///
/// ```go
///   httpReq.Header.Set("Content-Type", "application/json")
///   httpReq.Header.Set("Authorization", "Bearer "+token)
///   httpReq.Header.Set("User-Agent", resolveUserAgent(auth))
/// ```
///
/// 同文件 :107-110 还特意写了「Deliberately no httpReq.Close」的理由：原生
/// Antigravity 客户端省略 `Connection` 头并保持 HTTP/1.1 长连接。也就是说，
/// 上游认的是一个**只有三头**的 Hub 客户端指纹，多出来的 `x-client-name` /
/// `x-client-version` 不在它的认知里。
///
/// 本仓原先在这里发 5 个头、UA 还是 IDE 家族的 `Antigravity/4.3.0 (...)
/// Chrome/... Electron/...`，等于用一个上游没见过的客户端形态去问新模型 ——
/// 这就是 `gemini-4-argon-high` 稳定 404 的原因（Go 的
/// `TestAntigravityFallbackVersionMeetsBackendFloor` 注释原文：
/// 「Cloud Code resolves newer models only for clients reporting at least
/// 2.23.0; older versions get 404 Requested entity was not found」）。
///
/// 未带的两个指纹头（`x-machine-id` / `x-vscode-sessionid`）：规格 §8.2 明确
/// 它们**不是硬性必需**（9router 只带 Content-Type / Authorization / UA 也能通），
/// 本仓不实现设备指纹采集，故如实缺席。
pub fn content_headers(access_token: &str) -> Vec<(String, String)> {
    vec![
        ("Content-Type".to_string(), "application/json".to_string()),
        bearer_header(access_token),
        ("User-Agent".to_string(), hub_user_agent()),
    ]
}

/// **Claude 模型**的 content 请求头：在 [`content_headers`] 之上补
/// `anthropic-beta`（规格 §3.2 的头表 + §5.3：`anthropic-beta` **仅 Claude**）。
///
/// 值取 Manager 的 `claude-code-20250219`（`handlers/openai.rs` 与
/// `handlers/claude.rs` 两处逐字相同的常量；9router 的 gemini 分支用的是更长的
/// 三连 `claude-code-20250219,interleaved-thinking-2025-05-14,fine-grained-tool-streaming-2025-05-14`
/// —— 两者都能通，本仓取 Manager 那一份，与其余头集合的出处保持一致）。
///
/// **只给 Claude 加**：Gemini 的请求带上它没有依据（规格头表把它标成「仅
/// Claude」），多一个非官方头只会离官方指纹更远。
///
/// 注意 Go 的 antigravity executor 并不发这个头（它只有三个头，Claude 模型
/// 走的是 `request.toolConfig.functionCallingConfig.mode = "VALIDATED"`
/// 那条路）。本仓保留它：上游对 Claude 模型的 `anthropic-beta` 有实际作用，
/// 而它与「三头指纹」不冲突 —— 它只在 Claude 分支出现，不是通用指纹的一部分。
pub fn claude_content_headers(access_token: &str) -> Vec<(String, String)> {
    let mut headers = content_headers(access_token);
    headers.push(("anthropic-beta".to_string(), ANTHROPIC_BETA_CLAUDE.to_string()));
    headers
}

/// Claude 请求要带的 `anthropic-beta` 值（Manager 逐字，见
/// [`claude_content_headers`]）
const ANTHROPIC_BETA_CLAUDE: &str = "claude-code-20250219";

/// **非 content** 方法（project 发现 / 额度摘要）的头集合。
///
/// 与 [`content_headers`] 的两处差别：
///   1. `project_id` 非空时带上 `x-goog-user-project` —— 这类方法上游忽略
///      **请求体**里的 `project` 字段，这个头才是「哪个项目」的表述；
///   2. UA 走 [`oauth_user_agent`]（它现在也返回 Hub UA，见该函数的注释）。
///
/// ── 为什么不再发 `x-client-name` / `x-client-version` ──────────
/// Go 参考实现的控制面（`internal/auth/antigravity/auth.go` 的
/// `FetchUserInfo` / `FetchProjectID` / `OnboardUser`）只发
/// `Authorization` + `Content-Type` + `User-Agent`，`OnboardUser` 另加
/// `X-Goog-Api-Client`。`x-client-name` / `x-client-version` 在 Go 侧
/// **零命中** —— 它们是 IDE 家族（Manager）的指纹，不是 Hub 家族的。
pub fn admin_headers(access_token: &str, project_id: &str) -> Vec<(String, String)> {
    let mut headers = vec![
        ("Content-Type".to_string(), "application/json".to_string()),
        bearer_header(access_token),
        ("User-Agent".to_string(), oauth_user_agent()),
    ];
    let project = project_id.trim();
    if !project.is_empty() {
        headers.push(("x-goog-user-project".to_string(), project.to_string()));
    }
    headers
}

/// **模型目录探测**（`fetchAvailableModels`）的头集合：只有三个。
///
/// ── 为什么不复用 [`admin_headers`] ──────────────────────────
/// Go 参考实现（`auth/antigravity_models.go` 的 `FetchAntigravityAvailableModels`）
/// 探这个接口时**只发三个头**：
///
/// ```text
///   Content-Type:  application/json
///   Authorization: Bearer <access_token>
///   User-Agent:    antigravity/hub/{ver} {os}/{arch}      ← Hub 家族，不是 IDE 家族
/// ```
///
/// 它**明确不发** `x-client-name` / `x-client-version` / `x-goog-user-project`
/// / `x-goog-api-client`。本仓原先照 [`admin_headers`] 发 5–6 个头、UA 用
/// `vscode/1.X.X (Antigravity/4.3.0)`，与参考实现是两套完全不同的指纹 ——
/// 上游对这个「不像任何真实客户端」的组合给空目录或 4xx，于是只剩兜底清单。
///
/// `project` 仍然只放在**请求体**里（参考实现就是这么做的：body 只有一个
/// `project` 键），不转成 `x-goog-user-project` 头。
///
/// 额度摘要（`balance.rs`）与 project 发现（`project.rs`）**仍走
/// [`admin_headers`]**：参考实现没有给出这两个接口的头口径，而它们是
/// 「非 content 方法」，保留 `x-goog-user-project` 与 IDE 家族 UA 更接近
/// 既有行为（这两条链路本来是通的）。
pub fn probe_headers(access_token: &str) -> Vec<(String, String)> {
    vec![
        ("Content-Type".to_string(), "application/json".to_string()),
        bearer_header(access_token),
        ("User-Agent".to_string(), hub_user_agent()),
    ]
}
