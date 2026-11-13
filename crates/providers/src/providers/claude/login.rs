//! Claude 的登录：网页授权（loopback 回调）与粘贴 refresh token 两条入口。
//!
//! ── 两条入口的取舍 ─────────────────────────────────────────
//! * **网页授权**（`login.start` → 浏览器 → 回调 → 换码）：标准 OAuth 流程，
//!   用户点一下就行。授权 URL 里的 `redirect_uri` 用本机随机端口。
//! * **粘贴 refresh token**（`accounts.normalize` 的 `Manual` 分支）：给
//!   「浏览器在这台机器上打不开 claude.ai」的用户留的后路。粘贴进来的东西
//!   会先做一次**真实刷新**再落库 —— 不校验就存，用户会得到一个「加进去了
//!   但一发就 401」的账号，比直接报错难排查得多。
//!
//! ── state 的两个来源 ───────────────────────────────────────
//! 正常情况回调 query 里带 `state`，与发起时那个逐字比对即可。但参考实现
//! 记录了一个上游行为：**Claude 会把 state 塞在 `code` 后面用 `#` 分隔**
//! （`parseCodeAndState`），而且 `#` 后那个优先。这里两条都认：先按 `#` 拆，
//! 拆出来的 state 优先于 query 里的 state。
//!
//! ── 谁负责落库 ─────────────────────────────────────────────
//! 本模块只负责「走完流程、返回 `LoginPoll::Done{account}`」；真正的写入由
//! 网关拿到 `NormalizedAccount` 后完成（与 Antigravity 家一致）。
//!
//! ── 硬约束 ──────────────────────────────────────────────────
//! release 是 `panic=abort`：本文件零 unwrap / expect / panic。

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use serde_json::{json, Value};

use agent2api_provider_protocol as proto;
use agent2api_provider_protocol::WireProxy as ResolvedProxy;

use crate::errors::GatewayError;

use super::callback_server::CallbackListener;
use super::credentials::ClaudeCredentials;
use super::{accounts, oauth};

/// 面板能贴进来的最长文本（整段回调地址可能很长，但 8 KiB 足够）。
pub const MAX_INPUT_LENGTH: usize = 8192;

/// flow id 前缀（一眼能看出是哪一家的登录流程）。
const FLOW_PREFIX: &str = "claude-web-";

/// 界面上的登录方式清单（`auth.methods` 管理动作的返回值）。
///
/// ── 为什么必须实现 ──────────────────────────────────────────
/// 网关优先问 `auth.methods`；不实现时整块降级成「手动凭证 JSON（兼容入口）」，
/// 用户看不到真正的登录方式，只能自己拼一个凭证对象 —— 这正是用户反馈的
/// 「这边还是只能填凭证」。
///
/// ── 字段契约（从网关前端的校验函数反推）────────────────────
/// * `methodIndex`：非负安全整数，数组内唯一。
/// * `type`：**只有 `oauth` 与 `api` 两种**。`oauth` 会走 `login.start`（网关
///   统一传 `method = "browser"`，靠 `payload.methodIndex` 区分具体是哪条）；
///   `api` 走 `account.normalize`，用户填的字段包在 `payload.inputs` 里。
/// * `callbackInput`：`"url"`（缺省同义）或 `"code"`；后者要求
///   `manualCallback: true`。
/// * `type: "api"` 时**不能**带 `localOnly` / `manualCallback` / `embeddedOnly`
///   为真 —— 网关的校验函数会直接报「插件返回了无效的登录方式」。
/// * 每个 prompt 的 `key` 要匹配 `/^[A-Za-z][A-Za-z0-9_-]{0,63}$/`，且不能是
///   `__proto__` / `prototype` / `constructor` / `signal`。
pub fn login_methods() -> Value {
    json!({
        "methods": [
            {
                "methodIndex": 0,
                "type": "oauth",
                "label": "Claude 网页登录",
                "instructions": "在弹出的 claude.ai 授权页里确认授权；回调会回到本机，完成后自动添加账号。也可以把浏览器地址栏里的整段回调地址粘回来。",
                "prompts": [],
                "localOnly": false,
                "manualCallback": false,
                "callbackInput": "url"
            },
            {
                "methodIndex": 1,
                "type": "api",
                "label": "粘贴 refresh token",
                "instructions": "粘贴以 sk-ant-ort 开头的 Claude refresh token（或整段回调地址）。保存前会先用它做一次真实刷新校验，失败会当场报错。",
                "prompts": [
                    {
                        "key": "refreshToken",
                        "type": "text",
                        "label": "refresh token",
                        "placeholder": "sk-ant-ort…",
                        "secret": true,
                        "optional": false
                    }
                ]
            }
        ]
    })
}

/// 一轮登录的状态。
enum FlowState {
    /// 已打开授权页，等回调。
    Waiting,
    /// 收到授权码，正在换证。
    Working,
    /// 已完成（带账号 payload）。
    Done(Value),
    /// 已失败。
    Failed(String),
}

/// 登录表里的一条。
struct Entry {
    listener: Arc<CallbackListener>,
    state: FlowState,
}

/// 进程内的登录表。
fn flows() -> &'static Mutex<HashMap<String, Entry>> {
    static FLOWS: std::sync::OnceLock<Mutex<HashMap<String, Entry>>> = std::sync::OnceLock::new();
    FLOWS.get_or_init(|| Mutex::new(HashMap::new()))
}

/// 拿表并执行（毒锁时取内部值 —— panic=abort 下没有 unwrap 可用）。
fn with_flows<T>(action: impl FnOnce(&mut HashMap<String, Entry>) -> T) -> T {
    let mut guard = flows()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    action(&mut guard)
}

/// 关掉所有在等回调的监听器（发起新登录前清场）。
fn close_all() {
    let listeners: Vec<Arc<CallbackListener>> = with_flows(|table| {
        table
            .values()
            .map(|entry| Arc::clone(&entry.listener))
            .collect()
    });
    for listener in listeners {
        listener.close();
    }
}

/// 发起登录。
///
/// 网关对 `auth.methods` 里 `type: "oauth"` 的入口**统一传 `method = "browser"`**，
/// 靠 `payload.methodIndex` 区分是哪一条（Kiro 用一个 oauth 入口配两套索引正是
/// 这么分发的）。旧版网关不传 `methodIndex`，此时按 0 处理。`type: "api"` 的入口
/// 不经过这里 —— 它走 `account.normalize`，凭证在 `payload.inputs` 里。
pub(super) async fn login_start(method: &str, payload: &Value) -> Result<proto::LoginStart, String> {
    let index = payload.get("methodIndex").and_then(Value::as_u64);
    if method != "browser" {
        return Err(format!(
            "Claude 不支持「{method}」登录方式（网页登录走 oauth 入口；粘贴 refresh token 请用添加账号的凭证入口）"
        ));
    }
    if let Some(index) = index.filter(|index| *index != 0) {
        return Err(format!(
            "Claude 的登录方式 #{index} 不发起浏览器授权（只有网页登录需要打开授权页；粘贴 token 走添加账号）"
        ));
    }
    let proxy = resolve_login_proxy(payload.get("proxy"))?;
    // 同时只留一轮：旧监听器占着端口没有意义，还会让用户看到两个授权页。
    close_all();
    let listener = Arc::new(CallbackListener::bind().await?);
    let redirect_uri = format!(
        "http://localhost:{}{}",
        listener.port(),
        super::callback_server::PATH
    );
    let state = oauth::new_state().map_err(|error| error.message)?;
    let pkce = oauth::pkce().map_err(|error| error.message)?;
    let url = oauth::authorize_url(&redirect_uri, &state, &pkce.challenge)
        .map_err(|error| error.message)?;
    let flow_id = format!("{FLOW_PREFIX}{state}");
    with_flows(|table| {
        table.insert(
            flow_id.clone(),
            Entry {
                listener: Arc::clone(&listener),
                state: FlowState::Waiting,
            },
        );
    });
    spawn_completion(
        flow_id.clone(),
        Arc::clone(&listener),
        state,
        pkce.verifier,
        redirect_uri,
        proxy,
    );
    Ok(proto::LoginStart {
        flow: flow_id,
        url,
        instructions: "在浏览器里完成 Claude 授权；完成后本窗口会自动收到回调（也可以把回调地址整段粘回来）。".to_string(),
        poll_interval_ms: 2_000,
        external_browser: false,
        allowed_hosts: Vec::new(),
    })
}

/// 起一个后台任务等回调并换码。
fn spawn_completion(
    flow_id: String,
    listener: Arc<CallbackListener>,
    expected_state: String,
    verifier: String,
    redirect_uri: String,
    proxy: Option<ResolvedProxy>,
) {
    tokio::spawn(async move {
        let query = listener.next_callback().await;
        let Some(query) = query else {
            set_failed(&flow_id, "这次登录已取消，请重新发起".to_string());
            listener.close();
            return;
        };
        set_working(&flow_id);
        let result = finish(&query, &expected_state, &verifier, &redirect_uri, proxy.as_ref()).await;
        match result {
            Ok(credentials) => {
                let payload = credentials_to_value(&credentials);
                set_done(&flow_id, payload);
            }
            Err(error) => set_failed(&flow_id, error.message),
        }
        listener.close();
    });
}

/// 把回调 query 换成凭证。
async fn finish(
    query: &str,
    expected_state: &str,
    verifier: &str,
    redirect_uri: &str,
    proxy: Option<&ResolvedProxy>,
) -> Result<ClaudeCredentials, GatewayError> {
    let parsed = parse_query(query);
    let error = parsed
        .get("error")
        .map(|value| value.trim().to_string())
        .unwrap_or_default();
    if !error.is_empty() {
        let description = parsed
            .get("error_description")
            .map(|value| value.trim().to_string())
            .unwrap_or_default();
        let detail = if description.is_empty() {
            error
        } else {
            format!("{error}（{description}）")
        };
        return Err(GatewayError::with_status(
            400,
            format!("Claude 授权被拒绝：{detail}"),
        ));
    }
    let raw_code = parsed
        .get("code")
        .map(|value| percent_decode(value))
        .unwrap_or_default();
    let (code, embedded_state) = split_code_and_state(&raw_code);
    if code.is_empty() {
        return Err(GatewayError::with_status(400, "Claude 回调没有带回授权码"));
    }
    // `#` 后的 state 优先（参考实现 parseCodeAndState 的取舍）。
    let query_state = parsed
        .get("state")
        .map(|value| percent_decode(value))
        .unwrap_or_default();
    let actual_state = if embedded_state.is_empty() {
        query_state
    } else {
        embedded_state
    };
    if actual_state.is_empty() {
        return Err(GatewayError::with_status(400, "Claude 回调没有带回 state"));
    }
    if actual_state != expected_state {
        return Err(GatewayError::with_status(
            400,
            "Claude 回调的 state 与本轮登录不匹配（可能是过期的授权页）",
        ));
    }
    oauth::exchange_code(&code, &actual_state, verifier, redirect_uri, proxy).await
}

/// 上游会把 state 塞在 code 后面用 `#` 分隔，这里拆开。
fn split_code_and_state(raw: &str) -> (String, String) {
    match raw.split_once('#') {
        Some((code, state)) => (code.trim().to_string(), state.trim().to_string()),
        None => (raw.trim().to_string(), String::new()),
    }
}

/// 查一轮登录的进度。
pub(super) async fn login_poll(flow: &str) -> Result<proto::LoginPoll, String> {
    let (poll, terminal) = with_flows(|table| {
        let Some(entry) = table.get(flow) else {
            return (
                proto::LoginPoll::Failed {
                    message: "这次登录流程已失效（插件进程重启过？），请重新发起".to_string(),
                },
                true,
            );
        };
        match &entry.state {
            FlowState::Waiting => (
                proto::LoginPoll::Pending {
                    hint: Some("等待你在浏览器里完成 Claude 授权…".to_string()),
                },
                false,
            ),
            FlowState::Working => (
                proto::LoginPoll::Pending {
                    hint: Some("已收到授权码，正在换取凭证…".to_string()),
                },
                false,
            ),
            FlowState::Done(payload) => (done_poll(payload.clone()), true),
            FlowState::Failed(message) => (
                proto::LoginPoll::Failed {
                    message: message.clone(),
                },
                true,
            ),
        }
    });
    if terminal {
        with_flows(|table| table.remove(flow));
    }
    Ok(poll)
}

/// 用户手工粘贴回调地址。
pub(super) async fn login_callback(callback: &proto::LoginCallback) -> Result<proto::LoginPoll, String> {
    let query = callback_query(callback);
    let listener = with_flows(|table| {
        table
            .get(&callback.flow)
            .map(|entry| Arc::clone(&entry.listener))
    });
    let Some(listener) = listener else {
        return Ok(proto::LoginPoll::Failed {
            message: "这次登录流程已失效（插件进程重启过？），请重新发起".to_string(),
        });
    };
    if let Err(message) = listener.submit_callback(&query) {
        return Ok(proto::LoginPoll::Failed { message });
    }
    // 后台任务收到后会换码；这里只等状态变化，不重复消费通道。
    for _ in 0..60 {
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        let poll = login_poll(&callback.flow).await?;
        if !matches!(poll, proto::LoginPoll::Pending { .. }) {
            return Ok(poll);
        }
    }
    Ok(proto::LoginPoll::Pending {
        hint: Some("已收到回调，正在换取凭证…".to_string()),
    })
}

/// 取消一轮登录。
pub(super) async fn login_cancel(flow: &str) -> Result<(), String> {
    let listener = with_flows(|table| table.remove(flow).map(|entry| Arc::clone(&entry.listener)));
    if let Some(listener) = listener {
        listener.close();
    }
    Ok(())
}

/// 把粘贴进来的文本规整成 refresh token。
///
/// 用户可能粘：完整回调地址、`refresh_token=...`、带引号的一长串、甚至整段
/// JSON。这里只做「剥壳」，**不改动 token 本体**（Claude 的 refresh token 以
/// `sk-ant-ort01-` 开头，任何前缀剥离都可能把有效令牌改坏）。
pub fn normalize_refresh_token(raw: &str) -> String {
    let mut text = raw.trim().to_string();
    if text.len() > MAX_INPUT_LENGTH {
        text.truncate(MAX_INPUT_LENGTH);
    }
    // 引号 / 反引号包裹
    for quote in ['"', '\'', '`'] {
        if text.starts_with(quote) && text.ends_with(quote) && text.len() > 2 {
            text = text[1..text.len() - 1].to_string();
        }
    }
    // `refresh_token=xxx` / `refresh_token: xxx`
    for label in [
        "refresh_token=",
        "refresh_token:",
        "refreshToken=",
        "refreshToken:",
    ] {
        if let Some((_, tail)) = text.split_once(label) {
            // 只取到下一个 `&` 为止：整段 query 里 `refresh_token=x&state=y` 是
            // 常见形态，吞掉 `&state=y` 会让令牌带上一截垃圾。
            let value = tail.split('&').next().unwrap_or(tail);
            text = value.trim().to_string();
        }
    }
    for label in ["Bearer ", "bearer "] {
        if let Some(tail) = text.strip_prefix(label) {
            text = tail.trim().to_string();
        }
    }
    // 整段回调地址：取 query 里的 refresh_token
    if text.contains("://") || text.starts_with('?') {
        let query = text.split_once('?').map(|(_, tail)| tail).unwrap_or(&text);
        let parsed = parse_query(query);
        for key in ["refresh_token", "refreshToken"] {
            if let Some(value) = parsed.get(key) {
                let decoded = percent_decode(value);
                if !decoded.trim().is_empty() {
                    text = decoded.trim().to_string();
                    break;
                }
            }
        }
    }
    text.trim().to_string()
}

/// 粘贴式登录：真刷新校验一次，成功才返回凭证。
pub(super) async fn verify_paste(
    payload: &Value,
    proxy: Option<&ResolvedProxy>,
) -> Result<ClaudeCredentials, GatewayError> {
    let raw = payload
        .get("refreshToken")
        .or_else(|| payload.get("refresh_token"))
        .or_else(|| payload.get("token"))
        .or_else(|| payload.get("credential"))
        .and_then(Value::as_str)
        .unwrap_or_default();
    let token = normalize_refresh_token(raw);
    if token.is_empty() {
        return Err(GatewayError::with_status(
            400,
            "没有读到 Claude refresh token（请粘贴以 sk-ant-ort 开头的 refresh token，或整段回调地址）",
        ));
    }
    let refreshed = oauth::refresh_access_token(&token, proxy).await?;
    Ok(refreshed.credentials)
}

/// 一轮完成后的 payload（写进登录表，供 poll 取）。
fn credentials_to_value(credentials: &ClaudeCredentials) -> Value {
    json!({
        "refreshToken": credentials.refresh_token,
        "accessToken": credentials.access_token,
        "expiresAt": credentials.expires_at,
        "email": credentials.email,
        "accountUuid": credentials.account_uuid,
        "organizationUuid": credentials.organization_uuid,
        "organizationName": credentials.organization_name,
        "plan": credentials.plan,
    })
}

/// payload → `LoginPoll::Done`。
fn done_poll(payload: Value) -> proto::LoginPoll {
    let pick = |key: &str| -> String {
        payload
            .get(key)
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string()
    };
    let credentials = ClaudeCredentials {
        refresh_token: pick("refreshToken"),
        access_token: pick("accessToken"),
        expires_at: payload.get("expiresAt").and_then(Value::as_i64).unwrap_or(0),
        email: pick("email"),
        account_uuid: pick("accountUuid"),
        organization_uuid: pick("organizationUuid"),
        organization_name: pick("organizationName"),
        plan: pick("plan"),
        ..Default::default()
    };
    proto::LoginPoll::Done {
        account: accounts::account_of(&credentials, "browser", None),
    }
}

/// 回调结构 → query 串。
fn callback_query(callback: &proto::LoginCallback) -> String {
    let code = callback.code.trim();
    if !code.is_empty() {
        return format!("code={code}");
    }
    let url = callback.url.trim();
    if let Some((_, query)) = url.split_once('?') {
        return query.to_string();
    }
    if url.contains('=') {
        return url.to_string();
    }
    String::new()
}

/// 记录「已收到回调，正在换证」。
fn set_working(flow_id: &str) {
    with_flows(|table| {
        if let Some(entry) = table.get_mut(flow_id) {
            entry.state = FlowState::Working;
        }
    });
}

/// 记录完成。
fn set_done(flow_id: &str, payload: Value) {
    with_flows(|table| {
        if let Some(entry) = table.get_mut(flow_id) {
            entry.state = FlowState::Done(payload);
        }
    });
}

/// 记录失败。
fn set_failed(flow_id: &str, message: String) {
    with_flows(|table| {
        if let Some(entry) = table.get_mut(flow_id) {
            entry.state = FlowState::Failed(message);
        }
    });
}

/// 解析 query 串（不解码）。
fn parse_query(query: &str) -> HashMap<String, String> {
    query
        .split('&')
        .filter_map(|pair| pair.split_once('='))
        .map(|(key, value)| (key.to_string(), value.to_string()))
        .collect()
}

/// 百分号解码（`+` → 空格；非法 `%` 原样保留）。
fn percent_decode(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'+' => {
                out.push(b' ');
                index += 1;
            }
            b'%' if index + 2 < bytes.len() => {
                let hex = std::str::from_utf8(&bytes[index + 1..index + 3]).unwrap_or_default();
                match u8::from_str_radix(hex, 16) {
                    Ok(byte) => {
                        out.push(byte);
                        index += 3;
                    }
                    Err(_) => {
                        out.push(bytes[index]);
                        index += 1;
                    }
                }
            }
            byte => {
                out.push(byte);
                index += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).to_string()
}

/// 解析登录用的代理配置（**不静默回落直连**）。
fn resolve_login_proxy(raw: Option<&Value>) -> Result<Option<ResolvedProxy>, String> {
    let Some(raw) = raw else {
        return Ok(None);
    };
    if raw.is_null() {
        return Ok(None);
    }
    if let Ok(proxy) = serde_json::from_value::<ResolvedProxy>(raw.clone()) {
        if !proxy.host.trim().is_empty() {
            return Ok(Some(proxy));
        }
    }
    match crate::proxy_util::resolve_account_proxy(Some(raw)) {
        None => Ok(None),
        Some(crate::proxy_util::ProxyResolution::Resolved(proxy)) => Ok(Some(proxy)),
        Some(crate::proxy_util::ProxyResolution::Failed(reason)) => Err(reason),
    }
}

#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn state_embedded_after_a_hash_wins() {
        let (code, state) = split_code_and_state("abc123#st-9");
        assert_eq!(code, "abc123");
        assert_eq!(state, "st-9");
    }

    #[test]
    fn a_plain_code_has_no_embedded_state() {
        let (code, state) = split_code_and_state("abc123");
        assert_eq!(code, "abc123");
        assert!(state.is_empty());
    }

    #[test]
    fn percent_decoding_handles_plus_and_escapes() {
        assert_eq!(percent_decode("a+b"), "a b");
        assert_eq!(percent_decode("a%2Bb"), "a+b");
        // 非法转义原样保留，不吞字符。
        assert_eq!(percent_decode("100%"), "100%");
    }

    #[test]
    fn pasted_tokens_are_unwrapped_but_never_rewritten() {
        assert_eq!(
            normalize_refresh_token("  sk-ant-ort01-x  "),
            "sk-ant-ort01-x"
        );
        assert_eq!(
            normalize_refresh_token("\"sk-ant-ort01-x\""),
            "sk-ant-ort01-x"
        );
        assert_eq!(
            normalize_refresh_token("refresh_token=sk-ant-ort01-x"),
            "sk-ant-ort01-x"
        );
        assert_eq!(
            normalize_refresh_token("Bearer sk-ant-ort01-x"),
            "sk-ant-ort01-x"
        );
        // 前缀本身绝不能被剥掉。
        assert!(normalize_refresh_token("sk-ant-ort01-x").starts_with("sk-ant-ort01-"));
    }

    #[test]
    fn a_pasted_callback_url_yields_the_token_inside_it() {
        let url = "http://localhost:54545/callback?code=abc&refresh_token=sk-ant-ort01-y&state=s";
        assert_eq!(normalize_refresh_token(url), "sk-ant-ort01-y");
    }

    #[test]
    fn query_parsing_keeps_raw_values() {
        let parsed = parse_query("code=a%20b&state=s1");
        assert_eq!(parsed.get("code").map(String::as_str), Some("a%20b"));
        assert_eq!(parsed.get("state").map(String::as_str), Some("s1"));
    }

    // ── auth.methods 的契约 ────────────────────────────────────
    // 网关对这份 JSON 做严格校验，任何一条不合规都会让整个添加账号弹窗
    // 报「插件返回了无效的登录方式」。下面按网关的规则逐条断言，改字段时
    // 有测试兜底。

    /// 网关允许的 prompt key 形态（`/^[A-Za-z][A-Za-z0-9_-]{0,63}$/`）。
    fn key_is_valid(key: &str) -> bool {
        let mut chars = key.chars();
        let Some(first) = chars.next() else {
            return false;
        };
        if !first.is_ascii_alphabetic() {
            return false;
        }
        key.len() <= 64
            && chars.all(|ch| ch.is_ascii_alphanumeric() || ch == '_' || ch == '-')
    }

    #[test]
    fn the_method_list_satisfies_the_gateway_contract() {
        let list = login_methods();
        let methods = list["methods"].as_array().expect("methods 必须是数组");
        assert!(!methods.is_empty(), "至少要有网页登录入口");

        let mut seen = Vec::new();
        for method in methods {
            let index = method["methodIndex"]
                .as_u64()
                .expect("methodIndex 必须是非负整数");
            assert!(!seen.contains(&index), "methodIndex 不能重复：{index}");
            seen.push(index);

            let kind = method["type"].as_str().expect("type 必须是字符串");
            assert!(
                kind == "oauth" || kind == "api",
                "type 只能是 oauth / api，得到 {kind}"
            );

            // callbackInput 只接受 "url" / "code"（缺省等价 "url"）。
            if let Some(input) = method.get("callbackInput") {
                let input = input.as_str().expect("callbackInput 必须是字符串");
                assert!(
                    input == "url" || input == "code",
                    "callbackInput 只能是 url / code，得到 {input}"
                );
                if input == "code" {
                    assert_eq!(
                        method["manualCallback"], true,
                        "callbackInput=code 必须同时 manualCallback=true"
                    );
                }
            }

            // api 类型不能带本机 / 手动回调 / 内嵌标记。
            if kind == "api" {
                for flag in ["localOnly", "manualCallback", "embeddedOnly"] {
                    assert_ne!(
                        method[flag], true,
                        "api 方式不能把 {flag} 设为 true（网关会判定为无效）"
                    );
                }
            }

            let prompts = method["prompts"]
                .as_array()
                .expect("prompts 必须是数组");
            let mut keys = Vec::new();
            for prompt in prompts {
                let key = prompt["key"].as_str().expect("prompt.key 必须是字符串");
                assert!(key_is_valid(key), "prompt.key 不合规：{key}");
                assert!(
                    !["__proto__", "prototype", "constructor", "signal"].contains(&key),
                    "prompt.key 用了保留名：{key}"
                );
                assert!(!keys.contains(&key), "prompt.key 不能重复：{key}");
                keys.push(key);

                let prompt_kind = prompt["type"].as_str().expect("prompt.type 必须是字符串");
                assert!(
                    prompt_kind == "text" || prompt_kind == "select",
                    "prompt.type 只能是 text / select，得到 {prompt_kind}"
                );
                // 密文字段不能预填默认值。
                if prompt["secret"] == true {
                    assert!(
                        prompt.get("default").is_none(),
                        "secret 字段不接受 default：{key}"
                    );
                }
            }
        }

        // 必须有且只有一条网页登录（type=oauth、methodIndex=0）。
        let browser = methods
            .iter()
            .find(|method| method["methodIndex"] == 0)
            .expect("缺少 methodIndex=0");
        assert_eq!(browser["type"], "oauth", "#0 应该是网页授权");
        // 粘贴 token 的入口必须是 api 类型，否则网关不会走 normalize。
        let paste = methods
            .iter()
            .find(|method| method["label"] == "粘贴 refresh token")
            .expect("缺少粘贴 token 入口");
        assert_eq!(paste["type"], "api", "粘贴 token 必须走 api 类型");
    }

    #[tokio::test]
    async fn a_non_zero_index_does_not_open_a_browser() {
        let payload = json!({ "methodIndex": 1 });
        let error = login_start("browser", &payload)
            .await
            .expect_err("非 0 索引不该发起授权");
        assert!(
            error.contains("#1"),
            "错误里要指认是哪条方式，实际：{error}"
        );
    }

    #[tokio::test]
    async fn a_paste_only_method_is_not_a_login_start() {
        // 网关对 api 类型不会调 login.start；万一手工调过来要明确报错，
        // 而不是悄悄开一个授权页。
        let payload = json!({ "methodIndex": 1 });
        assert!(login_start("token", &payload).await.is_err());
        assert!(login_start("api", &payload).await.is_err());
    }
}
