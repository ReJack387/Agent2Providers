//! Codex 的登录流程：浏览器回调 + 设备码两种入口，外加粘贴 refresh token。
//!
//! ── 为什么两条路 ────────────────────────────────────────────
//! 参考实现 `CodexAuthenticator.Login` 先判 `shouldUseCodexDeviceFlow(opts)`：
//! 有浏览器的环境走 loopback 回调，无浏览器的（远程 / 容器）走设备码。插件
//! 跑在用户本机，默认走浏览器；但设备码对「浏览器打不开 auth.openai.com」
//! 的用户是唯一可行的路，所以两条都实现。
//!
//! ── 状态机 ──────────────────────────────────────────────────
//! `Waiting`（等回调 / 等用户确认）→ `Working`（换码中）→ `Done` / `Failed`。
//! 面板每 2 秒 `login.poll` 一次，拿到 `Done` 后由网关落库。
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
use super::credentials::CodexCredentials;
use super::oauth::{self, DeviceCode};
use super::{accounts, endpoints};

/// 面板能贴进来的最长文本。
pub const MAX_INPUT_LENGTH: usize = 8192;

/// 浏览器流程的 flow 前缀。
const FLOW_PREFIX: &str = "codex-web-";

/// 设备码流程的 flow 前缀。
const DEVICE_PREFIX: &str = "codex-device-";

/// 界面上的登录方式清单（`auth.methods` 管理动作的返回值）。
///
/// ── 为什么必须实现 ──────────────────────────────────────────
/// 网关优先问 `auth.methods`；不实现时整块降级成「手动凭证 JSON（兼容入口）」，
/// 用户看不到真正的登录方式，只能自己拼一个凭证对象。
///
/// ── 字段契约（从网关前端的校验函数反推）────────────────────
/// * `methodIndex`：非负安全整数，数组内唯一。
/// * `type`：**只有 `oauth` 与 `api` 两种**。`oauth` 走 `login.start`（网关统一
///   传 `method = "browser"`，靠 `payload.methodIndex` 区分）；`api` 走
///   `account.normalize`，用户填的字段包在 `payload.inputs` 里。
/// * `callbackInput`：`"url"`（缺省同义）或 `"code"`；后者要求
///   `manualCallback: true`。
/// * `type: "api"` 时**不能**带 `localOnly` / `manualCallback` / `embeddedOnly`
///   为真 —— 网关的校验函数会直接报「插件返回了无效的登录方式」。
/// * 每个 prompt 的 `key` 要匹配 `/^[A-Za-z][A-Za-z0-9_-]{0,63}$/`，且不能是
///   `__proto__` / `prototype` / `constructor` / `signal`。
///
/// 设备码那条（#1）也标 `manualCallback: false`：它的授权页是
/// `auth.openai.com/codex/device`（要用户填验证码），不产生本机回调，也不接受
/// 粘贴回调地址 —— `login_callback` 对设备流程会明确拒绝。所以不给界面一个
/// 只会失败的粘贴框。
pub fn login_methods() -> Value {
    json!({
        "methods": [
            {
                "methodIndex": 0,
                "type": "oauth",
                "label": "Codex 网页登录",
                "instructions": "在弹出的 auth.openai.com 授权页里确认；回调会回到本机，完成后自动添加账号。也可以把浏览器地址栏里的整段回调地址粘回来。",
                "prompts": [],
                "localOnly": false,
                "manualCallback": false,
                "callbackInput": "url"
            },
            {
                "methodIndex": 1,
                "type": "oauth",
                "label": "Codex 设备码登录",
                "instructions": "点「开始」后拿到验证码，在任意设备的浏览器打开 auth.openai.com/codex/device 输入它即可；15 分钟内有效。浏览器打不开授权页时用这条。",
                "prompts": [],
                "localOnly": false,
                "manualCallback": false,
                "callbackInput": "url"
            },
            {
                "methodIndex": 2,
                "type": "api",
                "label": "粘贴 refresh token",
                "instructions": "粘贴以 rt_ 开头的 Codex refresh token（或整段回调地址）。保存前会先用它做一次真实刷新校验，失败会当场报错。",
                "prompts": [
                    {
                        "key": "refreshToken",
                        "type": "text",
                        "label": "refresh token",
                        "placeholder": "rt_…",
                        "secret": true,
                        "optional": false
                    }
                ]
            }
        ]
    })
}

/// 一个登录流程的状态。
enum FlowState {
    Waiting,
    Working,
    Done(Value),
    Failed(String),
}

/// 一个登录流程的运行时。
struct Entry {
    listener: Option<Arc<CallbackListener>>,
    device: Option<Arc<DeviceCode>>,
    state: FlowState,
}

fn flows() -> &'static Mutex<HashMap<String, Entry>> {
    static FLOWS: std::sync::OnceLock<Mutex<HashMap<String, Entry>>> =
        std::sync::OnceLock::new();
    FLOWS.get_or_init(|| Mutex::new(HashMap::new()))
}

fn with_flows<T>(action: impl FnOnce(&mut HashMap<String, Entry>) -> T) -> T {
    let mut guard = match flows().lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    };
    action(&mut guard)
}

fn close_all() {
    let listeners = with_flows(|table| {
        table
            .values()
            .filter_map(|entry| entry.listener.clone())
            .collect::<Vec<_>>()
    });
    for listener in listeners {
        listener.close();
    }
    with_flows(|table| table.clear());
}

/// 发起登录。
///
/// 网关对 `auth.methods` 里 `type: "oauth"` 的入口**统一传 `method = "browser"`**，
/// 靠 `payload.methodIndex` 区分具体是哪一条（浏览器授权 / 设备码）。旧版网关
/// 不传 `methodIndex`，此时按浏览器授权处理；`method = "device"` 的老写法仍然认。
pub(super) async fn login_start(
    method: &str,
    payload: &Value,
) -> Result<proto::LoginStart, String> {
    let index = payload.get("methodIndex").and_then(Value::as_u64);
    match (method, index) {
        // 动态表单：#0 浏览器授权、#1 设备码。
        ("browser", Some(0)) | ("browser", None) => start_browser(payload).await,
        ("browser", Some(1)) => start_device(payload).await,
        ("browser", Some(index)) => Err(format!(
            "Codex 的登录方式 #{index} 不发起授权（#0 浏览器授权、#1 设备码；粘贴 token 走添加账号）"
        )),
        ("device", _) => start_device(payload).await,
        (other, _) => Err(format!(
            "Codex 不支持「{other}」登录方式（网页授权与设备码走 oauth 入口；粘贴 token 走添加账号）"
        )),
    }
}

async fn start_browser(payload: &Value) -> Result<proto::LoginStart, String> {
    let proxy = resolve_login_proxy(payload.get("proxy"))?;
    close_all();
    let listener = Arc::new(CallbackListener::bind().await?);
    let redirect_uri = format!(
        "http://localhost:{}{}",
        listener.port(),
        super::callback_server::PATH
    );
    let pkce = oauth::pkce().map_err(|error| error.message)?;
    let state = oauth::new_state().map_err(|error| error.message)?;
    let url = oauth::authorize_url(&redirect_uri, &state, &pkce.challenge)
        .map_err(|error| error.message)?;
    let flow_id = format!("{FLOW_PREFIX}{state}");
    with_flows(|table| {
        table.insert(
            flow_id.clone(),
            Entry {
                listener: Some(listener.clone()),
                device: None,
                state: FlowState::Waiting,
            },
        );
    });
    spawn_completion(
        flow_id.clone(),
        listener,
        state,
        pkce.verifier,
        redirect_uri,
        proxy,
    );
    Ok(proto::LoginStart {
        flow: flow_id,
        url,
        instructions: "在浏览器里完成 ChatGPT 授权；完成后本窗口会自动收到回调（也可以把回调地址整段粘回来）。"
            .to_string(),
        poll_interval_ms: 2_000,
        external_browser: false,
        allowed_hosts: Vec::new(),
    })
}

async fn start_device(payload: &Value) -> Result<proto::LoginStart, String> {
    let proxy = resolve_login_proxy(payload.get("proxy"))?;
    close_all();
    let device = oauth::device_request(proxy.as_ref())
        .await
        .map_err(|error| error.message)?;
    let flow_id = format!("{DEVICE_PREFIX}{}", oauth::new_state().map_err(|e| e.message)?);
    let device = Arc::new(device);
    with_flows(|table| {
        table.insert(
            flow_id.clone(),
            Entry {
                listener: None,
                device: Some(device.clone()),
                state: FlowState::Waiting,
            },
        );
    });
    spawn_device_poll(flow_id.clone(), device.clone(), proxy);
    Ok(proto::LoginStart {
        flow: flow_id,
        url: device.verify_url.clone(),
        instructions: format!(
            "在浏览器打开上面的地址并输入验证码 {}（{} 分钟内有效）。",
            device.user_code,
            endpoints::DEVICE_TIMEOUT_SECONDS / 60
        ),
        poll_interval_ms: device.interval_seconds.max(2) * 1000,
        external_browser: false,
        allowed_hosts: Vec::new(),
    })
}

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
            return;
        };
        set_working(&flow_id);
        let result = finish(&query, &expected_state, &verifier, &redirect_uri, proxy).await;
        match result {
            Ok(credentials) => set_done(&flow_id, credentials_to_value(&credentials)),
            Err(error) => set_failed(&flow_id, error.message),
        }
        listener.close();
    });
}

fn spawn_device_poll(flow_id: String, device: Arc<DeviceCode>, proxy: Option<ResolvedProxy>) {
    tokio::spawn(async move {
        let interval = device.interval_seconds.max(2);
        let deadline = std::time::Instant::now()
            + std::time::Duration::from_secs(endpoints::DEVICE_TIMEOUT_SECONDS);
        loop {
            if std::time::Instant::now() > deadline {
                set_failed(
                    &flow_id,
                    format!(
                        "设备码已过期（{} 分钟内没有在网页上确认），请重新发起",
                        endpoints::DEVICE_TIMEOUT_SECONDS / 60
                    ),
                );
                return;
            }
            // 已经结束的流程不再打上游。
            let alive = with_flows(|table| {
                table
                    .get(&flow_id)
                    .map(|entry| matches!(entry.state, FlowState::Waiting | FlowState::Working))
                    .unwrap_or(false)
            });
            if !alive {
                return;
            }
            match oauth::device_poll(&device, proxy.as_ref()).await {
                Ok(Some(credentials)) => {
                    set_done(&flow_id, credentials_to_value(&credentials));
                    return;
                }
                Ok(None) => {}
                Err(error) => {
                    set_failed(&flow_id, error.message);
                    return;
                }
            }
            tokio::time::sleep(std::time::Duration::from_secs(interval)).await;
        }
    });
}

/// 处理一次回调（`code#state` 或 query）。
async fn finish(
    query: &str,
    expected_state: &str,
    verifier: &str,
    redirect_uri: &str,
    proxy: Option<ResolvedProxy>,
) -> Result<CodexCredentials, GatewayError> {
    let params = parse_query(query);
    if let Some(error) = params.get("error") {
        if !error.trim().is_empty() {
            let detail = params
                .get("error_description")
                .map(|value| value.trim().to_string())
                .unwrap_or_else(|| error.trim().to_string());
            return Err(GatewayError::with_status(
                400,
                format!("Codex 授权被拒绝：{detail}"),
            ));
        }
    }
    let raw_code = params
        .get("code")
        .map(|value| percent_decode(value))
        .unwrap_or_default();
    if raw_code.trim().is_empty() {
        return Err(GatewayError::with_status(400, "Codex 回调里没有授权码"));
    }
    // 上游可能把 state 用 `#` 塞在 code 后面；这种情况下 `#` 后的 state 才是准的。
    let (code, embedded_state) = split_code_and_state(&raw_code);
    let state = if embedded_state.is_empty() {
        params
            .get("state")
            .map(|value| percent_decode(value))
            .unwrap_or_default()
    } else {
        embedded_state
    };
    if state.trim().is_empty() {
        return Err(GatewayError::with_status(
            400,
            "Codex 回调里没有 state，无法校验这次登录",
        ));
    }
    if state.trim() != expected_state.trim() {
        return Err(GatewayError::with_status(
            400,
            "Codex 回调的 state 与本轮登录不匹配（可能是过期的授权页）",
        ));
    }
    oauth::exchange_code(&code, verifier, redirect_uri, proxy.as_ref()).await
}

/// `code#state` 拆分。
fn split_code_and_state(raw: &str) -> (String, String) {
    match raw.split_once('#') {
        Some((code, state)) => (code.trim().to_string(), state.trim().to_string()),
        None => (raw.trim().to_string(), String::new()),
    }
}

/// 轮询一个登录流程。
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
        let poll = match &entry.state {
            FlowState::Waiting => proto::LoginPoll::Pending {
                hint: Some(match &entry.device {
                    Some(device) => format!("等待你在网页上确认设备码 {}…", device.user_code),
                    None => "等待你在浏览器里完成 ChatGPT 授权…".to_string(),
                }),
            },
            FlowState::Working => proto::LoginPoll::Pending {
                hint: Some("已收到授权码，正在换取凭证…".to_string()),
            },
            FlowState::Done(payload) => done_poll(payload),
            FlowState::Failed(message) => proto::LoginPoll::Failed {
                message: message.clone(),
            },
        };
        let terminal = is_terminal(&poll);
        (poll, terminal)
    });
    if terminal {
        with_flows(|table| table.remove(flow));
    }
    Ok(poll)
}

/// 手工投递回调。
pub(super) async fn login_callback(callback: &proto::LoginCallback) -> Result<proto::LoginPoll, String> {
    let query = callback_query(callback);
    let listener = with_flows(|table| table.get(&callback.flow).and_then(|entry| entry.listener.clone()));
    let Some(listener) = listener else {
        return Ok(proto::LoginPoll::Failed {
            message: "这次登录不接受粘贴回调（设备码流程请直接在网页上确认），或流程已失效".to_string(),
        });
    };
    listener.submit_callback(&query)?;
    // 换码在后台跑，这里最多等 30 秒给它一个「已完成」的机会。
    for _ in 0..60 {
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        let poll = login_poll(&callback.flow).await?;
        if is_terminal(&poll) {
            return Ok(poll);
        }
    }
    Ok(proto::LoginPoll::Pending {
        hint: Some("已收到回调，正在换取凭证…".to_string()),
    })
}

/// 取消一个登录流程。
pub(super) async fn login_cancel(flow: &str) {
    let listener = with_flows(|table| table.remove(flow).and_then(|entry| entry.listener));
    if let Some(listener) = listener {
        listener.close();
    }
}

/// 粘贴 refresh token 时的剥壳（**绝不剥 `rt_` 之类的前缀**）。
pub fn normalize_refresh_token(raw: &str) -> String {
    let mut text = raw.trim();
    if text.chars().count() > MAX_INPUT_LENGTH {
        text = &text[..MAX_INPUT_LENGTH];
    }
    let mut text = text.to_string();
    // 剥引号
    for quote in ['"', '\'', '`'] {
        if text.starts_with(quote) && text.ends_with(quote) && text.len() >= 2 {
            text = text[1..text.len() - 1].to_string();
        }
    }
    let text = text.trim().to_string();
    // 剥标签
    for label in [
        "refresh_token=",
        "refresh_token:",
        "refreshToken=",
        "refreshToken:",
        "token=",
        "token:",
    ] {
        if let Some(rest) = text.strip_prefix(label) {
            return rest.trim().trim_matches('"').trim().to_string();
        }
    }
    // 剥 Bearer
    let lowered = text.to_ascii_lowercase();
    if let Some(rest) = lowered.strip_prefix("bearer ") {
        let start = text.len() - rest.len();
        return text[start..].trim().to_string();
    }
    // 整段回调地址：从 query 里取
    if text.contains("://") || text.starts_with('?') {
        if let Some(token) = token_from_url(&text) {
            return token;
        }
    }
    text
}

fn token_from_url(text: &str) -> Option<String> {
    let query = match text.split_once('?') {
        Some((_, query)) => query,
        None => return None,
    };
    let params = parse_query(query);
    for key in ["refresh_token", "refreshToken", "token", "code"] {
        if let Some(value) = params.get(key) {
            let decoded = percent_decode(value);
            let trimmed = decoded.trim();
            if !trimmed.is_empty() {
                return Some(trimmed.to_string());
            }
        }
    }
    None
}

/// 粘贴式登录：真刷新校验一遍。
pub(super) async fn verify_paste(
    payload: &Value,
    proxy: Option<&ResolvedProxy>,
) -> Result<CodexCredentials, GatewayError> {
    let raw = ["refreshToken", "refresh_token", "token", "credential"]
        .iter()
        .find_map(|key| payload.get(*key).and_then(Value::as_str))
        .unwrap_or_default();
    let token = normalize_refresh_token(raw);
    if token.is_empty() {
        return Err(GatewayError::with_status(
            400,
            "没有读到 Codex refresh token（请粘贴以 rt_ 开头的 refresh token，或整段回调地址）",
        ));
    }
    let refreshed = oauth::refresh_access_token(&token, proxy).await?;
    Ok(refreshed.credentials)
}

fn credentials_to_value(credentials: &CodexCredentials) -> Value {
    let mut value = json!({
        "refreshToken": credentials.refresh_token,
        "accessToken": credentials.access_token,
        "expiresAt": credentials.expires_at,
    });
    if let Some(object) = value.as_object_mut() {
        if !credentials.id_token.trim().is_empty() {
            object.insert(
                "idToken".to_string(),
                Value::String(credentials.id_token.clone()),
            );
        }
        if !credentials.account_id.trim().is_empty() {
            object.insert(
                "accountId".to_string(),
                Value::String(credentials.account_id.clone()),
            );
        }
        if !credentials.plan_type.trim().is_empty() {
            object.insert(
                "planType".to_string(),
                Value::String(credentials.plan_type.clone()),
            );
        }
        if !credentials.email.trim().is_empty() {
            object.insert("email".to_string(), Value::String(credentials.email.clone()));
        }
    }
    value
}

fn done_poll(payload: &Value) -> proto::LoginPoll {
    match super::credentials::from_record(Some(payload)) {
        Ok(credentials) => proto::LoginPoll::Done {
            account: accounts::account_of(&credentials, "browser", None),
        },
        Err(error) => proto::LoginPoll::Failed {
            message: error.message,
        },
    }
}

fn is_terminal(poll: &proto::LoginPoll) -> bool {
    !matches!(poll, proto::LoginPoll::Pending { .. })
}

fn set_working(flow_id: &str) {
    with_flows(|table| {
        if let Some(entry) = table.get_mut(flow_id) {
            entry.state = FlowState::Working;
        }
    });
}

fn set_done(flow_id: &str, payload: Value) {
    with_flows(|table| {
        if let Some(entry) = table.get_mut(flow_id) {
            entry.state = FlowState::Done(payload);
        }
    });
}

fn set_failed(flow_id: &str, message: String) {
    with_flows(|table| {
        if let Some(entry) = table.get_mut(flow_id) {
            entry.state = FlowState::Failed(message);
        }
    });
}

fn callback_query(callback: &proto::LoginCallback) -> String {
    let code = callback.code.trim();
    if !code.is_empty() {
        return code.to_string();
    }
    let url = callback.url.trim();
    match url.split_once('?') {
        Some((_, query)) => query.to_string(),
        None => url.to_string(),
    }
}

fn parse_query(query: &str) -> HashMap<String, String> {
    let mut params = HashMap::new();
    for pair in query.split('&') {
        if let Some((key, value)) = pair.split_once('=') {
            params.insert(key.to_string(), value.to_string());
        }
    }
    params
}

pub(super) fn percent_decode(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'+' => {
                out.push(b' ');
                index += 1;
            }
            b'%' if index + 2 < bytes.len() => {
                let hex = &value[index + 1..index + 3];
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
    let Some(value) = raw else {
        return Ok(None);
    };
    if value.is_null() {
        return Ok(None);
    }
    if let Ok(proxy) = serde_json::from_value::<ResolvedProxy>(value.clone()) {
        if !proxy.host.trim().is_empty() {
            return Ok(Some(proxy));
        }
    }
    match crate::proxy_util::resolve_account_proxy(Some(value)) {
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
    fn a_hash_separated_state_wins() {
        let (code, state) = split_code_and_state("abc#xyz");
        assert_eq!(code, "abc");
        assert_eq!(state, "xyz");
    }

    #[test]
    fn a_plain_code_has_no_state() {
        let (code, state) = split_code_and_state("abc");
        assert_eq!(code, "abc");
        assert!(state.is_empty());
    }

    #[test]
    fn percent_decode_handles_plus_and_escapes() {
        assert_eq!(percent_decode("a+b"), "a b");
        assert_eq!(percent_decode("a%2Fb"), "a/b");
        assert_eq!(percent_decode("100%"), "100%");
    }

    #[test]
    fn pasting_strips_wrappers_but_not_the_token_body() {
        assert_eq!(normalize_refresh_token("  rt_abc  "), "rt_abc");
        assert_eq!(normalize_refresh_token("\"rt_abc\""), "rt_abc");
        assert_eq!(normalize_refresh_token("refresh_token=rt_abc"), "rt_abc");
        assert_eq!(normalize_refresh_token("Bearer rt_abc"), "rt_abc");
    }

    #[test]
    fn a_callback_url_yields_the_token() {
        let token = normalize_refresh_token("http://localhost:1455/auth/callback?code=abc&state=st");
        assert_eq!(token, "abc");
    }

    #[test]
    fn query_parsing_keeps_raw_values() {
        let params = parse_query("code=a%2Fb&state=st");
        assert_eq!(params.get("code").map(String::as_str), Some("a%2Fb"));
        assert_eq!(params.get("state").map(String::as_str), Some("st"));
    }

    #[test]
    fn callback_query_prefers_the_code_field() {
        let callback = proto::LoginCallback {
            flow: "f".to_string(),
            code: "direct-code".to_string(),
            url: "http://localhost/cb?code=from-url".to_string(),
        };
        assert_eq!(callback_query(&callback), "direct-code");
    }

    // ── auth.methods 的契约 ────────────────────────────────────
    // 网关对这份 JSON 做严格校验，任何一条不合规都会让整个添加账号弹窗
    // 报「插件返回了无效的登录方式」。下面按网关的规则逐条断言。

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
        assert!(!methods.is_empty());

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

            if let Some(input) = method.get("callbackInput") {
                let input = input.as_str().expect("callbackInput 必须是字符串");
                assert!(input == "url" || input == "code");
                if input == "code" {
                    assert_eq!(method["manualCallback"], true);
                }
            }

            if kind == "api" {
                for flag in ["localOnly", "manualCallback", "embeddedOnly"] {
                    assert_ne!(method[flag], true, "api 方式不能把 {flag} 设为 true");
                }
            }

            let prompts = method["prompts"].as_array().expect("prompts 必须是数组");
            let mut keys = Vec::new();
            for prompt in prompts {
                let key = prompt["key"].as_str().expect("prompt.key 必须是字符串");
                assert!(key_is_valid(key), "prompt.key 不合规：{key}");
                assert!(!["__proto__", "prototype", "constructor", "signal"].contains(&key));
                assert!(!keys.contains(&key), "prompt.key 不能重复：{key}");
                keys.push(key);
                let prompt_kind = prompt["type"].as_str().expect("prompt.type 必须是字符串");
                assert!(prompt_kind == "text" || prompt_kind == "select");
                if prompt["secret"] == true {
                    assert!(prompt.get("default").is_none(), "secret 字段不接受 default");
                }
            }
        }

        // 三条入口：浏览器授权、设备码、粘贴 token。
        assert!(methods.iter().any(|m| m["methodIndex"] == 0 && m["type"] == "oauth"));
        assert!(methods.iter().any(|m| m["methodIndex"] == 1 && m["type"] == "oauth"));
        let paste = methods
            .iter()
            .find(|method| method["label"] == "粘贴 refresh token")
            .expect("缺少粘贴 token 入口");
        assert_eq!(paste["type"], "api", "粘贴 token 必须走 api 类型");
    }

    #[tokio::test]
    async fn the_index_picks_between_browser_and_device() {
        // #2 是 api 类型，网关不会调 login.start；万一手工调过来要明确报错。
        let payload = json!({ "methodIndex": 2 });
        let error = login_start("browser", &payload)
            .await
            .expect_err("#2 不该发起授权");
        assert!(error.contains("#2"), "错误里要指认索引，实际：{error}");
    }
}
