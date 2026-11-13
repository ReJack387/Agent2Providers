//! Codex 的 loopback 回调服务器。
//!
//! ── 与 Antigravity / Claude 两家的差别 ──────────────────────
//! 路径是 `/auth/callback`（参考实现 `mux.HandleFunc("/auth/callback", ...)`，
//! 与 `RedirectURI = http://localhost:1455/auth/callback` 对齐），端口优先用
//! 参考实现那个 **1455**（Codex CLI 已登录时可能占着它，所以被占用必须能退让
//! 到随机端口，而不是直接报错）。
//!
//! ── 为什么端口可退让 ────────────────────────────────────────
//! 参考实现固定 1455，占用时报 `ErrPortInUse`。在插件里这会让「本机装了
//! Codex CLI 的用户」完全无法登录 —— 而 `redirect_uri` 是授权 URL 的参数
//! （不是预登记常量），换端口不影响换码。

use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::Mutex;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::{mpsc, watch};

use crate::logging;

/// 回调路径。
pub use super::endpoints::CALLBACK_PATH as PATH;

/// 一个正在监听的回调入口。
pub struct CallbackListener {
    port: u16,
    shutdown: watch::Sender<bool>,
    sender: Mutex<Option<mpsc::UnboundedSender<String>>>,
    inbox: tokio::sync::Mutex<mpsc::UnboundedReceiver<String>>,
}

impl CallbackListener {
    /// 绑一个 loopback 端口（IPv4 必须成功；IPv6 尽力而为）。
    ///
    /// 端口选择：`CODEX_CALLBACK_PORT` 显式指定时用它；否则先试参考实现的
    /// 1455，被占用再退到系统分配的空闲端口。
    pub async fn bind() -> Result<Self, String> {
        let explicit = std::env::var(super::endpoints::ENV_CALLBACK_PORT)
            .ok()
            .and_then(|raw| raw.trim().parse::<u16>().ok())
            .filter(|port| *port > 0);
        let listener = match explicit {
            Some(port) => TcpListener::bind((Ipv4Addr::LOCALHOST, port))
                .await
                .map_err(|error| {
                    format!(
                        "绑定本机回调端口 {port} 失败：{error}（可用 {}=0 换随机端口）",
                        super::endpoints::ENV_CALLBACK_PORT
                    )
                })?,
            None => match TcpListener::bind((
                Ipv4Addr::LOCALHOST,
                super::endpoints::DEFAULT_CALLBACK_PORT,
            ))
            .await
            {
                Ok(listener) => listener,
                Err(error) => {
                    logging::verbose(
                        "[Codex]",
                        &format!(
                            "回调端口 {} 不可用（{error}），改用随机端口",
                            super::endpoints::DEFAULT_CALLBACK_PORT
                        ),
                    );
                    TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
                        .await
                        .map_err(|error| format!("绑定本机回调端口失败：{error}"))?
                }
            },
        };
        let port = listener
            .local_addr()
            .map_err(|error| format!("读取回调端口失败：{error}"))?
            .port();
        let (sender, receiver) = mpsc::unbounded_channel::<String>();
        let (shutdown, shutdown_rx) = watch::channel(false);
        spawn_server(listener, sender.clone(), shutdown_rx.clone());
        // IPv6 尽力而为：有些系统把 localhost 解析到 ::1。
        if let Ok(listener) = TcpListener::bind((Ipv6Addr::LOCALHOST, port)).await {
            spawn_server(listener, sender.clone(), shutdown_rx);
        }
        logging::log(
            "[Login]",
            &format!("Codex OAuth 回调已监听 127.0.0.1:{port}{PATH}"),
        );
        Ok(Self {
            port,
            shutdown,
            sender: Mutex::new(Some(sender)),
            inbox: tokio::sync::Mutex::new(receiver),
        })
    }

    pub fn port(&self) -> u16 {
        self.port
    }

    /// 关掉监听（幂等）。
    pub fn close(&self) {
        if let Ok(mut guard) = self.sender.lock() {
            guard.take();
        }
        let _ = self.shutdown.send(true);
    }

    /// 等下一次回调（`None` = 已关闭）。
    pub async fn next_callback(&self) -> Option<String> {
        self.inbox.lock().await.recv().await
    }

    /// 手工投递一次回调（用户把回调地址整段粘回来时）。
    pub fn submit_callback(&self, query: &str) -> Result<(), String> {
        let trimmed = query.trim();
        if trimmed.is_empty() {
            return Err("回调地址是空的".to_string());
        }
        if !carries_credential(trimmed) {
            return Err("回调地址没有携带可用的 Codex 授权信息".to_string());
        }
        let sender = self
            .sender
            .lock()
            .map_err(|_| "回调通道不可用".to_string())?
            .clone()
            .ok_or_else(|| "Codex 登录任务已结束，请重新发起".to_string())?;
        sender
            .send(trimmed.to_string())
            .map_err(|_| "Codex 登录任务已结束，请重新发起".to_string())
    }
}

impl Drop for CallbackListener {
    fn drop(&mut self) {
        let _ = self.shutdown.send(true);
    }
}

/// 这段 query 里是否真带了一次授权结果。
///
/// 只判 `contains("code=")` 不够：浏览器预连接、`code=&state=x` 这类空值都会
/// 被当成有效回调，投递进去之后换码失败，用户看到的却是一个「登录失败」而
/// 不是「这不是回调」。所以要求 `=` 之后至少有一个非 `&` 的字符。
fn carries_credential(query: &str) -> bool {
    query.split('&').any(|pair| {
        let Some((key, value)) = pair.split_once('=') else {
            return false;
        };
        let key = key.trim();
        if key != "code" && key != "error" {
            return false;
        }
        !value.trim().is_empty()
    })
}

fn spawn_server(
    listener: TcpListener,
    sender: mpsc::UnboundedSender<String>,
    mut shutdown: watch::Receiver<bool>,
) {
    tokio::spawn(async move {
        loop {
            if *shutdown.borrow() {
                return;
            }
            tokio::select! {
                accepted = listener.accept() => {
                    match accepted {
                        Ok((stream, _)) => {
                            let sender = sender.clone();
                            tokio::spawn(serve_one(stream, sender));
                        }
                        Err(error) => {
                            logging::verbose("[Codex]", &format!("回调 accept 失败：{error}"));
                        }
                    }
                }
                _ = shutdown.changed() => return,
            }
        }
    });
}

async fn serve_one(mut stream: tokio::net::TcpStream, sender: mpsc::UnboundedSender<String>) {
    let mut buffer = Vec::with_capacity(1024);
    let mut chunk = [0u8; 1024];
    loop {
        match tokio::time::timeout(Duration::from_secs(5), stream.read(&mut chunk)).await {
            Ok(Ok(0)) | Err(_) => break,
            Ok(Ok(read)) => {
                buffer.extend_from_slice(&chunk[..read]);
                if buffer.windows(4).any(|window| window == b"\r\n\r\n") || buffer.len() >= 8192 {
                    break;
                }
            }
            Ok(Err(_)) => return,
        }
    }
    let text = String::from_utf8_lossy(&buffer);
    let request_line = text.lines().next().unwrap_or_default();
    let mut parts = request_line.split_whitespace();
    let _method = parts.next().unwrap_or_default();
    let target = parts.next().unwrap_or_default();
    let (path, query) = match target.split_once('?') {
        Some((path, query)) => (path, query),
        None => (target, ""),
    };
    if path != PATH {
        respond(&mut stream, 404, "Not found", "这不是 Codex 的登录回调地址。").await;
        return;
    }
    // 过滤浏览器预连接 / favicon 之类的噪音：既没 code 也没 error 就不投递。
    if !carries_credential(query) {
        respond(&mut stream, 404, "Not found", "回调地址没有携带授权信息。").await;
        return;
    }
    if sender.send(query.to_string()).is_err() {
        respond(
            &mut stream,
            410,
            "Login expired",
            "这次登录已经结束，请回到面板重新发起。",
        )
        .await;
        return;
    }
    respond(
        &mut stream,
        200,
        "Login successful",
        "You can close this window now.",
    )
    .await;
}

async fn respond(stream: &mut tokio::net::TcpStream, status: u16, title: &str, message: &str) {
    let escaped = message.replace('<', "&lt;").replace('>', "&gt;");
    let body = format!(
        "<!doctype html><meta charset=\"utf-8\"><title>{title}</title>\
         <div style=\"font:16px/1.6 system-ui;padding:40px;text-align:center\">\
         <h2>{title}</h2><p>{escaped}</p></div>"
    );
    let reason = match status {
        200 => "OK",
        404 => "Not Found",
        410 => "Gone",
        _ => "OK",
    };
    let head = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    let _ = stream.write_all(head.as_bytes()).await;
    let _ = stream.write_all(body.as_bytes()).await;
    let _ = stream.flush().await;
}

#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_callback_path_matches_the_reference_redirect_uri() {
        assert_eq!(PATH, "/auth/callback");
    }

    #[tokio::test]
    async fn bind_picks_a_port_and_closes_idempotently() {
        let listener = CallbackListener::bind().await.expect("bind");
        assert!(listener.port() > 0);
        listener.close();
        listener.close();
        // 关掉之后 next_callback 立刻返回 None（sender 被 take 掉，channel 关闭）。
        assert!(listener.next_callback().await.is_none());
    }

    #[tokio::test]
    async fn submit_rejects_noise_and_accepts_a_code() {
        let listener = CallbackListener::bind().await.expect("bind");
        assert!(listener.submit_callback("").is_err());
        assert!(listener.submit_callback("code=&nothing").is_err());
        assert!(listener.submit_callback("code=&state=st").is_err());
        assert!(listener.submit_callback("state=st").is_err());
        assert!(listener.submit_callback("code=abc&state=st").is_ok());
        let received = listener.next_callback().await;
        assert_eq!(received.as_deref(), Some("code=abc&state=st"));
        listener.close();
    }

    #[test]
    fn only_a_filled_code_or_error_counts_as_a_callback() {
        assert!(carries_credential("code=abc"));
        assert!(carries_credential("error=access_denied"));
        assert!(carries_credential("state=st&code=abc"));
        assert!(!carries_credential("code="));
        assert!(!carries_credential("code=&state=st"));
        assert!(!carries_credential("state=st"));
        assert!(!carries_credential(""));
    }
}
