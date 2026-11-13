//! Claude 网页登录的本机回调监听器（一次登录一个，随机端口）。
//!
//! 结构与 Antigravity 那份一致（自绑 loopback 端口、只读请求头、认不出授权
//! 材料就 404 继续等），差别只有两处：
//!   1. 路径是 `/callback`（Claude 的 `redirect_uri` 是
//!      `http://localhost:54545/callback`，不是 `/oauth-callback`）；
//!   2. 页面文案换成 Claude。
//!
//! ── 为什么不用固定端口 54545 ────────────────────────────────
//! 参考实现把端口固定成 54545 并在占用时报 `ErrPortInUse`。插件里同时可能有
//! 多个面板/多个账号在登录，固定端口会互相打架；而 Claude 的授权页接受任意
//! `http://localhost:<port>/callback`（redirect_uri 是授权 URL 的参数，不是
//! 预先登记的常量），所以随机端口完全可行，还免掉「端口被占」这一整类失败。
//!
//! ── 硬约束 ──────────────────────────────────────────────────
//! release 是 `panic=abort`：本文件零 unwrap / expect / panic。

use std::net::Ipv4Addr;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, watch};

use crate::logging;

/// 回调路径（转导出，供 `login` 拼 `redirect_uri` 用）。
pub use super::endpoints::CALLBACK_PATH as PATH;

/// 一次登录占用的 loopback 监听器。
pub struct CallbackListener {
    port: u16,
    shutdown: watch::Sender<bool>,
    sender: std::sync::Mutex<Option<mpsc::UnboundedSender<String>>>,
    inbox: tokio::sync::Mutex<mpsc::UnboundedReceiver<String>>,
}

impl CallbackListener {
    /// 绑一个空闲 loopback 端口（IPv4 必须成功；IPv6 尽力而为）。
    ///
    /// 端口选择：`CLAUDE_CALLBACK_PORT` 显式指定时用它（调试 / 需要与既有
    /// 登记地址对齐时），否则取系统分配的空闲端口。
    pub async fn bind() -> Result<Self, String> {
        let preferred = std::env::var(super::endpoints::ENV_CALLBACK_PORT)
            .ok()
            .and_then(|raw| raw.trim().parse::<u16>().ok())
            .filter(|port| *port > 0);
        let listener = match preferred {
            Some(port) => TcpListener::bind((Ipv4Addr::LOCALHOST, port))
                .await
                .map_err(|error| format!("绑定本机回调端口 {port} 失败：{error}（可用 {}=0 换随机端口）", super::endpoints::ENV_CALLBACK_PORT))?,
            None => TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
                .await
                .map_err(|error| format!("绑定本机回调端口失败：{error}"))?,
        };
        let port = listener
            .local_addr()
            .map_err(|error| format!("读不到回调端口：{error}"))?
            .port();
        let (shutdown, receiver) = watch::channel(false);
        let (sender, inbox) = mpsc::unbounded_channel();
        spawn_server(listener, sender.clone(), receiver.clone());
        // 浏览器把 localhost 解析成 ::1 时也要有人接。
        if let Ok(v6) = TcpListener::bind((std::net::Ipv6Addr::LOCALHOST, port)).await {
            spawn_server(v6, sender.clone(), receiver);
        }
        logging::log(
            "[Login]",
            &format!("Claude OAuth 回调已监听 127.0.0.1:{port}{PATH}"),
        );
        Ok(Self {
            port,
            shutdown,
            sender: std::sync::Mutex::new(Some(sender)),
            inbox: tokio::sync::Mutex::new(inbox),
        })
    }

    /// 这一轮占到的端口（拼 `redirect_uri` 用）。
    pub fn port(&self) -> u16 {
        self.port
    }

    /// 主动收摊（幂等）。
    pub fn close(&self) {
        self.sender
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .take();
        let _ = self.shutdown.send(true);
    }

    /// 等下一次真回调；`None` = 监听器已关闭。
    pub async fn next_callback(&self) -> Option<String> {
        let mut guard = self.inbox.lock().await;
        guard.recv().await
    }

    /// 从接口注入一条用户粘贴的回调 query。
    pub fn submit_callback(&self, query: &str) -> Result<(), String> {
        let parsed = parse_query(query);
        let has_code = parsed
            .get("code")
            .is_some_and(|value| !value.trim().is_empty());
        let has_error = parsed
            .get("error")
            .is_some_and(|value| !value.trim().is_empty());
        if !has_code && !has_error {
            return Err("回调地址没有携带可用的 Claude 授权信息".to_string());
        }
        let sender = self
            .sender
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .clone()
            .ok_or_else(|| "Claude 登录任务已结束，请重新发起".to_string())?;
        sender
            .send(query.to_string())
            .map_err(|_| "Claude 登录任务已结束，请重新发起".to_string())
    }
}

impl Drop for CallbackListener {
    fn drop(&mut self) {
        let _ = self.shutdown.send(true);
    }
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
                        Ok((stream, _peer)) => {
                            let sender = sender.clone();
                            tokio::spawn(async move {
                                serve_one(stream, sender).await;
                            });
                        }
                        Err(error) => {
                            logging::verbose(
                                "[Login]",
                                &format!("Claude 回调 accept 失败：{error}"),
                            );
                        }
                    }
                }
                _ = shutdown.changed() => return,
            }
        }
    });
}

async fn serve_one(mut stream: TcpStream, sender: mpsc::UnboundedSender<String>) {
    let mut buffer = Vec::with_capacity(1024);
    let mut chunk = [0u8; 1024];
    loop {
        let read = match tokio::time::timeout(
            std::time::Duration::from_secs(5),
            stream.read(&mut chunk),
        )
        .await
        {
            Ok(Ok(0)) | Err(_) => break,
            Ok(Ok(read)) => read,
            Ok(Err(_)) => return,
        };
        buffer.extend_from_slice(&chunk[..read]);
        if buffer.windows(4).any(|window| window == b"\r\n\r\n") {
            break;
        }
        if buffer.len() >= 8192 {
            break;
        }
    }
    let head = String::from_utf8_lossy(&buffer);
    let request_line = head.lines().next().unwrap_or_default();
    let mut parts = request_line.split_whitespace();
    let _method = parts.next().unwrap_or_default();
    let target = parts.next().unwrap_or_default();
    let (path, query) = match target.split_once('?') {
        Some((path, query)) => (path, query),
        None => (target, ""),
    };
    if path != PATH {
        respond(&mut stream, 404, "Not Found", "Not Found").await;
        return;
    }
    let parsed = parse_query(query);
    let has_code = parsed
        .get("code")
        .is_some_and(|value| !value.trim().is_empty());
    let has_error = parsed
        .get("error")
        .is_some_and(|value| !value.trim().is_empty());
    if !has_code && !has_error {
        respond(&mut stream, 404, "Not Found", "Not Found").await;
        return;
    }
    if sender.send(query.to_string()).is_err() {
        respond(
            &mut stream,
            410,
            "Login expired",
            "这一轮登录已经结束，请回到面板重新发起。",
        )
        .await;
        return;
    }
    if has_error {
        let message = parsed.get("error").cloned().unwrap_or_default();
        respond(&mut stream, 200, "Login failed", &message).await;
    } else {
        respond(
            &mut stream,
            200,
            "Login successful",
            "You can close this window now.",
        )
        .await;
    }
}

fn parse_query(query: &str) -> std::collections::HashMap<String, String> {
    query
        .split('&')
        .filter_map(|pair| pair.split_once('='))
        .map(|(key, value)| (key.to_string(), value.to_string()))
        .collect()
}

async fn respond(stream: &mut TcpStream, status: u16, title: &str, message: &str) {
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
    let response = format!(
        "HTTP/1.1 {status} {reason}\r\n\
         Content-Type: text/html; charset=utf-8\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\
         \r\n{body}",
        body.len()
    );
    let _ = stream.write_all(response.as_bytes()).await;
    let _ = stream.flush().await;
}
