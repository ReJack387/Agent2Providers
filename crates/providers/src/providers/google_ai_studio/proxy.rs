//! 从账号记录里解析出网代理。
//!
//! ── 为什么这家要自己解析（不能只靠 `ctx.env.proxy`）────────────
//! `ctx.env.proxy` 是**网关默认出口**。用户把代理配在账号上时它是空的，直接用
//! 就会去直连 `generativelanguage.googleapis.com` —— 表现是「聊天能用、拉模型
//! 目录超时」，因为聊天走 `conversation`，网关会把选路结果放进 `request.proxy`；
//! 而 `models.refresh` 的网关分支只带 `account` 与 `force`，**不传 proxy**
//! （见网关 `plugin_host__rpc.rs` 的 `MODELS_REFRESH` 分支）。
//!
//! 所以两条路径都要兜一层账号代理：能拿到就用自己的，拿不到才退回默认出口。

use agent2api_provider_protocol as proto;
use agent2api_provider_sdk::{StoreAccount, StoreProxy};

/// 取账号自己的出口；`None` = 账号没配代理，调用方应退回网关默认出口。
///
/// 返回 `Err` 的两种情形都是**配置问题**，不能静默降级成直连 —— 用户以为
/// 自己配了代理，直连只会得到一次超时，比一条明确的报错难排查得多。
pub fn of_account(account: &StoreAccount) -> Result<Option<proto::WireProxy>, String> {
    resolve(account.proxy.as_ref())
}

/// 解析 `StoreProxy` 四态。
pub fn resolve(proxy: Option<&StoreProxy>) -> Result<Option<proto::WireProxy>, String> {
    match proxy {
        // 网关已经解析好了，直接用
        Some(StoreProxy::Resolved { proxy }) => Ok(Some(proxy.clone())),
        // 只给了原始配置，按仓库通用的规则解析
        Some(StoreProxy::Static { config }) => {
            match crate::proxy_util::resolve_account_proxy(Some(config)) {
                Some(crate::proxy_util::ProxyResolution::Resolved(proxy)) => Ok(Some(proxy)),
                Some(crate::proxy_util::ProxyResolution::Failed(message)) => {
                    Err(format!("账号代理配置有误：{message}"))
                }
                None => Ok(None),
            }
        }
        // 网关解析失败过，把原因透传出去
        Some(StoreProxy::Failed { message }) => Err(format!("账号代理不可用：{message}")),
        Some(StoreProxy::Unset) | None => Ok(None),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn wire(host: &str, port: u16) -> proto::WireProxy {
        proto::WireProxy {
            protocol: "http".into(),
            host: host.into(),
            port: Some(port),
            username: String::new(),
            password: String::new(),
        }
    }

    #[test]
    fn unset_means_follow_the_gateway_default() {
        assert!(resolve(None).unwrap().is_none());
        assert!(resolve(Some(&StoreProxy::Unset)).unwrap().is_none());
    }

    #[test]
    fn resolved_is_used_as_is() {
        let proxy = StoreProxy::Resolved {
            proxy: wire("127.0.0.1", 7890),
        };
        let parsed = resolve(Some(&proxy)).unwrap().unwrap();
        assert_eq!(parsed.host, "127.0.0.1");
        assert_eq!(parsed.port, Some(7890));
    }

    #[test]
    fn static_config_is_parsed() {
        let proxy = StoreProxy::Static {
            config: serde_json::json!({
                "url": "socks5://user:pass@10.0.0.2:1080"
            }),
        };
        let parsed = resolve(Some(&proxy)).unwrap().unwrap();
        assert_eq!(parsed.protocol, "socks5");
        assert_eq!(parsed.host, "10.0.0.2");
        assert_eq!(parsed.port, Some(1080));
        assert_eq!(parsed.username, "user");
    }

    #[test]
    fn static_direct_config_falls_back_to_default() {
        let proxy = StoreProxy::Static {
            config: serde_json::json!({ "source": "direct" }),
        };
        assert!(resolve(Some(&proxy)).unwrap().is_none());
    }

    #[test]
    fn failed_and_broken_configs_are_reported_not_silently_direct() {
        let failed = StoreProxy::Failed {
            message: "凭据过期".into(),
        };
        let error = resolve(Some(&failed)).unwrap_err();
        assert!(error.contains("账号代理不可用"), "{error}");
        assert!(error.contains("凭据过期"), "{error}");

        // 网关托管但插件拿不到实际出口（system / rotate / pool / clash）
        let unresolved = StoreProxy::Static {
            config: serde_json::json!({ "source": "system" }),
        };
        let error = resolve(Some(&unresolved)).unwrap_err();
        assert!(error.contains("账号代理配置有误"), "{error}");
    }
}
