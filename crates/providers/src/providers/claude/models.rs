//! Claude 的模型目录：静态清单（按账号可裁剪）。
//!
//! ── 为什么不探测 ────────────────────────────────────────────
//! 参考实现 `cliproxy/service_models.go:148-158` 对 `"claude"` 走的是
//! `registry.GetClaudeModels()` —— **一份静态清单**，没有远程目录接口
//! （不像 Antigravity 要打 `fetchAvailableModels`）。Claude 的 `/v1/models`
//! 只在 API key 鉴权下可用，OAuth 令牌打过去是 403，因此不能当目录源。
//!
//! ── 清单从哪来 ──────────────────────────────────────────────
//! 全部取自参考实现里出现过的确切模型 id（`CliProxyAPI-sdk` 的测试与
//! `registry` 调用点）。**不自行发明** `-latest` / `-preview` 这类后缀 ——
//! 猜错后缀的症状是「界面上有、一发就 404」。
//!
//! ── 为什么 `-thinking` 只在 Opus 上出现 ─────────────────────
//! 参考实现里 `claude-opus-4-6-thinking` 是独立 id（Antigravity 家的别名表
//! 也把它当成独立目标），而 Sonnet 的思考是靠请求体 `thinking` 参数开的，
//! 不是独立模型名。因此这里只给 Opus 挂 `-thinking` 变体。

use serde_json::{json, Value};

/// 一条静态模型：(id, 显示名, 输入上限, 输出上限, 是否支持思考)。
///
/// 上限取自 Claude 公开的上下文窗口（200K 输入 / 64K 输出）。Haiku 的窗口
/// 与 Sonnet/Opus 相同，但输出上限更低。
const MODELS: &[(&str, &str, i64, i64, bool)] = &[
    ("claude-sonnet-4-6", "Claude Sonnet 4.6", 200_000, 64_000, true),
    ("claude-opus-4-6", "Claude Opus 4.6", 200_000, 32_000, true),
    (
        "claude-opus-4-6-thinking",
        "Claude Opus 4.6 Thinking",
        200_000,
        32_000,
        true,
    ),
    ("claude-opus-4-5", "Claude Opus 4.5", 200_000, 32_000, true),
    ("claude-sonnet-4-5", "Claude Sonnet 4.5", 200_000, 64_000, true),
    (
        "claude-sonnet-4-5-20250929",
        "Claude Sonnet 4.5 (2025-09-29)",
        200_000,
        64_000,
        true,
    ),
    ("claude-sonnet-4", "Claude Sonnet 4", 200_000, 64_000, true),
    (
        "claude-haiku-4-5-20251001",
        "Claude Haiku 4.5",
        200_000,
        32_000,
        false,
    ),
    ("claude-3-7-sonnet", "Claude 3.7 Sonnet", 200_000, 64_000, true),
    (
        "claude-3-7-sonnet-20250219",
        "Claude 3.7 Sonnet (2025-02-19)",
        200_000,
        64_000,
        true,
    ),
    (
        "claude-3-5-sonnet",
        "Claude 3.5 Sonnet",
        200_000,
        8_192,
        false,
    ),
    (
        "claude-3-5-sonnet-20241022",
        "Claude 3.5 Sonnet (2024-10-22)",
        200_000,
        8_192,
        false,
    ),
    ("claude-3-5-haiku", "Claude 3.5 Haiku", 200_000, 8_192, false),
    (
        "claude-3-opus-20240229",
        "Claude 3 Opus (2024-02-29)",
        200_000,
        4_096,
        false,
    ),
];

/// 默认模型（新建会话时不指定模型就用它）。
pub const DEFAULT_MODEL: &str = "claude-sonnet-4-6";

/// 静态清单（`meta().default_models` 与 `models()` 共用）。
pub fn catalog() -> Vec<Value> {
    MODELS
        .iter()
        .map(|(id, name, input, output, thinking)| {
            json!({
                "id": id,
                "name": name,
                "maxInputTokens": input,
                "maxOutputTokens": output,
                "supportsToolCall": true,
                "supportsImages": true,
                "supportsReasoning": thinking,
                "supportsThinking": thinking,
                "isDefault": *id == DEFAULT_MODEL,
            })
        })
        .collect()
}

/// 这个 id 是不是本家认的模型。
///
/// ── 为什么用前缀而不是白名单 ────────────────────────────────
/// 上游会先上新模型、后改文档；用前缀（`claude-`）放行，客户端带新 id 时
/// 直接透传就能用。白名单会把「上游已经支持」的请求挡在插件里。
pub fn is_known_model(id: &str) -> bool {
    id.trim().to_ascii_lowercase().starts_with("claude-")
}

/// 该模型是否支持思考档（决定界面给不给开关）。
pub fn supports_thinking(id: &str) -> bool {
    let lowered = id.trim().to_ascii_lowercase();
    if lowered.contains("haiku") {
        return false;
    }
    lowered.contains("sonnet")
        || lowered.contains("opus")
        || lowered.contains("thinking")
        || lowered.contains("4-6")
        || lowered.contains("4-5")
        || lowered.contains("3-7")
}

#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_entry_has_the_fields_the_gateway_renders() {
        for record in catalog() {
            for key in ["id", "name", "maxInputTokens", "maxOutputTokens"] {
                assert!(record.get(key).is_some(), "{key} missing");
            }
            assert_eq!(
                record["supportsToolCall"],
                Value::Bool(true),
                "Claude 全线支持工具调用"
            );
        }
    }

    #[test]
    fn exactly_one_model_is_the_default() {
        let defaults: Vec<_> = catalog()
            .into_iter()
            .filter(|record| record["isDefault"] == Value::Bool(true))
            .collect();
        assert_eq!(defaults.len(), 1);
        assert_eq!(defaults[0]["id"], Value::String(DEFAULT_MODEL.to_string()));
    }

    #[test]
    fn no_duplicate_ids() {
        let records = catalog();
        let mut ids: Vec<&str> = records
            .iter()
            .filter_map(|record| record["id"].as_str())
            .collect();
        let total = ids.len();
        ids.sort_unstable();
        ids.dedup();
        assert_eq!(ids.len(), total, "静态清单里不该有重复 id");
    }

    #[test]
    fn unknown_prefixes_are_rejected_but_new_claude_versions_pass() {
        assert!(is_known_model("claude-sonnet-4-6"));
        assert!(is_known_model("claude-5-0-sonnet"), "新版本要能透传");
        assert!(!is_known_model("gpt-5"));
        assert!(!is_known_model(""));
    }

    #[test]
    fn haiku_has_no_thinking_toggle() {
        assert!(!supports_thinking("claude-3-5-haiku"));
        assert!(supports_thinking("claude-sonnet-4-6"));
        assert!(supports_thinking("claude-opus-4-6-thinking"));
    }
}
