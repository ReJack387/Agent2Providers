//! `thoughtSignature` 的往返：响应侧提取、请求侧回填。
//!
//! ── 为什么需要它 ─────────────────────────────────────────────
//! Gemini 对**历史回放**里的 `functionCall` 强制要求带 `thoughtSignature`：
//! 不带直接 400（「Function call is missing a thought_signature in functionCall
//! parts」）。签名的语义是「模型当初为什么这么调工具」，它由模型在生成
//! `functionCall` 时一并吐出，客户端必须在下一轮回传。
//!
//! 问题在于 OpenAI Chat Completions 格式里**没有放签名的位置**：我们只能把它
//! 塞进 `tool_calls[].extra_content.google.thought_signature`（Google 自家
//! OpenAI 兼容端点用的就是这个位置）。绝大多数客户端下一轮会把这个非标字段
//! 丢掉 —— 于是「模型调工具 → 客户端回传结果」的多轮循环第二轮必 400。
//!
//! 所以插件自己记一份：响应侧把签名按 call id 存下来，请求侧发现客户端没带
//! 就回填。签名只在这一台机器的一次会话里有效，不需要持久化。
//!
//! ── 为什么只按 call id 记，不按「函数名 + 参数」兜底 ─────────
//! 曾经加过一档 `函数名 + 参数摘要 → 签名` 的兜底，用来救「框架重排 call id」
//! 的场景，后来去掉了：Agent 会反复调用同一个函数（反复 `read_file` 同一路径、
//! 反复 `list_dir` 同一目录），形状完全一样而**签名每轮都不同**。按形状取回的
//! 必然是另一轮的签名，上游对错签名报 `Corrupted thought signature` —— 比哨兵
//! 更糟：哨兵是「明确跳过校验」，错签名是「给出错误理由」。
//!
//! 现在只有一条路：call id 精确命中就给真签名，否则给官方哨兵。
//!
//! ── 容量与生命周期：两代有界缓存 ─────────────────────────────
//! 写入只进当代；当代写满（[`CAPACITY`] 条）整体转正为前代、当代清空重来；
//! 读先查当代再查前代，命中前代不搬回当代（搬家要可变借用，读路径就得加写锁）。
//! 最坏常驻 2×CAPACITY 条，一条签名约 1KB，上界约 2MB。全在内存：进程重启即
//! 清空 —— 重启前旧会话的下一轮续接会落到哨兵，仍能继续跑。
//!
//! ── 硬约束 ──────────────────────────────────────────────────
//! release 是 `panic=abort`：零 unwrap/expect/panic；毒锁按「未命中 / 忽略写入」
//! 处理 —— 这份缓存可丢弃，不值得让任何一次请求失败。

use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

use serde_json::{Map, Value};

/// 当代容量（最坏常驻 2×CAPACITY 条，见模块头）。
const CAPACITY: usize = 1024;

/// 官方文档给的「跳过校验」哨兵。
///
/// 缓存未命中时用它顶位：让请求成功，而不是让整条对话卡死。上游对哨兵只跳过
/// 校验、不报错，代价是模型可能少一点上下文（比 400 强）。
pub const SKIP_SIGNATURE_SENTINEL: &str = "skip_thought_signature_validator";

/// 两个「世代」的键值表：写入只进 `current`，写满整体转正为 `previous`。
#[derive(Default)]
struct Generations {
    current: HashMap<String, String>,
    previous: HashMap<String, String>,
}

static CACHE: OnceLock<Mutex<Generations>> = OnceLock::new();

fn cache() -> &'static Mutex<Generations> {
    CACHE.get_or_init(|| Mutex::new(Generations::default()))
}

/// 从 `functionCall` 所在的 part 上取签名。
pub fn signature_of(part: &Value) -> Option<String> {
    part.get("thoughtSignature")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
}

/// 记一个签名（响应侧：拿到带签名的 `functionCall` 时调用）。
pub fn remember(call_id: &str, signature: &str) {
    if call_id.is_empty() || signature.is_empty() {
        return;
    }
    let Ok(mut guard) = cache().lock() else {
        // 锁中毒 → 静默放弃这次写入：缓存可丢弃，不影响主流程。
        return;
    };
    if guard.current.len() >= CAPACITY && !guard.current.contains_key(call_id) {
        guard.previous = std::mem::take(&mut guard.current);
    }
    guard
        .current
        .insert(call_id.to_string(), signature.to_string());
}

/// 按 call id 取回签名。
pub fn lookup(call_id: &str) -> Option<String> {
    if call_id.is_empty() {
        return None;
    }
    let guard = cache().lock().ok()?;
    guard
        .current
        .get(call_id)
        .or_else(|| guard.previous.get(call_id))
        .cloned()
}

/// 从客户端带回的 tool call 上读签名。
///
/// 客户端若是 Google 自家 SDK，会把它放在
/// `extra_content.google.thought_signature`；裸字段名也算（有些框架直接透传）。
pub fn carried_signature(call: &Value) -> Option<String> {
    [
        "/extra_content/google/thought_signature",
        "/extra_content/google/thoughtSignature",
        "/thought_signature",
        "/thoughtSignature",
    ]
    .iter()
    .find_map(|pointer| {
        call.pointer(pointer)
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_string)
    })
}

/// 给一个 `functionCall` part 补上签名。
///
/// 优先级：客户端带回的 > 缓存里按 call id 命中的 > 官方哨兵。哨兵是最后的
/// 兜底 —— 让请求能过，而不是让整条对话在第二轮卡死。
pub fn fill_part(part: &mut Map<String, Value>, carried: Option<&str>, call_id: &str) {
    if part
        .get("thoughtSignature")
        .and_then(Value::as_str)
        .is_some_and(|value| !value.trim().is_empty())
    {
        return;
    }
    let signature = carried
        .map(str::to_string)
        .or_else(|| lookup(call_id))
        .unwrap_or_else(|| String::from(SKIP_SIGNATURE_SENTINEL));
    part.insert(String::from("thoughtSignature"), Value::String(signature));
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn signature_is_read_from_the_part() {
        let part = json!({ "functionCall": { "name": "read" }, "thoughtSignature": "abc" });
        assert_eq!(signature_of(&part).as_deref(), Some("abc"));
    }

    #[test]
    fn blank_signatures_are_not_signatures() {
        let part = json!({ "functionCall": { "name": "read" }, "thoughtSignature": "   " });
        assert!(signature_of(&part).is_none());
    }

    #[test]
    fn a_remembered_signature_comes_back_by_call_id() {
        remember("call_7", "sig-7");
        assert_eq!(lookup("call_7").as_deref(), Some("sig-7"));
    }

    #[test]
    fn repeated_calls_to_the_same_function_keep_their_own_signatures() {
        // 同一函数、同样参数、两轮 —— 签名必须各归各的，不能串。
        remember("call_a_0", "sig-first-round");
        remember("call_b_0", "sig-second-round");
        assert_eq!(lookup("call_a_0").as_deref(), Some("sig-first-round"));
        assert_eq!(lookup("call_b_0").as_deref(), Some("sig-second-round"));
    }

    #[test]
    fn carried_signatures_win_over_the_cache() {
        remember("call_9", "cached");
        let carried = json!({ "extra_content": { "google": { "thought_signature": "from-client" } } });
        assert_eq!(carried_signature(&carried).as_deref(), Some("from-client"));

        let mut part = Map::new();
        part.insert(String::from("functionCall"), json!({ "name": "read" }));
        fill_part(&mut part, Some("from-client"), "call_9");
        assert_eq!(
            part.get("thoughtSignature").and_then(Value::as_str),
            Some("from-client")
        );
    }

    #[test]
    fn the_cache_beats_the_sentinel_when_the_call_id_matches() {
        remember("call_hit", "sig-hit");
        let mut part = Map::new();
        part.insert(String::from("functionCall"), json!({ "name": "read" }));
        fill_part(&mut part, None, "call_hit");
        assert_eq!(
            part.get("thoughtSignature").and_then(Value::as_str),
            Some("sig-hit")
        );
    }

    #[test]
    fn a_cache_miss_falls_back_to_the_sentinel() {
        let mut part = Map::new();
        part.insert(String::from("functionCall"), json!({ "name": "read" }));
        fill_part(&mut part, None, "call_never_seen");
        assert_eq!(
            part.get("thoughtSignature").and_then(Value::as_str),
            Some(SKIP_SIGNATURE_SENTINEL)
        );
    }

    #[test]
    fn an_empty_call_id_never_hits_the_cache() {
        // 没有 id 就没法精确匹配 —— 宁可给哨兵，也不要瞎猜一个签名。
        remember("", "ignored");
        assert!(lookup("").is_none());
        let mut part = Map::new();
        part.insert(String::from("functionCall"), json!({ "name": "read" }));
        fill_part(&mut part, None, "");
        assert_eq!(
            part.get("thoughtSignature").and_then(Value::as_str),
            Some(SKIP_SIGNATURE_SENTINEL)
        );
    }

    #[test]
    fn an_existing_signature_is_left_alone() {
        let mut part = Map::new();
        part.insert(String::from("functionCall"), json!({ "name": "read" }));
        part.insert(String::from("thoughtSignature"), json!("already-here"));
        fill_part(&mut part, Some("ignored"), "call_1");
        assert_eq!(
            part.get("thoughtSignature").and_then(Value::as_str),
            Some("already-here")
        );
    }
}
