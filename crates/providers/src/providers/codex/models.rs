//! Codex 的模型清单（按套餐档位分档）。
//!
//! ── 为什么按档位分而不是一份清单 ────────────────────────────
//! 参考实现 `cliproxy/service_models.go` 的 codex 分支按
//! `a.Attributes["plan_type"]` 选清单：`pro` / `plus` / `team|business|go` /
//! `free`，**未知档位回落 pro**。ChatGPT 订阅的可用模型确实是随套餐变的
//! （Free 拿不到 `-codex` 系列），用一份清单会让免费账号在界面上看到一堆
//! 选了就 403 的模型。
//!
//! ── 为什么没有远程刷新 ──────────────────────────────────────
//! 上游没有公开的「列出我的可用模型」端点（参考实现也是静态注册表）。所以
//! 本家 `model_refresh` 能力位为 false，清单只来自这里。

use serde_json::{json, Value};

/// 一个模型条目的静态描述。
struct Entry {
    id: &'static str,
    name: &'static str,
    max_input: i64,
    max_output: i64,
    reasoning: bool,
}

/// 所有档位共享的条目池（按 id 去重，档位表只引用 id）。
const POOL: &[Entry] = &[
    Entry {
        id: "gpt-5.2",
        name: "GPT-5.2",
        max_input: 272_000,
        max_output: 128_000,
        reasoning: true,
    },
    Entry {
        id: "gpt-5.3-codex",
        name: "GPT-5.3 Codex",
        max_input: 272_000,
        max_output: 128_000,
        reasoning: true,
    },
    Entry {
        id: "gpt-5.3-codex-spark",
        name: "GPT-5.3 Codex Spark",
        max_input: 272_000,
        max_output: 128_000,
        reasoning: true,
    },
    Entry {
        id: "gpt-5.4",
        name: "GPT-5.4",
        max_input: 272_000,
        max_output: 128_000,
        reasoning: true,
    },
    Entry {
        id: "gpt-5.4-fast",
        name: "GPT-5.4 Fast",
        max_input: 272_000,
        max_output: 128_000,
        reasoning: true,
    },
    Entry {
        id: "gpt-5.4-mini",
        name: "GPT-5.4 Mini",
        max_input: 272_000,
        max_output: 64_000,
        reasoning: true,
    },
    Entry {
        id: "gpt-5.5",
        name: "GPT-5.5",
        max_input: 400_000,
        max_output: 128_000,
        reasoning: true,
    },
    Entry {
        id: "gpt-5.6-luna",
        name: "GPT-5.6 Luna",
        max_input: 400_000,
        max_output: 128_000,
        reasoning: true,
    },
    Entry {
        id: "gpt-5.6-luna-2026-05-13",
        name: "GPT-5.6 Luna (2026-05-13)",
        max_input: 400_000,
        max_output: 128_000,
        reasoning: true,
    },
    Entry {
        id: "gpt-5.6-sol",
        name: "GPT-5.6 Sol",
        max_input: 400_000,
        max_output: 128_000,
        reasoning: true,
    },
    Entry {
        id: "gpt-5.6-terra",
        name: "GPT-5.6 Terra",
        max_input: 400_000,
        max_output: 128_000,
        reasoning: true,
    },
];

/// 默认模型（Free 档也能用的那个）。
pub const DEFAULT_MODEL: &str = "gpt-5.4-mini";

/// Free 档能用的 id。
const FREE_IDS: &[&str] = &["gpt-5.4-mini"];

/// Plus 档能用的 id。
const PLUS_IDS: &[&str] = &[
    "gpt-5.2",
    "gpt-5.4",
    "gpt-5.4-fast",
    "gpt-5.4-mini",
    "gpt-5.5",
];

/// Team / Business / Go 档能用的 id。
const TEAM_IDS: &[&str] = &[
    "gpt-5.2",
    "gpt-5.3-codex",
    "gpt-5.4",
    "gpt-5.4-fast",
    "gpt-5.4-mini",
    "gpt-5.5",
    "gpt-5.6-sol",
];

/// Pro 档能用的 id（全量）。
const PRO_IDS: &[&str] = &[
    "gpt-5.2",
    "gpt-5.3-codex",
    "gpt-5.3-codex-spark",
    "gpt-5.4",
    "gpt-5.4-fast",
    "gpt-5.4-mini",
    "gpt-5.5",
    "gpt-5.6-luna",
    "gpt-5.6-luna-2026-05-13",
    "gpt-5.6-sol",
    "gpt-5.6-terra",
];

/// 按套餐档位挑 id 列表。
///
/// 未知档位回落 pro —— 与参考实现 `default: GetCodexProModels()` 一致：
/// 宁可多给几个（选错了上游会明确报错），也别让新套餐的账号看到空清单。
fn ids_for(plan: &str) -> &'static [&'static str] {
    match plan.trim().to_ascii_lowercase().as_str() {
        "free" => FREE_IDS,
        "plus" => PLUS_IDS,
        "team" | "business" | "go" => TEAM_IDS,
        _ => PRO_IDS,
    }
}

fn find(id: &str) -> Option<&'static Entry> {
    POOL.iter().find(|entry| entry.id == id)
}

fn record(entry: &Entry, is_default: bool) -> Value {
    json!({
        "id": entry.id,
        "name": entry.name,
        "maxInputTokens": entry.max_input,
        "maxOutputTokens": entry.max_output,
        "supportsToolCall": true,
        "supportsImages": true,
        "supportsReasoning": entry.reasoning,
        "supportsThinking": entry.reasoning,
        "isDefault": is_default,
    })
}

/// 某档位的模型清单。
pub fn catalog(plan: &str) -> Vec<Value> {
    let ids = ids_for(plan);
    ids.iter()
        .filter_map(|id| find(id))
        .map(|entry| record(entry, entry.id == DEFAULT_MODEL))
        .collect()
}

/// 不区分档位的并集清单（用于 `meta().default_models`：账号还没加进来时，
/// 面板也要能显示这一家「大概有哪些模型」）。
pub fn union_catalog() -> Vec<Value> {
    let mut seen: Vec<&str> = Vec::new();
    let mut models = Vec::new();
    for entry in POOL {
        if seen.contains(&entry.id) {
            continue;
        }
        seen.push(entry.id);
        models.push(record(entry, entry.id == DEFAULT_MODEL));
    }
    models
}

/// 这个 id 是不是本家认的模型。
///
/// 用 `gpt-` 前缀放行：上游上新模型时不必等插件跟着发版。
pub fn is_known_model(id: &str) -> bool {
    let lowered = id.trim().to_ascii_lowercase();
    lowered.starts_with("gpt-") || lowered.starts_with("o1") || lowered.starts_with("o3")
}

/// 该模型是否支持思考档。
pub fn supports_reasoning(id: &str) -> bool {
    let lowered = id.trim().to_ascii_lowercase();
    if lowered.is_empty() {
        return false;
    }
    // 本家清单里除了 mini 系列都支持；`-mini` / `-spark` 也支持，但不给小模型的
    // 思考开关是更稳的默认（选了高档上游会直接拒）。
    !lowered.contains("-nano")
}

#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pro_gets_the_whole_pool() {
        let models = catalog("pro");
        assert_eq!(models.len(), POOL.len());
    }

    #[test]
    fn free_is_a_strict_subset() {
        let free = catalog("free");
        assert!(!free.is_empty(), "免费档不能是空清单");
        assert!(free.len() < catalog("pro").len());
    }

    #[test]
    fn unknown_plans_fall_back_to_pro() {
        assert_eq!(catalog("weird-plan").len(), catalog("pro").len());
        assert_eq!(catalog("").len(), catalog("pro").len());
    }

    #[test]
    fn team_aliases_share_one_list() {
        assert_eq!(catalog("team").len(), catalog("business").len());
        assert_eq!(catalog("team").len(), catalog("go").len());
    }

    #[test]
    fn every_tier_marks_exactly_one_default() {
        for plan in ["free", "plus", "team", "pro"] {
            let defaults = catalog(plan)
                .iter()
                .filter(|model| model["isDefault"] == json!(true))
                .count();
            assert_eq!(defaults, 1, "{plan} 档必须有且只有一个默认模型");
        }
    }

    #[test]
    fn union_catalog_is_deduplicated() {
        let union = union_catalog();
        assert_eq!(union.len(), POOL.len());
        let mut ids: Vec<&str> = union
            .iter()
            .filter_map(|model| model["id"].as_str())
            .collect();
        let before = ids.len();
        ids.sort_unstable();
        ids.dedup();
        assert_eq!(ids.len(), before);
    }

    #[test]
    fn the_prefix_gate_lets_new_models_through() {
        assert!(is_known_model("gpt-5.4"));
        assert!(is_known_model("gpt-7-future"));
        assert!(!is_known_model("claude-sonnet-4-6"));
        assert!(!is_known_model(""));
    }
}
