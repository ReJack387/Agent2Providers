//! 通用的 OpenAI Chat → Responses 出站转换与 Responses 流事件读取。
//!
//! ── 为什么提到 crate 根 ────────────────────────────────────
//! 这份实现原本只在 AStudio 家里（上游 `wire_api = responses`）。Codex 的
//! `backend-api/codex/responses` 用的是同一套 wire 形态，于是把它提升成共享
//! 模块（与 `crate::anthropic` 的做法一致：物理文件仍留在某个 provider 目录
//! 下，经 `#[path]` 暴露），避免第二份转换各自漂移。
//!
//! 模块内不含任何提供商的端点、鉴权或套餐信息 —— 那些留在各自的 `endpoints`
//! 与 `chat` 里。

#[path = "providers/astudio/responses.rs"]
pub mod responses;
