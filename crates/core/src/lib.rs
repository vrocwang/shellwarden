//! ShellWarden 本地安全核心：审计哈希链、摘要、错误与 ID。
//!
//! 工具/策略/审批/计划/Grant 路径已删除；通用命令模式只保留审计与风险拦截。

pub mod audit;
pub mod digest;
pub mod error;
pub mod ids;

pub use error::{AppError, Result};

/// 人类可读的产品版本。
pub const APP_VERSION: &str = env!("CARGO_PKG_VERSION");
