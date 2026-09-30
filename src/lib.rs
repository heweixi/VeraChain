//! DataChain Rust 库入口。
//!
//! 背景:src/main.rs 是一个"简化版"独立入口(自带精简 Block 实现),从未通过
//! `mod` 声明接入 src/ 下的真实模块(core/auth/storage/...),导致这些模块长期
//! 游离于编译单元之外——既未编译也无法测试。
//!
//! 本 lib.rs 逐步把真实模块接入编译单元,使其可编译、可测试(如 core 的区块哈希
//! 黄金向量、auth 的权限模型)。模块按依赖关系分批接入。

pub mod error;
pub mod config;
pub mod core;
pub mod crypto;
pub mod auth;
pub mod utils;
pub mod metadata;
pub mod storage;
pub mod versioning;
pub mod aggregation;
pub mod p2p;
pub mod api;
pub mod cli;
