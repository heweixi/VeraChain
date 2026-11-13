//! CLI 命令共用的严格链加载 + 退出码映射。
//!
//! `load_verified_chain` 统一"读区块→校验→加载进内存链"三步,任何命令只要经过
//! 这里就不会在无效/损坏数据上继续往下跑(此前 metadata/aggregate/status 等命令
//! 直接 `storage.get_all_blocks().await?` 后 `chain.load_blocks(blocks)`,从不调用
//! `validate_loaded_blocks`)。
//!
//! `exit_code_for` 把错误映射到约定退出码:0 由 main 在无错误时直接返回,
//! 1 其他错误,2 链无效(InvalidChain/InvalidBlock),3 数据损坏(DataCorruption)。

use std::sync::Arc;

use crate::core::{Block, Chain};
use crate::error::{DataChainError, Result};
use crate::storage::Storage;

/// 读取全部区块、校验、加载进内存链,返回已加载的区块列表供调用方复用
/// (如 ensure_projections、CLI 输出)。校验失败或读取损坏时返回 Err,
/// 不会把未经验证的区块加载进 chain。
pub async fn load_verified_chain(storage: &Arc<Storage>, chain: &Arc<Chain>) -> Result<Vec<Block>> {
    let blocks = storage.get_all_blocks().await?;
    if !blocks.is_empty() {
        chain.validate_loaded_blocks(&blocks)?;
        chain.load_blocks(blocks.clone());
    }
    Ok(blocks)
}

/// 把 `anyhow::Error` 尝试下转型为 `DataChainError` 并映射到约定退出码(u8):
/// 1 其他错误,2 链无效(InvalidChain/InvalidBlock),3 数据损坏(DataCorruption)。
/// 返回 u8 而非 `std::process::ExitCode`,便于单测直接比较
/// (`ExitCode` 未实现 `PartialEq`);main 里再转换为 `ExitCode::from(code)`。
pub fn exit_code_for(err: &anyhow::Error) -> u8 {
    match err.downcast_ref::<DataChainError>() {
        Some(DataChainError::DataCorruption { .. }) => 3,
        Some(DataChainError::InvalidChain) | Some(DataChainError::InvalidBlock(_)) => 2,
        _ => 1,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::create_chain;
    use crate::storage::create_storage;

    #[tokio::test]
    async fn load_verified_chain_loads_valid_blocks() {
        let dir = tempfile::tempdir().unwrap();
        let dsn = dir.path().join("data.sqlite");
        let storage = create_storage(dsn.to_str().unwrap()).await.unwrap();
        let chain = create_chain(1, 100);
        let genesis = chain.init();
        storage.save_block(&genesis).await.unwrap();
        // 用新的空 chain 实例模拟 CLI 命令每次新建 chain 的场景。
        let fresh_chain = create_chain(1, 100);

        let blocks = load_verified_chain(&storage, &fresh_chain).await.unwrap();
        assert_eq!(blocks.len(), 1);
        assert_eq!(fresh_chain.get_block_count(), 1);
    }

    #[tokio::test]
    async fn load_verified_chain_rejects_invalid_chain_without_loading() {
        let dir = tempfile::tempdir().unwrap();
        let dsn = dir.path().join("data.sqlite");
        let storage = create_storage(dsn.to_str().unwrap()).await.unwrap();
        let mut corrupt = Block::new(0, "tampered".to_string(), 1);
        corrupt.mine();
        storage.save_block(&corrupt).await.unwrap();
        let chain = create_chain(1, 100);

        assert!(load_verified_chain(&storage, &chain).await.is_err());
        assert_eq!(chain.get_block_count(), 0);
    }

    #[test]
    fn exit_code_for_maps_data_corruption_to_3() {
        let err: anyhow::Error = DataChainError::DataCorruption {
            category: crate::error::CorruptionCategory::Authoritative,
            table: "users",
            key: "u1".to_string(),
            reason: "json_data".to_string(),
        }
        .into();
        assert_eq!(exit_code_for(&err), 3);
    }

    #[test]
    fn exit_code_for_maps_invalid_chain_to_2() {
        let err: anyhow::Error = DataChainError::InvalidChain.into();
        assert_eq!(exit_code_for(&err), 2);
    }

    #[test]
    fn exit_code_for_maps_other_errors_to_1() {
        let err: anyhow::Error = DataChainError::ConfigError("bad".to_string()).into();
        assert_eq!(exit_code_for(&err), 1);
    }
}
