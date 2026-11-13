use clap::Subcommand;

use crate::cli::common::load_verified_chain;
use crate::cli::server::recover_pending_identity_transactions;
use crate::config::AppConfig;
use crate::core::create_chain;
use crate::error::DataChainError;
use crate::storage::create_storage;

#[derive(Subcommand)]
pub enum ChainAction {
    /// 查看链信息
    Info,
    /// 验证链完整性
    Validate,
    /// 挖掘新区块
    Mine,
    /// 列出区块
    Blocks {
        /// 起始索引
        #[arg(short, long, default_value = "0")]
        start: usize,
        /// 数量限制
        #[arg(short, long, default_value = "10")]
        limit: usize,
    },
    /// 查看区块详情
    Block {
        /// 区块索引
        index: i64,
    },
}

/// 运行链命令。`chain validate` 之外的命令若遇数据损坏,`load_verified_chain`
/// 直接返回 Err(DataCorruption),经 main.rs 的 exit_code_for 映射为退出码 3。
pub async fn run_chain(config: &AppConfig, action: ChainAction) -> anyhow::Result<()> {
    let storage = create_storage(&config.database.dsn).await?;
    let chain = create_chain(config.blockchain.difficulty, config.blockchain.block_size);

    // ChainAction::Validate 是本命令唯一允许在"链本身无效"时仍打印结果并以退出码 2
    // 结束的分支(用户可见、非数据损坏);其余分支复用严格的 load_verified_chain,
    // 链无效或数据损坏都直接 fail-closed。
    if let ChainAction::Validate = action {
        let blocks = storage.get_all_blocks().await?;
        let valid = chain.validate_loaded_blocks(&blocks).is_ok() && !blocks.is_empty();
        if valid {
            println!("✓ 链验证通过");
            return Ok(());
        } else {
            println!("✗ 链验证失败");
            // 退出码 2:链无效,不是数据损坏(get_all_blocks 已成功读取,只是规则不通过)。
            return Err(DataChainError::InvalidChain.into());
        }
    }

    load_verified_chain(&storage, &chain).await?;

    // Mine 需要内存链里有待打包元数据才能出块;CLI 各命令各自独立进程/连接,
    // 这里按与 server 启动一致的"去重"语义加载一次(已打包的不会重复加入)。
    if let ChainAction::Mine = action {
        let committed_data_ids: std::collections::HashSet<String> = chain
            .get_all_blocks()
            .iter()
            .flat_map(|b| b.metadata_list.iter().map(|e| e.data_id.clone()))
            .collect();
        let pending = storage.get_pending_metadata().await?;
        let pending_to_load: Vec<_> = pending
            .into_iter()
            .filter(|e| !committed_data_ids.contains(&e.data_id))
            .collect();
        chain.load_pending(pending_to_load);
    }
    if matches!(&action, ChainAction::Mine) {
        recover_pending_identity_transactions(&chain, &storage).await?;
    }

    match action {
        ChainAction::Info => {
            let info = chain.get_chain_info();
            println!("区块链信息");
            println!("==========");
            println!("区块数量: {}", info.block_count);
            println!("难度: {}", info.difficulty);
            println!("区块大小: {}", info.block_size);
            println!("待打包: {}", info.pending_count);

            if let Some(latest) = info.latest_block {
                println!();
                println!("最新区块:");
                println!("  索引: {}", latest.index);
                println!("  哈希: {}", latest.hash);
                println!("  时间: {}", latest.timestamp);
            }
        }
        ChainAction::Validate => unreachable!("handled above"),
        ChainAction::Mine => match chain.mine_block_with_identity_transaction_ids() {
            Ok(mined) => {
                // Mine 与挖矿后的 CLI 导入统一走 commit_block,同事务补投影
                // (metadata/catalog_*)并把身份交易账本行转为 committed;
                // 提交失败时把区块与 sidecar 一并回滚回待打包队列。
                if let Err(error) = storage
                    .commit_block(&mined.block, &mined.identity_transaction_ids)
                    .await
                {
                    chain.rollback_mined_block_with_identity_transaction_ids(&mined);
                    return Err(error.into());
                }
                println!("✓ 新区块已挖掘");
                println!("  索引: {}", mined.block.index);
                println!("  哈希: {}", mined.block.hash);
                println!("  元数据数量: {}", mined.block.metadata_list.len());
            }
            Err(e) => {
                println!("✗ 挖矿失败: {}", e);
            }
        },
        ChainAction::Blocks { start, limit } => {
            let blocks = chain.get_blocks(start, limit);
            println!("区块列表 (共 {} 个)", chain.get_block_count());
            println!("=========");

            for block in blocks {
                println!(
                    "[{}] {} | {} 条元数据 | {}",
                    block.index,
                    &block.hash[..16],
                    block.metadata_list.len(),
                    block.timestamp.format("%Y-%m-%d %H:%M:%S")
                );
            }
        }
        ChainAction::Block { index } => match chain.get_block(index) {
            Ok(block) => {
                println!("区块 #{}", block.index);
                println!("========");
                println!("哈希: {}", block.hash);
                println!("前一哈希: {}", block.previous_hash);
                println!("Merkle 根: {}", block.merkle_root);
                println!("时间戳: {}", block.timestamp);
                println!("难度: {}", block.difficulty);
                println!("Nonce: {}", block.nonce);
                println!("元数据数量: {}", block.metadata_list.len());

                if !block.metadata_list.is_empty() {
                    println!();
                    println!("元数据:");
                    for (i, entry) in block.metadata_list.iter().enumerate() {
                        println!(
                            "  [{}] {} | {} bytes | {}",
                            i, entry.data_id, entry.data_size, entry.owner
                        );
                    }
                }
            }
            Err(e) => {
                println!("✗ 获取区块失败: {}", e);
            }
        },
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::KeyTransactionEntry;

    fn pending_identity_entry() -> KeyTransactionEntry {
        KeyTransactionEntry {
            tx_type: "register".to_string(),
            target_key: "key-a".to_string(),
            role: "node".to_string(),
            label: "pending".to_string(),
            signed_by: "key-a".to_string(),
            signature: "signature".to_string(),
            timestamp: 10,
            reason: String::new(),
        }
    }

    #[tokio::test]
    async fn mine_recovers_persisted_pending_identity_transactions_before_mining() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("data.sqlite");
        let storage = create_storage(path.to_str().unwrap()).await.unwrap();
        let chain = create_chain(1, 100);
        let genesis = chain.init();
        storage.save_block(&genesis).await.unwrap();

        let entry = pending_identity_entry();
        let transaction = storage
            .create_or_get_identity_transaction("user-a", None, "fingerprint-a", &entry, 10)
            .await
            .unwrap()
            .transaction;
        let mut config = AppConfig::default();
        config.database.dsn = path.to_string_lossy().into_owned();
        config.blockchain.difficulty = 1;
        config.blockchain.block_size = 100;

        run_chain(&config, ChainAction::Mine).await.unwrap();

        let blocks = storage.get_all_blocks().await.unwrap();
        assert_eq!(blocks.len(), 2);
        assert_eq!(blocks[1].key_transactions.len(), 1);
        assert_eq!(blocks[1].key_transactions[0].target_key, "key-a");
        assert_eq!(
            storage
                .get_identity_transaction(&transaction.transaction_id)
                .await
                .unwrap()
                .unwrap()
                .status,
            "committed"
        );
    }
}
