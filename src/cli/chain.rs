use clap::Subcommand;

use crate::cli::server::recover_pending_identity_transactions;
use crate::config::AppConfig;
use crate::core::create_chain;
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

/// 运行链命令
pub async fn run_chain(config: &AppConfig, action: ChainAction) -> anyhow::Result<()> {
    let storage = create_storage(&config.database.dsn).await?;
    let chain = create_chain(config.blockchain.difficulty, config.blockchain.block_size);

    // 加载区块
    let blocks = storage.get_all_blocks().await?;
    if !blocks.is_empty() {
        if matches!(&action, ChainAction::Mine) {
            chain.validate_loaded_blocks(&blocks)?;
        }
        chain.load_blocks(blocks);
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
        ChainAction::Validate => {
            let valid = chain.validate_chain();
            if valid {
                println!("✓ 链验证通过");
            } else {
                println!("✗ 链验证失败");
            }
        }
        ChainAction::Mine => match chain.mine_block_with_identity_transaction_ids() {
            Ok(mined) => {
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
