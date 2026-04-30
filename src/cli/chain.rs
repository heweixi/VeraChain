use clap::Subcommand;

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
        chain.load_blocks(blocks);
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
        ChainAction::Mine => {
            match chain.mine_block() {
                Ok(block) => {
                    storage.save_block(&block).await?;
                    println!("✓ 新区块已挖掘");
                    println!("  索引: {}", block.index);
                    println!("  哈希: {}", block.hash);
                    println!("  元数据数量: {}", block.metadata_list.len());
                }
                Err(e) => {
                    println!("✗ 挖矿失败: {}", e);
                }
            }
        }
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
        ChainAction::Block { index } => {
            match chain.get_block(index) {
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
                            println!("  [{}] {} | {} bytes | {}", i, entry.data_id, entry.data_size, entry.owner);
                        }
                    }
                }
                Err(e) => {
                    println!("✗ 获取区块失败: {}", e);
                }
            }
        }
    }

    Ok(())
}
