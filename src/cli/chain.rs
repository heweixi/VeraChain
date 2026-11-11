use clap::Subcommand;

use crate::cli::common::load_verified_chain;
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

    let blocks = load_verified_chain(&storage, &chain).await?;
    let _ = blocks;

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
        ChainAction::Mine => match chain.mine_block() {
            Ok(block) => {
                // Mine 与挖矿后的 CLI 导入统一走 commit_block,同事务补投影
                // (metadata/catalog_*),不再用低层 save_block(无投影写入)。
                storage.commit_block(&block).await?;
                println!("✓ 新区块已挖掘");
                println!("  索引: {}", block.index);
                println!("  哈希: {}", block.hash);
                println!("  元数据数量: {}", block.metadata_list.len());
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
