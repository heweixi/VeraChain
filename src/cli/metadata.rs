use clap::Subcommand;

use crate::cli::common::load_verified_chain;
use crate::config::AppConfig;
use crate::core::create_chain;
use crate::crypto::HashEngine;
use crate::metadata::{create_metadata_manager, CreateMetadataRequest, QueryMetadataRequest};
use crate::storage::create_storage;

#[derive(Subcommand)]
pub enum MetadataAction {
    /// 添加元数据
    Add {
        /// 文件路径
        #[arg(short, long)]
        file: Option<String>,
        /// 数据大小
        #[arg(short, long, default_value = "0")]
        size: i64,
        /// 所有者
        #[arg(short, long)]
        owner: String,
        /// 标签
        #[arg(short, long)]
        tags: Option<String>,
    },
    /// 列出元数据
    List {
        /// 所有者过滤
        #[arg(short, long)]
        owner: Option<String>,
        /// 页码
        #[arg(short, long, default_value = "1")]
        page: usize,
        /// 每页数量
        #[arg(long, default_value = "20")]
        page_size: usize,
    },
    /// 获取元数据
    Get {
        /// 数据 ID
        data_id: String,
    },
    /// 查询元数据
    Query {
        /// 所有者
        #[arg(short, long)]
        owner: Option<String>,
        /// 标签
        #[arg(short, long)]
        tags: Option<String>,
    },
    /// 统计信息
    Stats,
    /// 计算文件哈希
    Hash {
        /// 文件路径
        file: String,
        /// 计算所有哈希
        #[arg(short, long)]
        all: bool,
    },
}

/// 运行元数据命令
pub async fn run_metadata(config: &AppConfig, action: MetadataAction) -> anyhow::Result<()> {
    let storage = create_storage(&config.database.dsn).await?;
    let chain = create_chain(config.blockchain.difficulty, config.blockchain.block_size);

    // 严格加载:区块损坏或链无效时 fail-closed,不会继续执行回填/查询。
    load_verified_chain(&storage, &chain).await?;

    // 回填 metadata 投影,确保读命令(list/get/query/stats)能命中历史上链元数据。
    storage
        .backfill_metadata_from_blocks(&chain.get_all_blocks())
        .await?;

    let manager = create_metadata_manager(chain, storage.clone());

    match action {
        MetadataAction::Add {
            file,
            size,
            owner,
            tags,
        } => {
            let mut req = CreateMetadataRequest {
                data_size: size,
                owner: Some(owner.clone()),
                hashes: std::collections::HashMap::new(),
                metadata: std::collections::HashMap::new(),
                parent_id: None,
                tags: tags
                    .map(|t| t.split(',').map(|s| s.trim().to_string()).collect())
                    .unwrap_or_default(),
                content: None,
            };

            // 如果提供了文件，读取并计算哈希
            if let Some(file_path) = file {
                let content = std::fs::read(&file_path)?;
                req.data_size = content.len() as i64;
                req.content = Some(content);
            }

            let entry = manager.create(&req, &owner)?;
            storage.save_pending_metadata(&entry).await?;
            println!("✓ 元数据已添加");
            println!("  数据 ID: {}", entry.data_id);
            println!("  大小: {} bytes", entry.data_size);
            println!("  所有者: {}", entry.owner);
        }
        MetadataAction::List {
            owner,
            page,
            page_size,
        } => {
            let req = QueryMetadataRequest {
                data_id: None,
                owner,
                start_time: None,
                end_time: None,
                tags: Vec::new(),
                page,
                page_size,
            };

            let results = manager.query(&req).await?;
            println!("元数据列表 (第 {} 页)", page);
            println!("==========");

            for entry in results {
                println!(
                    "{} | {} bytes | {} | {}",
                    entry.data_id,
                    entry.data_size,
                    entry.owner,
                    entry.created_at.format("%Y-%m-%d %H:%M:%S")
                );
            }
        }
        MetadataAction::Get { data_id } => match manager.get_by_data_id(&data_id).await? {
            Some(entry) => {
                println!("元数据详情");
                println!("==========");
                println!("数据 ID: {}", entry.data_id);
                println!("大小: {} bytes", entry.data_size);
                println!("所有者: {}", entry.owner);
                println!("创建时间: {}", entry.created_at);
                println!("修改时间: {}", entry.modified_at);

                if !entry.tags.is_empty() {
                    println!("标签: {}", entry.tags.join(", "));
                }

                if !entry.hashes.is_empty() {
                    println!();
                    println!("哈希值:");
                    for (algo, hash) in &entry.hashes {
                        println!("  {}: {}", algo, hash);
                    }
                }
            }
            None => {
                println!("✗ 元数据未找到: {}", data_id);
            }
        },
        MetadataAction::Query { owner, tags } => {
            let req = QueryMetadataRequest {
                data_id: None,
                owner,
                start_time: None,
                end_time: None,
                tags: tags
                    .map(|t| t.split(',').map(|s| s.trim().to_string()).collect())
                    .unwrap_or_default(),
                page: 1,
                page_size: 50,
            };

            let results = manager.query(&req).await?;
            println!("查询结果: {} 条", results.len());

            for entry in results {
                println!(
                    "{} | {} bytes | {}",
                    entry.data_id, entry.data_size, entry.owner
                );
            }
        }
        MetadataAction::Stats => {
            let stats = manager.get_statistics().await?;
            println!("元数据统计");
            println!("==========");
            println!("总数量: {}", stats.total_metadata);
            println!("总大小: {} bytes", stats.total_size);
            println!("唯一所有者: {}", stats.unique_owners);
            println!("待打包: {}", stats.pending_count);

            if !stats.top_owners.is_empty() {
                println!();
                println!("Top 所有者:");
                for (owner, count) in &stats.top_owners {
                    println!("  {}: {}", owner, count);
                }
            }
        }
        MetadataAction::Hash { file, all } => {
            let content = std::fs::read(&file)?;
            let engine = HashEngine::new(None);

            println!("文件: {}", file);
            println!("大小: {} bytes", content.len());
            println!();

            if all {
                let hashes = engine.compute_all_hashes(&content);
                for (algo, hash) in &hashes {
                    println!("{}: {}", algo, hash);
                }
            } else {
                let hashes = engine.compute_fast_hashes(&content);
                for (algo, hash) in &hashes {
                    println!("{}: {}", algo, hash);
                }
            }
        }
    }

    Ok(())
}
