use clap::Subcommand;

use crate::config::AppConfig;
use crate::storage::create_storage;
use crate::versioning::create_version_tracker;

#[derive(Subcommand)]
pub enum VersionAction {
    /// 追踪文件
    Track {
        /// 文件路径
        file: String,
        /// 作者
        #[arg(short, long, default_value = "system")]
        author: String,
        /// 提交信息
        #[arg(short, long, default_value = "")]
        message: String,
    },
    /// 追踪目录
    TrackDir {
        /// 目录路径
        #[arg(short, long)]
        dir: String,
        /// 文件模式
        #[arg(short, long)]
        pattern: Option<String>,
        /// 作者
        #[arg(short, long, default_value = "system")]
        author: String,
    },
    /// 列出版本
    List,
    /// 版本历史
    History {
        /// 文件路径
        file: String,
    },
    /// 版本差异
    Diff {
        /// 旧版本 ID
        old: String,
        /// 新版本 ID
        new: String,
    },
    /// 版本统计
    Stats,
}

/// 运行版本命令
pub async fn run_version(config: &AppConfig, action: VersionAction) -> anyhow::Result<()> {
    let storage = create_storage(&config.database.dsn).await?;
    let tracker = create_version_tracker();

    // 加载版本
    let versions = storage.get_all_versions().await?;
    for version in versions {
        tracker.load_version(version);
    }

    match action {
        VersionAction::Track { file, author, message } => {
            match tracker.track_file(&file, &author, &message) {
                Ok(version) => {
                    storage.save_version(&version).await?;
                    println!("✓ 文件已追踪");
                    println!("  版本 ID: {}", version.version_id);
                    println!("  文件: {}", version.file_path);
                    println!("  哈希: {}", version.content_hash);
                    println!("  大小: {} bytes", version.size);
                }
                Err(e) => {
                    println!("✗ 追踪失败: {}", e);
                }
            }
        }
        VersionAction::TrackDir { dir, pattern, author } => {
            let patterns: Vec<String> = pattern
                .map(|p| p.split(',').map(|s| s.trim().to_string()).collect())
                .unwrap_or_default();

            match tracker.track_directory(&dir, &patterns, &author) {
                Ok(versions) => {
                    for version in &versions {
                        storage.save_version(version).await?;
                    }
                    println!("✓ 已追踪 {} 个文件", versions.len());
                }
                Err(e) => {
                    println!("✗ 追踪失败: {}", e);
                }
            }
        }
        VersionAction::List => {
            let versions = tracker.get_all_versions();
            println!("版本列表 (共 {} 个)", versions.len());
            println!("=========");

            for version in versions {
                println!(
                    "{} | {} | {} bytes | {}",
                    &version.version_id[..8],
                    version.file_path,
                    version.size,
                    version.timestamp.format("%Y-%m-%d %H:%M:%S")
                );
            }
        }
        VersionAction::History { file } => {
            let history = tracker.get_version_history(&file);
            println!("版本历史: {}", file);
            println!("=========");

            for version in history {
                println!(
                    "{} | {} | {} bytes | {}",
                    &version.version_id[..8],
                    &version.content_hash[..16],
                    version.size,
                    version.timestamp.format("%Y-%m-%d %H:%M:%S")
                );
            }
        }
        VersionAction::Diff { old, new } => {
            match tracker.get_version_diff(&old, &new) {
                Ok(diff) => {
                    println!("版本差异");
                    println!("========");
                    println!("旧版本: {}", diff.old_version);
                    println!("新版本: {}", diff.new_version);
                    println!("添加: {} 行", diff.additions);
                    println!("删除: {} 行", diff.deletions);
                    println!("修改: {} 行", diff.modifications);
                }
                Err(e) => {
                    println!("✗ 无法读取版本快照: {}", e);
                }
            }
        }
        VersionAction::Stats => {
            let stats = tracker.get_statistics();
            println!("版本统计");
            println!("========");
            println!("追踪文件数: {}", stats.tracked_files);
            println!("总版本数: {}", stats.total_versions);
            println!("总大小: {} bytes", stats.total_size);

            if !stats.authors.is_empty() {
                println!();
                println!("作者:");
                for (author, count) in &stats.authors {
                    println!("  {}: {}", author, count);
                }
            }
        }
    }

    Ok(())
}
