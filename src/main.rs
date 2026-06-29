mod aggregation;
mod api;
mod auth;
mod cli;
// Note: "core" shadows std core crate, but Rust 2021 resolves std types via prelude.
// All internal references use `crate::core::*` which resolves to our module.
pub mod core;
mod crypto;
pub mod error;
mod metadata;
mod storage;
mod utils;
mod versioning;

pub mod config;

use std::sync::Arc;

use clap::Parser;
use tracing_subscriber::EnvFilter;

use crate::api::{run_server, AppState};
use crate::auth::AuthService;
use crate::core::create_chain;
use crate::config::AppConfig;
use crate::metadata::MetadataManager;
use crate::storage::Storage;
use crate::versioning::VersionTracker;
use crate::aggregation::AggregationEngine;

/// DataChain - 数据追溯区块链系统 (Rust)
#[derive(Parser, Debug)]
#[command(name = "datachain", version = "1.0.0", about = "数据追溯区块链系统")]
struct Cli {
    /// 配置文件路径
    #[arg(short, long, default_value = "config/config.toml")]
    config: String,

    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(clap::Subcommand, Debug)]
enum Commands {
    /// 启动 HTTP 服务器
    Serve {
        /// 监听端口
        #[arg(short, long, default_value = "8080")]
        port: u16,
    },
    /// 显示链信息
    Info,
    /// 显示版本
    Version,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // 初始化日志
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env().add_directive("datachain=info".parse()?))
        .init();

    let cli = Cli::parse();

    // 加载配置
    let cfg = AppConfig::load(&cli.config).unwrap_or_default();

    match cli.command {
        Some(Commands::Version) => {
            println!("DataChain Rust v1.0.0");
        }
        Some(Commands::Info) => {
            println!("DataChain Rust v1.0.0");
            println!("Config: {}", cli.config);
            println!("Difficulty: {}", cfg.blockchain.difficulty);
            println!("Block size: {}", cfg.blockchain.block_size);
        }
        Some(Commands::Serve { port }) | None => {
            let port = if cli.command.is_none() { cfg.server.port } else { port };

            tracing::info!("DataChain Rust v1.0.0");
            tracing::info!("Loading config from: {}", cli.config);

            // 初始化组件
            let chain = create_chain(cfg.blockchain.difficulty, cfg.blockchain.block_size);
            chain.init();
            tracing::info!("Blockchain initialized with {} block(s)", chain.get_block_count());

            let storage = Arc::new(
                Storage::new(&cfg.database.dsn)
                    .await
                    .expect("Failed to initialize storage"),
            );
            let auth_service = Arc::new(AuthService::new(
                cfg.jwt.secret.clone(),
                cfg.jwt.expire_hours,
            ));
            let metadata_manager = Arc::new(MetadataManager::new(chain.clone()));
            let version_tracker = Arc::new(VersionTracker::new());
            let aggregation_engine = Arc::new(AggregationEngine::new(
                chain.clone(),
                cfg.aggregation.time_interval_secs,
                cfg.aggregation.count_threshold,
            ));

            let state = AppState::new(
                chain,
                auth_service,
                metadata_manager,
                version_tracker,
                aggregation_engine,
                storage,
            );

            let addr = format!("{}:{}", cfg.server.host, port);
            tracing::info!("Starting server on http://{}", addr);

            run_server(state, &addr).await?;
        }
    }

    Ok(())
}
