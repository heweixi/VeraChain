use clap::{Parser, Subcommand};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

mod api;
mod cli;
mod config;
mod core;
mod crypto;
mod error;
mod metadata;
mod storage;
mod aggregation;
mod versioning;
mod auth;
mod utils;

use crate::config::AppConfig;

#[derive(Parser)]
#[command(name = "datachain")]
#[command(author = "DataChain Team")]
#[command(version = "0.1.0")]
#[command(about = "数据追溯区块链系统 - Rust 实现", long_about = None)]
struct Cli {
    /// 配置文件路径
    #[arg(short, long, default_value = "config.toml")]
    config: String,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// 启动服务
    Serve {
        /// 服务端口
        #[arg(short, long, default_value = "8080")]
        port: u16,
    },
    /// 初始化区块链
    Init,
    /// 查看系统状态
    Status,
    /// 查看版本信息
    Info {
        /// 显示详细信息
        #[arg(short, long)]
        detailed: bool,
    },
    /// 区块链管理
    Chain {
        #[command(subcommand)]
        action: cli::chain::ChainAction,
    },
    /// 元数据管理
    Metadata {
        #[command(subcommand)]
        action: cli::metadata::MetadataAction,
    },
    /// 用户管理
    User {
        #[command(subcommand)]
        action: cli::user::UserAction,
    },
    /// 汇总管理
    Aggregate {
        #[command(subcommand)]
        action: cli::aggregate::AggregateAction,
    },
    /// 版本管理
    Version {
        #[command(subcommand)]
        action: cli::version::VersionAction,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // 强制行缓冲
    use std::io::Write;
    
    // 初始化日志
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::new(
            std::env::var("RUST_LOG").unwrap_or_else(|_| "debug".into()),
        ))
        .with(tracing_subscriber::fmt::layer().with_ansi(false))
        .init();

    eprintln!("DataChain 启动中...");
    std::io::stderr().flush().ok();
    
    tracing::info!("DataChain 启动中...");

    let cli = Cli::parse();

    eprintln!("加载配置文件: {}", cli.config);
    tracing::info!("加载配置文件: {}", cli.config);

    // 加载配置
    let config = match AppConfig::load(&cli.config) {
        Ok(c) => {
            eprintln!("配置加载成功");
            tracing::info!("配置加载成功");
            c
        }
        Err(e) => {
            eprintln!("配置加载失败: {}", e);
            tracing::error!("配置加载失败: {}", e);
            return Err(e);
        }
    };

    match cli.command {
        Commands::Serve { port } => {
            eprintln!("启动服务器，端口: {}", port);
            tracing::info!("启动服务器，端口: {}", port);
            cli::server::run_server(config, port).await?;
        }
        Commands::Init => {
            cli::init::run_init(&config).await?;
        }
        Commands::Status => {
            cli::status::run_status(&config).await?;
        }
        Commands::Info { detailed } => {
            cli::info::run_info(detailed);
        }
        Commands::Chain { action } => {
            cli::chain::run_chain(&config, action).await?;
        }
        Commands::Metadata { action } => {
            cli::metadata::run_metadata(&config, action).await?;
        }
        Commands::User { action } => {
            cli::user::run_user(&config, action).await?;
        }
        Commands::Aggregate { action } => {
            cli::aggregate::run_aggregate(&config, action).await?;
        }
        Commands::Version { action } => {
            cli::version::run_version(&config, action).await?;
        }
    }

    Ok(())
}
