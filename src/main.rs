//! DataChain Rust —— 命令行入口。
//!
//! 此前 main.rs 是一个"简化版"独立实现(自带精简 Block/HTTP、simple_hash),
//! 与 lib 中的真实模块(core/auth/api/storage/...)完全脱节。现改为薄入口:
//! 解析命令行并 dispatch 到 lib 的真实实现,使 bin 跑完整服务与 CLI。

use clap::{Parser, Subcommand};

use datachain::cli::aggregate::{run_aggregate, AggregateAction};
use datachain::cli::chain::{run_chain, ChainAction};
use datachain::cli::info::run_info;
use datachain::cli::init::run_init;
use datachain::cli::metadata::{run_metadata, MetadataAction};
use datachain::cli::server::run_server;
use datachain::cli::status::run_status;
use datachain::cli::user::{run_user, UserAction};
use datachain::cli::version::{run_version, VersionAction};
use datachain::config::AppConfig;
// utils::logger 是私有模块,经 utils 的 re-export 访问。
// 注意 utils::LogConfig 与 config::LogConfig 是两套类型,需转换。
use datachain::utils::{init_logger, LogConfig};

#[derive(Parser)]
#[command(
    name = "datachain",
    version,
    about = "DataChain - 数据追溯区块链系统 (Rust)"
)]
struct Cli {
    /// 配置文件路径
    #[arg(short, long, global = true, default_value = "config.toml")]
    config: String,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// 启动 HTTP + WebSocket 服务
    Serve {
        /// 监听端口(覆盖配置)
        #[arg(short, long)]
        port: Option<u16>,
    },
    /// 初始化数据目录与创世区块
    Init,
    /// 查看系统状态
    Status,
    /// 版本信息
    Info {
        #[arg(short, long)]
        detailed: bool,
    },
    /// 区块链操作
    Chain {
        #[command(subcommand)]
        action: ChainAction,
    },
    /// 元数据操作
    Metadata {
        #[command(subcommand)]
        action: MetadataAction,
    },
    /// 用户管理
    User {
        #[command(subcommand)]
        action: UserAction,
    },
    /// 汇总操作
    Aggregate {
        #[command(subcommand)]
        action: AggregateAction,
    },
    /// 版本追踪
    Version {
        #[command(subcommand)]
        action: VersionAction,
    },
}

/// 退出码契约(设计文档第3节):0 成功;1 其他错误;2 链校验失败(valid=false);
/// 3 数据损坏。`exit_code_for` 依赖 downcast 出底层 `DataChainError`,因此各
/// `run_*` 内部的 `anyhow::Result<()>` 错误链必须保留原始错误类型(不得用
/// `.context(..)` 包装丢失 downcast 能力的场景除外——当前实现均用 `?` 直接
/// 传播,downcast 仍可命中最内层 DataChainError)。
#[tokio::main]
async fn main() -> std::process::ExitCode {
    let cli = Cli::parse();

    // info 无需加载配置/日志
    if let Commands::Info { detailed } = &cli.command {
        run_info(*detailed);
        return std::process::ExitCode::SUCCESS;
    }

    let config = match AppConfig::load(&cli.config) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("配置加载失败: {}", e);
            return std::process::ExitCode::from(1);
        }
    };
    // config::LogConfig 仅含 level;转成 logger 的 LogConfig(其余取默认)
    init_logger(&LogConfig {
        level: config.log.level.clone(),
        ..LogConfig::default()
    });

    let result: anyhow::Result<()> = async {
        match cli.command {
            Commands::Serve { port } => {
                let p = port.unwrap_or(config.server.port);
                run_server(config, p).await?;
            }
            Commands::Init => run_init(&config).await?,
            Commands::Status => run_status(&config).await?,
            Commands::Info { .. } => unreachable!("handled above"),
            Commands::Chain { action } => run_chain(&config, action).await?,
            Commands::Metadata { action } => run_metadata(&config, action).await?,
            Commands::User { action } => run_user(&config, action).await?,
            Commands::Aggregate { action } => run_aggregate(&config, action).await?,
            Commands::Version { action } => run_version(&config, action).await?,
        }
        Ok(())
    }
    .await;

    match result {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(e) => {
            // stderr 一行固定格式(错误契约第3节);DataChainError 的 Display 已是
            // `data corruption [..] table=.. key=..: ..` 或原有各变体的中文描述,
            // 不含行内容/password_hash/secret。
            eprintln!("{}", e);
            let code = datachain::cli::common::exit_code_for(&e);
            std::process::ExitCode::from(code)
        }
    }
}
