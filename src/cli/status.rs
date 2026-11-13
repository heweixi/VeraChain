use crate::cli::common::load_verified_chain;
use crate::config::AppConfig;
use crate::core::create_chain;
use crate::storage::create_storage;

/// 运行状态检查。区块经 load_verified_chain 严格校验,链无效或数据损坏
/// 时 fail-closed,不打印基于未经验证数据的"系统状态"。
pub async fn run_status(config: &AppConfig) -> anyhow::Result<()> {
    println!("DataChain 系统状态");
    println!("==================");

    // 初始化存储
    let storage = create_storage(&config.database.dsn).await?;
    let chain = create_chain(config.blockchain.difficulty, config.blockchain.block_size);
    let blocks = load_verified_chain(&storage, &chain).await?;

    // 获取用户数量
    let users = storage.get_all_users().await?;

    // 获取版本数量
    let versions = storage.get_all_versions().await?;

    println!("数据库: {}", config.database.dsn);
    println!("区块数量: {}", blocks.len());
    println!("用户数量: {}", users.len());
    println!("版本数量: {}", versions.len());
    println!();

    println!("系统信息");
    println!("--------");
    println!("Rust 版本: {}", rustc_version_runtime::version());
    println!("操作系统: {}", std::env::consts::OS);
    println!("架构: {}", std::env::consts::ARCH);

    Ok(())
}
