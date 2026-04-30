use tracing::info;

use crate::config::AppConfig;
use crate::core::create_chain;
use crate::storage::create_storage;

/// 运行初始化
pub async fn run_init(config: &AppConfig) -> anyhow::Result<()> {
    info!("正在初始化 DataChain...");

    // 创建数据目录
    std::fs::create_dir_all("./data")?;
    std::fs::create_dir_all("./data/versions")?;
    std::fs::create_dir_all("./logs")?;
    std::fs::create_dir_all("./config")?;

    println!("  ✓ 创建目录: ./data");
    println!("  ✓ 创建目录: ./data/versions");
    println!("  ✓ 创建目录: ./logs");
    println!("  ✓ 创建目录: ./config");

    // 初始化存储
    let storage = create_storage(&config.database.dsn).await?;

    // 检查是否已初始化
    let count = storage.get_block_count().await?;
    if count > 0 {
        println!("区块链已初始化，共 {} 个区块", count);
        return Ok(());
    }

    // 创建区块链并初始化
    let chain = create_chain(config.blockchain.difficulty, config.blockchain.block_size);
    let genesis = chain.init();

    // 保存创世区块
    storage.save_block(&genesis).await?;

    println!();
    println!("DataChain 初始化成功！");
    println!("创世区块哈希: {}", genesis.hash);
    println!();
    println!("下一步:");
    println!("  1. 编辑配置文件: config.toml");
    println!("  2. 启动服务: datachain serve");

    Ok(())
}
