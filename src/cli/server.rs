use std::sync::Arc;
use tracing::info;

use crate::aggregation::create_aggregation_engine;
use crate::api;
use crate::auth::create_auth_service;
use crate::config::AppConfig;
use crate::core::create_chain;
use crate::metadata::create_metadata_manager;
use crate::storage::create_storage;
use crate::versioning::create_version_tracker;

/// 运行服务器
pub async fn run_server(config: AppConfig, port: u16) -> anyhow::Result<()> {
    info!("正在启动 DataChain 服务...");

    // 创建数据目录
    std::fs::create_dir_all("./data")?;

    // 初始化存储
    let storage = create_storage(&config.database.dsn).await?;

    // 创建区块链
    let chain = create_chain(config.blockchain.difficulty, config.blockchain.block_size);

    // 从存储加载区块
    let blocks = storage.get_all_blocks().await?;
    if !blocks.is_empty() {
        chain.load_blocks(blocks);
        info!("已加载 {} 个区块", chain.get_block_count());
    } else {
        // 初始化创世区块
        let genesis = chain.init();
        storage.save_block(&genesis).await?;
        info!("已创建创世区块");
    }

    // 创建服务
    let auth_service = create_auth_service(config.jwt.secret.clone(), config.jwt.expire_hours);
    let metadata_manager = create_metadata_manager(chain.clone());
    let version_tracker = create_version_tracker();
    let aggregation_engine = create_aggregation_engine(
        chain.clone(),
        config.aggregation.time_interval_secs,
        config.aggregation.count_threshold,
    );

    // 加载用户
    let users = storage.get_all_users().await?;
    for user in users {
        auth_service.load_user(user);
    }

    // 加载版本
    let versions = storage.get_all_versions().await?;
    for version in versions {
        version_tracker.load_version(version);
    }

    // 创建应用状态
    let app_state = api::AppState {
        chain,
        auth_service,
        metadata_manager,
        version_tracker,
        aggregation_engine,
        storage,
    };

    // 启动服务
    let addr = format!("{}:{}", config.server.host, port);
    info!("DataChain 服务启动于 http://{}", addr);
    info!("WebSocket 端点: ws://{}/ws", addr);

    api::run_server(app_state, &addr).await?;

    Ok(())
}
