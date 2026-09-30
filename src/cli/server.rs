use std::sync::Arc;
use tracing::info;

use crate::aggregation::{create_aggregation_engine, create_scheduler};
use crate::api;
use crate::api::{Event, EventBus, EventType, NotificationService};
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
        chain.validate_loaded_blocks(&blocks)?;
        chain.load_blocks(blocks);
        info!("已加载 {} 个区块", chain.get_block_count());
    } else {
        // 初始化创世区块
        let genesis = chain.init();
        storage.save_block(&genesis).await?;
        info!("已创建创世区块");
    }

    // 恢复尚未打包的元数据；它们不会出现在 blocks 快照中。
    // 若上次进程在 save_block 成功后删除 pending 失败，启动时丢弃已提交的重复行。
    let pending = storage.get_pending_metadata().await?;
    let committed_data_ids: std::collections::HashSet<String> = chain
        .get_all_blocks()
        .iter()
        .flat_map(|block| {
            block
                .metadata_list
                .iter()
                .map(|entry| entry.data_id.clone())
        })
        .collect();
    let mut pending_to_load = Vec::new();
    for entry in pending {
        if committed_data_ids.contains(&entry.data_id) {
            storage.delete_pending_metadata(&entry.data_id).await?;
        } else {
            pending_to_load.push(entry);
        }
    }
    chain.load_pending(pending_to_load);
    info!("已加载 {} 条待打包元数据", chain.get_pending_count());

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

    // 加载历史聚合结果，恢复查询结果和聚合计数。
    let aggregations = storage.get_all_aggregations().await?;
    for summary in aggregations {
        aggregation_engine.load_aggregation(summary);
    }

    // 创建 WebSocket Hub、通知服务和事件总线
    let ws_hub = api::WsHub::new();
    let notification = Arc::new(NotificationService::new(ws_hub.clone()));
    let event_bus = Arc::new(EventBus::new(notification));

    // 启动聚合调度器;自动聚合结果异步持久化并发布事件。
    let scheduler = create_scheduler(
        aggregation_engine.clone(),
        config.aggregation.time_interval_secs,
    );
    let callback_storage = storage.clone();
    let callback_events = event_bus.clone();
    scheduler.set_callback(Box::new(move |summary| {
        let summary = summary.clone();
        let storage = callback_storage.clone();
        let events = callback_events.clone();
        events.publish(Event::new(
            EventType::AggregationDone,
            serde_json::to_value(&summary).unwrap_or_else(|_| serde_json::json!({})),
        ));
        tokio::spawn(async move {
            if let Err(e) = storage.save_aggregation(&summary).await {
                tracing::error!("自动聚合结果持久化失败: {}", e);
            }
        });
    }));
    scheduler.start();

    let p2p = crate::p2p::P2PService::new();
    let rate_limiter = api::RateLimiter::default();
    let _p2p_sync_task = p2p.clone().start_sync_loop(chain.clone());

    // 创建应用状态
    let app_state = api::AppState {
        chain,
        auth_service,
        metadata_manager,
        version_tracker,
        aggregation_engine,
        storage,
        ws_hub,
        event_bus,
        scheduler,
        p2p,
        rate_limiter,
    };

    // 启动服务
    let addr = format!("{}:{}", config.server.host, port);
    info!("DataChain 服务启动于 http://{}", addr);
    info!("WebSocket 端点: ws://{}/ws", addr);

    api::run_server(
        app_state,
        &addr,
        config.server.tls_cert.clone(),
        config.server.tls_key.clone(),
    )
    .await?;

    Ok(())
}
