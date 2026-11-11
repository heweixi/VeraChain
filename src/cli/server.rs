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

/// 从持久化存储恢复已验证区块；空存储则创建并持久化创世区块。
async fn initialize_or_load_chain(
    chain: &Arc<crate::core::Chain>,
    storage: &Arc<crate::storage::Storage>,
) -> anyhow::Result<()> {
    let blocks = storage.get_all_blocks().await?;
    if !blocks.is_empty() {
        chain.validate_loaded_blocks(&blocks)?;
        chain.load_blocks(blocks);
        info!("已加载 {} 个区块", chain.get_block_count());
    } else {
        let genesis = chain.init();
        storage.save_block(&genesis).await?;
        info!("已创建创世区块");
    }
    Ok(())
}

/// 启动时序第 4-7 步的核心逻辑,抽成独立可测函数:
/// 4) 权威源只读扫描(users/versions/pending metadata/pending catalog/anchor_outbox,
///    任一损坏即 fail-closed,此时尚无任何写操作)
/// 5) (无写)
/// 6) pending 去重(复用调用方已加载的区块判断)
/// 7) ensure_projections(&blocks)(区块校验通过后,检测并重建可重建投影)
///
/// 要求:调用方必须已对 `chain` 完成 `initialize_or_load_chain`(即区块已校验并加载),
/// 否则第 7 步重建会基于未经校验的区块。
///
/// 返回权威源数据(users/versions)供调用方后续加载进内存服务,以及投影重建报告。
pub struct StartupRecoveryResult {
    pub users: Vec<crate::auth::User>,
    pub versions: Vec<crate::versioning::Version>,
    pub pending_metadata: Vec<crate::core::MetadataEntry>,
    pub pending_catalog_records: Vec<crate::catalog::CatalogRecord>,
    pub projection_report: crate::storage::ProjectionReport,
}

pub async fn scan_authoritative_sources_and_ensure_projections(
    chain: &Arc<crate::core::Chain>,
    storage: &Arc<crate::storage::Storage>,
) -> crate::error::Result<StartupRecoveryResult> {
    // 第 4 步:权威源只读扫描,严格顺序 users → versions → refresh 撤销(无 JSON 列,
    // 由 purge_expired_refresh/is_* 按需查询,此处不整表扫描)→ pending metadata
    // → pending catalog → anchor_outbox。任一失败立即返回 Err,不执行任何写操作。
    let users = storage.get_all_users().await?;
    let versions = storage.get_all_versions().await?;
    let pending_metadata = storage.get_pending_metadata().await?;
    let pending_catalog_records = storage.get_pending_catalog_records().await?;
    let _ = storage.list_pending_anchors(i64::MAX).await?;

    // 第 7 步:区块校验已由调用方完成(initialize_or_load_chain),此处检测并重建
    // 可重建投影。
    let projection_report = storage.ensure_projections(&chain.get_all_blocks()).await?;

    Ok(StartupRecoveryResult {
        users,
        versions,
        pending_metadata,
        pending_catalog_records,
        projection_report,
    })
}

/// 运行服务器
pub async fn run_server(config: AppConfig, port: u16) -> anyhow::Result<()> {
    info!("正在启动 DataChain 服务...");

    // 创建数据目录
    std::fs::create_dir_all("./data")?;

    // 初始化存储
    let storage = create_storage(&config.database.dsn).await?;

    // 创建区块链
    let chain = create_chain(config.blockchain.difficulty, config.blockchain.block_size);

    initialize_or_load_chain(&chain, &storage).await?;

    // 启动时序第 4/7 步:权威源只读扫描(任一损坏 fail-closed,此时无写操作)+
    // 区块校验通过后检测并重建可重建投影。
    let recovery = scan_authoritative_sources_and_ensure_projections(&chain, &storage).await?;
    if !recovery.projection_report.rebuilt_tables.is_empty() {
        info!(
            event = "projection_rebuild",
            tables = ?recovery.projection_report.rebuilt_tables,
            "可重建投影与区块不一致,已重建"
        );
    }
    let users = recovery.users;
    let versions = recovery.versions;

    // 第 6 步:pending 去重。恢复尚未打包的元数据；它们不会出现在 blocks 快照中。
    // 若上次进程在 save_block 成功后删除 pending 失败，启动时丢弃已提交的重复行。
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
    for entry in recovery.pending_metadata {
        if committed_data_ids.contains(&entry.data_id) {
            storage.delete_pending_metadata(&entry.data_id).await?;
        } else {
            pending_to_load.push(entry);
        }
    }
    chain.load_pending(pending_to_load);
    info!("已加载 {} 条待打包元数据", chain.get_pending_count());

    // 恢复已被接受但尚未打包的完整语义目录记录(subject/revision/artifact/claim)。
    chain.load_pending_catalog_records(recovery.pending_catalog_records);
    info!(
        "已加载 {} 条待打包语义目录记录",
        chain.get_pending_catalog_record_count()
    );

    // 创建服务
    let auth_service = create_auth_service(
        config.jwt.secret.clone(),
        config.jwt.expire_hours,
        storage.clone(),
    );
    let metadata_manager = create_metadata_manager(chain.clone(), storage.clone());

    // 回填 metadata 查询投影(backlog #5):把已加载区块里的元数据幂等 upsert 进投影表。
    // ensure_projections 已在权威源扫描通过后、此前完成检测与必要的整体重建;
    // 此处的回填针对"投影已一致但仍可能缺少极少量历史条目"的边界场景,保持幂等。
    {
        let backfilled = storage
            .backfill_metadata_from_blocks(&chain.get_all_blocks())
            .await?;
        info!(
            "metadata 投影回填完成: {} 条(投影表共 {} 条)",
            backfilled,
            storage.metadata_projection_count().await?
        );
    }

    let version_tracker = create_version_tracker();
    let aggregation_engine = create_aggregation_engine(
        chain.clone(),
        config.aggregation.time_interval_secs,
        config.aggregation.count_threshold,
    );

    for user in users {
        auth_service.load_user(user);
    }

    // 清理已过期的刷新令牌撤销记录，避免撤销表无限增长。
    match storage
        .purge_expired_refresh(chrono::Utc::now().timestamp())
        .await
    {
        Ok(n) if n > 0 => info!("已清理 {} 条过期的刷新令牌撤销记录", n),
        Ok(_) => {}
        Err(e) => tracing::warn!("清理过期刷新令牌撤销记录失败: {}", e),
    }

    for version in versions {
        version_tracker.load_version(version);
    }

    // 加载历史聚合结果，恢复查询结果和聚合计数。aggregations 非可重建投影
    // (前置核实:含递归合并历史状态,不是纯区块导出),损坏时此处 fail-closed。
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

    let p2p = crate::p2p::P2PService::with_node_id(config.chain_identity.node_id.clone());
    let rate_limiter = Arc::new(api::RateLimiter::default());

    // 注册种子 peer(可选):环境变量 DATACHAIN_P2P_SEED_PEERS,逗号分隔,
    // 每项格式 peer_id|base_url[|auth_token]。用于 P2P 广播/发现的初始连接点。
    if let Ok(seeds) = std::env::var("DATACHAIN_P2P_SEED_PEERS") {
        for item in seeds.split(',').map(str::trim).filter(|s| !s.is_empty()) {
            let parts: Vec<&str> = item.split('|').collect();
            if parts.len() < 2 {
                tracing::warn!("忽略非法种子 peer 配置: {}", item);
                continue;
            }
            let reg = crate::p2p::PeerRegistration {
                peer_id: parts[0].to_string(),
                base_url: parts[1].to_string(),
                auth_token: parts.get(2).map(|t| t.to_string()),
            };
            match p2p.register_peer(reg) {
                Ok(peer) => info!("已注册种子 peer: {} ({})", peer.peer_id, peer.base_url),
                Err(e) => tracing::warn!("注册种子 peer {} 失败: {}", parts[0], e),
            }
        }
    }

    let _p2p_sync_task = p2p.clone().start_sync_loop(chain.clone());

    // 构造节点签名身份与跨链锚定服务。
    let ident_cfg = &config.chain_identity;
    let node_identity = match &ident_cfg.node_secret {
        Some(secret) if !secret.trim().is_empty() => {
            crate::node_signing::NodeIdentity::from_secret_base64(
                ident_cfg.node_id.clone(),
                secret,
            )?
        }
        _ => {
            let identity = crate::node_signing::NodeIdentity::generate(ident_cfg.node_id.clone());
            info!(
                "未配置 DATACHAIN_NODE_SECRET，已生成临时节点密钥；公钥: {}",
                identity.public_key_base64()
            );
            identity
        }
    };
    let connector: Option<Arc<dyn crate::crosschain::AnchorConnector>> =
        match &ident_cfg.anchor_endpoint {
            Some(endpoint) if !endpoint.trim().is_empty() => {
                info!("跨链锚定投递目标: {}", endpoint);
                Some(Arc::new(crate::crosschain::HttpAttestationConnector::new(
                    endpoint.clone(),
                    ident_cfg.anchor_auth_token.clone(),
                )))
            }
            _ => {
                info!("未配置锚定投递端点，锚定将仅生成并入库，不自动投递");
                None
            }
        };
    let anchor_service = Arc::new(
        crate::crosschain::AnchorService::new(
            Arc::new(node_identity),
            config.chain_identity.chain_id.clone(),
            storage.clone(),
            connector,
        )
        .with_default_target_chain_id(config.chain_identity.target_chain_id.clone()),
    );
    let _anchor_worker = anchor_service.clone().start_worker();
    let claim_resolver = Arc::new(crate::catalog::ClaimResolver::new(
        config.claim_policy.clone(),
    ));

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
        anchor_service,
        claim_resolver,
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::Block;

    #[tokio::test]
    async fn initialize_or_load_chain_creates_and_persists_genesis_for_empty_storage() {
        let directory = tempfile::tempdir().unwrap();
        let dsn = directory.path().join("datachain.sqlite");
        let storage = create_storage(dsn.to_str().unwrap()).await.unwrap();
        let chain = create_chain(1, 100);

        initialize_or_load_chain(&chain, &storage).await.unwrap();

        assert_eq!(chain.get_block_count(), 1);
        let stored_blocks = storage.get_all_blocks().await.unwrap();
        assert_eq!(stored_blocks.len(), 1);
        assert_eq!(stored_blocks[0].index, 0);
        assert_eq!(stored_blocks[0].previous_hash, "0");
        assert!(chain.validate_loaded_blocks(&stored_blocks).is_ok());
    }

    #[tokio::test]
    async fn initialize_or_load_chain_rejects_corrupt_storage_without_mutating_memory_or_database()
    {
        let directory = tempfile::tempdir().unwrap();
        let dsn = directory.path().join("datachain.sqlite");
        let storage = create_storage(dsn.to_str().unwrap()).await.unwrap();
        let mut corrupt = Block::new(0, "0".to_string(), 1);
        corrupt.mine();
        corrupt.metadata_list.push(crate::core::MetadataEntry {
            data_id: "tampered-after-mining".to_string(),
            data_size: 1,
            created_at: chrono::Utc::now(),
            modified_at: chrono::Utc::now(),
            owner: "tester".to_string(),
            hashes: std::collections::HashMap::new(),
            metadata: std::collections::HashMap::new(),
            parent_id: None,
            tags: Vec::new(),
        });
        storage.save_block(&corrupt).await.unwrap();
        let blocks_before = serde_json::to_value(storage.get_all_blocks().await.unwrap()).unwrap();
        let chain = create_chain(1, 100);

        assert!(initialize_or_load_chain(&chain, &storage).await.is_err());
        assert_eq!(chain.get_block_count(), 0);
        assert_eq!(
            serde_json::to_value(storage.get_all_blocks().await.unwrap()).unwrap(),
            blocks_before
        );
    }
}
