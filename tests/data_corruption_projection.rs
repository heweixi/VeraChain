//! S3:可重建投影检测与重建。
//!
//! Red 基线(实施前):
//! - `Storage::ensure_projections` 不存在,代码无法编译通过该 seam。
//! - commit_block 内联写投影逻辑未抽成 project_block_tx,无法被重建路径复用。
//! - metadata_projection_count 对损坏表仍 `.unwrap_or(-1)` 吞错(本测试不直接测该行为,
//!   行为改动在 S4 server.rs 里验证,这里聚焦 ensure_projections 本身)。
//!
//! aggregations 前置核实结论:AggregationSummary 含 parent_summaries/is_merged等
//! 递归合并状态,不是纯粹由"当前区块集合"可确定性推导的产物(是历史聚合动作的
//! 累积状态机),因此不进入可重建投影,维持现状(S3 不处理 aggregations 表)。

mod common;

use chrono::Utc;
use datachain::core::{Block, MetadataEntry};
use datachain::storage::create_storage;

fn metadata_entry(data_id: &str, owner: &str) -> MetadataEntry {
    MetadataEntry {
        data_id: data_id.to_string(),
        data_size: 10,
        created_at: Utc::now(),
        modified_at: Utc::now(),
        owner: owner.to_string(),
        hashes: std::collections::HashMap::new(),
        metadata: std::collections::HashMap::new(),
        parent_id: None,
        tags: Vec::new(),
    }
}

/// 构造两个合法区块(含 metadata),返回 storage + 已提交的区块列表。
async fn setup_two_blocks(dsn: &str) -> (std::sync::Arc<datachain::storage::Storage>, Vec<Block>) {
    let storage = create_storage(dsn).await.unwrap();

    let mut genesis = Block::new(0, "0".to_string(), 1);
    genesis.metadata_list.push(metadata_entry("m0", "alice"));
    genesis.mine();
    storage.commit_block(&genesis).await.unwrap();

    let mut b1 = Block::new(1, genesis.hash.clone(), 1);
    b1.metadata_list.push(metadata_entry("m1", "bob"));
    b1.mine();
    storage.commit_block(&b1).await.unwrap();

    (storage, vec![genesis, b1])
}

#[tokio::test]
async fn ensure_projections_rebuilds_metadata_projection_after_row_deleted() {
    let dir = tempfile::tempdir().unwrap();
    let dsn = dir.path().join("data.sqlite");
    let dsn = dsn.to_str().unwrap();
    let (storage, blocks) = setup_two_blocks(dsn).await;

    assert_eq!(storage.metadata_projection_count().await.unwrap(), 2);

    // 直接删掉一条投影行,模拟"投影与区块数量不一致"的损坏。
    let pool = common::corrupt::connect(dsn).await;
    sqlx::query("DELETE FROM metadata WHERE data_id = 'm1'")
        .execute(&pool)
        .await
        .unwrap();
    pool.close().await;
    assert_eq!(storage.metadata_projection_count().await.unwrap(), 1);

    let report = storage.ensure_projections(&blocks).await.unwrap();
    assert!(
        report.rebuilt_tables.contains(&"metadata".to_string()),
        "数量不一致应触发 metadata 重建, got: {:?}",
        report.rebuilt_tables
    );

    assert_eq!(storage.metadata_projection_count().await.unwrap(), 2);
    assert_eq!(
        storage.get_metadata_by_id("m1").await.unwrap().unwrap().owner,
        "bob"
    );
}

#[tokio::test]
async fn ensure_projections_rebuilds_catalog_projection_after_row_corrupted() {
    use datachain::catalog::{CatalogPayload, Subject};

    let dir = tempfile::tempdir().unwrap();
    let dsn = dir.path().join("data.sqlite");
    let dsn = dsn.to_str().unwrap();
    let storage = create_storage(dsn).await.unwrap();

    let mut genesis = Block::new(0, "0".to_string(), 1);
    genesis.catalog_records.push(datachain::catalog::CatalogRecord {
        record_id: "rec-1".to_string(),
        payload: CatalogPayload::Subject(Subject {
            subject_id: "subj-1".to_string(),
            subject_type: "package".to_string(),
            display_name: "demo".to_string(),
            source_ref: String::new(),
        }),
        issuer_identity: "issuer-1".to_string(),
        issuer_key: "key-1".to_string(),
        signature: "sig-1".to_string(),
        recorded_at: Utc::now().timestamp(),
    });
    genesis.mine();
    storage.commit_block(&genesis).await.unwrap();

    assert!(storage.get_catalog_subject("subj-1").await.unwrap().is_some());

    // 把投影行的 data 列改成非法 JSON,模拟解析失败型损坏(而非数量不一致)。
    let pool = common::corrupt::connect(dsn).await;
    sqlx::query("UPDATE catalog_subjects SET data = '{not valid json' WHERE subject_id = 'subj-1'")
        .execute(&pool)
        .await
        .unwrap();
    pool.close().await;

    let report = storage
        .ensure_projections(std::slice::from_ref(&genesis))
        .await
        .unwrap();
    assert!(
        report.rebuilt_tables.contains(&"catalog_subjects".to_string()),
        "解析失败应触发 catalog_subjects 重建, got: {:?}",
        report.rebuilt_tables
    );

    let restored = storage.get_catalog_subject("subj-1").await.unwrap().unwrap();
    if let CatalogPayload::Subject(s) = restored.payload {
        assert_eq!(s.display_name, "demo");
    } else {
        panic!("恢复后的记录类型不符");
    }
}

#[tokio::test]
async fn ensure_projections_is_idempotent_when_projections_already_consistent() {
    let dir = tempfile::tempdir().unwrap();
    let dsn = dir.path().join("data.sqlite");
    let dsn = dsn.to_str().unwrap();
    let (storage, blocks) = setup_two_blocks(dsn).await;

    let first = storage.ensure_projections(&blocks).await.unwrap();
    assert!(
        first.rebuilt_tables.is_empty(),
        "投影已与区块一致时不应重建: {:?}",
        first.rebuilt_tables
    );
    assert_eq!(storage.metadata_projection_count().await.unwrap(), 2);

    // 再跑一次,确认幂等(不会重复插入或报错)。
    let second = storage.ensure_projections(&blocks).await.unwrap();
    assert!(second.rebuilt_tables.is_empty());
    assert_eq!(storage.metadata_projection_count().await.unwrap(), 2);
}
