//! S2:anchor_outbox 权威源严格读取 —— 未知 status 与坏 JSON 均须 fail-closed。
//!
//! Red 基线(实施前):
//! - `AnchorStatus::parse_status` 把任何未知字符串静默当作 Pending,
//!   list_pending_anchors/get_anchor 不会报错,损坏被悄悄吞掉。
//! - signed/receipt 列坏 JSON 时走 `?`(`From<serde_json::Error>`),返回裸
//!   SerializationError,没有 table/key 结构。

mod common;

use chrono::Utc;
use datachain::crosschain::{AnchorStatus, ChainAnchor, SignedChainAnchor};
use datachain::core::MerkleProof;
use datachain::error::{CorruptionCategory, DataChainError};
use datachain::storage::create_storage;

fn sample_signed(anchor_id: &str) -> SignedChainAnchor {
    SignedChainAnchor {
        anchor: ChainAnchor {
            anchor_id: anchor_id.to_string(),
            source_chain_id: "src".to_string(),
            source_node_id: "node-1".to_string(),
            target_chain_id: "dst".to_string(),
            data_id: "data-1".to_string(),
            block_hash: "h".repeat(16),
            merkle_root: "root".to_string(),
            proof: MerkleProof {
                leaf: "leaf".to_string(),
                leaf_index: 0,
                siblings: Vec::new(),
                sibling_is_left: Vec::new(),
                root: "root".to_string(),
            },
            created_at: Utc::now(),
        },
        public_key: "pk".to_string(),
        signature: "sig".to_string(),
    }
}

#[tokio::test]
async fn parse_status_rejects_unknown_value_instead_of_defaulting_to_pending() {
    // 直接验证 seam 本身:parse_status 面对未知值不得静默归类为 Pending。
    assert!(AnchorStatus::parse_status("bogus").is_err());
    assert_eq!(AnchorStatus::parse_status("pending").unwrap(), AnchorStatus::Pending);
    assert_eq!(AnchorStatus::parse_status("confirmed").unwrap(), AnchorStatus::Confirmed);
    assert_eq!(AnchorStatus::parse_status("failed").unwrap(), AnchorStatus::Failed);
}

#[tokio::test]
async fn get_anchor_reports_structured_corruption_for_unknown_status() {
    let dir = tempfile::tempdir().unwrap();
    let dsn = dir.path().join("data.sqlite");
    let dsn = dsn.to_str().unwrap();
    let storage = create_storage(dsn).await.unwrap();

    let signed = sample_signed("anchor-1");
    storage.enqueue_anchor(&signed).await.unwrap();

    let pool = common::corrupt::connect(dsn).await;
    sqlx::query("UPDATE anchor_outbox SET status = 'bogus' WHERE anchor_id = ?")
        .bind("anchor-1")
        .execute(&pool)
        .await
        .unwrap();
    pool.close().await;

    let err = storage.get_anchor("anchor-1").await.unwrap_err();
    match err {
        DataChainError::DataCorruption {
            category,
            table,
            key,
            reason,
        } => {
            assert_eq!(category, CorruptionCategory::Authoritative);
            assert_eq!(table, "anchor_outbox");
            assert_eq!(key, "anchor-1");
            assert_eq!(reason, "unknown_status");
        }
        other => panic!("期望 DataCorruption,实际: {:?}", other),
    }
}

/// 辅助:对已入队的 anchor 执行一条损坏 SQL(绑定 ? = 值,? = anchor_id)。
async fn corrupt_outbox(dsn: &str, sql: &str, value: &str, anchor_id: &str) {
    let pool = common::corrupt::connect(dsn).await;
    sqlx::query(sql)
        .bind(value)
        .bind(anchor_id)
        .execute(&pool)
        .await
        .unwrap();
    pool.close().await;
}

fn assert_outbox_corruption(err: DataChainError, expected_key: &str, expected_reason: &str) {
    match err {
        DataChainError::DataCorruption {
            category,
            table,
            key,
            reason,
        } => {
            assert_eq!(category, CorruptionCategory::Authoritative);
            assert_eq!(table, "anchor_outbox");
            assert_eq!(key, expected_key);
            if expected_reason == "json_" {
                assert!(reason.starts_with("json_"), "reason={}", reason);
            } else {
                assert_eq!(reason, expected_reason);
            }
        }
        other => panic!("期望 DataCorruption,实际: {:?}", other),
    }
}

#[tokio::test]
async fn list_pending_anchors_reports_anchor_id_key_for_bad_signed_json() {
    let dir = tempfile::tempdir().unwrap();
    let dsn = dir.path().join("data.sqlite");
    let dsn = dsn.to_str().unwrap();
    let storage = create_storage(dsn).await.unwrap();

    storage.enqueue_anchor(&sample_signed("anchor-2")).await.unwrap();
    corrupt_outbox(
        dsn,
        "UPDATE anchor_outbox SET signed = ? WHERE anchor_id = ?",
        "{not valid json",
        "anchor-2",
    )
    .await;

    let err = storage.list_pending_anchors(10).await.unwrap_err();
    assert_outbox_corruption(err, "anchor-2", "json_");
}

#[tokio::test]
async fn scan_anchor_outbox_reports_unknown_status_row_filtered_by_pending_query() {
    let dir = tempfile::tempdir().unwrap();
    let dsn = dir.path().join("data.sqlite");
    let dsn = dsn.to_str().unwrap();
    let storage = create_storage(dsn).await.unwrap();

    storage.enqueue_anchor(&sample_signed("anchor-ok")).await.unwrap();
    storage.enqueue_anchor(&sample_signed("anchor-bogus")).await.unwrap();
    corrupt_outbox(
        dsn,
        "UPDATE anchor_outbox SET status = ? WHERE anchor_id = ?",
        "bogus",
        "anchor-bogus",
    )
    .await;

    // pending 查询按 status 过滤,漏掉 bogus 行;全表扫描必须抓到。
    assert_eq!(storage.list_pending_anchors(10).await.unwrap().len(), 1);
    let err = storage.scan_anchor_outbox().await.unwrap_err();
    assert_outbox_corruption(err, "anchor-bogus", "unknown_status");
}

#[tokio::test]
async fn scan_anchor_outbox_reports_bad_receipt_json_on_confirmed_row() {
    let dir = tempfile::tempdir().unwrap();
    let dsn = dir.path().join("data.sqlite");
    let dsn = dsn.to_str().unwrap();
    let storage = create_storage(dsn).await.unwrap();

    storage.enqueue_anchor(&sample_signed("anchor-conf")).await.unwrap();
    let pool = common::corrupt::connect(dsn).await;
    sqlx::query("UPDATE anchor_outbox SET status = 'confirmed', receipt = ? WHERE anchor_id = ?")
        .bind("{not valid json")
        .bind("anchor-conf")
        .execute(&pool)
        .await
        .unwrap();
    pool.close().await;

    let err = storage.scan_anchor_outbox().await.unwrap_err();
    assert_outbox_corruption(err, "anchor-conf", "json_");
}

#[tokio::test]
async fn scan_anchor_outbox_counts_healthy_rows() {
    let dir = tempfile::tempdir().unwrap();
    let dsn = dir.path().join("data.sqlite");
    let storage = create_storage(dsn.to_str().unwrap()).await.unwrap();
    storage.enqueue_anchor(&sample_signed("a1")).await.unwrap();
    storage.enqueue_anchor(&sample_signed("a2")).await.unwrap();
    assert_eq!(storage.scan_anchor_outbox().await.unwrap(), 2);
}

#[tokio::test]
async fn get_anchor_reports_structured_corruption_for_bad_signed_json() {
    let dir = tempfile::tempdir().unwrap();
    let dsn = dir.path().join("data.sqlite");
    let dsn = dsn.to_str().unwrap();
    let storage = create_storage(dsn).await.unwrap();

    let signed = sample_signed("anchor-3");
    storage.enqueue_anchor(&signed).await.unwrap();

    let pool = common::corrupt::connect(dsn).await;
    sqlx::query("UPDATE anchor_outbox SET signed = ? WHERE anchor_id = ?")
        .bind("{not valid json")
        .bind("anchor-3")
        .execute(&pool)
        .await
        .unwrap();
    pool.close().await;

    let err = storage.get_anchor("anchor-3").await.unwrap_err();
    match err {
        DataChainError::DataCorruption {
            category,
            table,
            key,
            reason,
        } => {
            assert_eq!(category, CorruptionCategory::Authoritative);
            assert_eq!(table, "anchor_outbox");
            assert_eq!(key, "anchor-3");
            assert!(reason.starts_with("json_"));
        }
        other => panic!("期望 DataCorruption,实际: {:?}", other),
    }
}

#[tokio::test]
async fn get_pending_metadata_reports_structured_corruption_with_data_id_key() {
    use datachain::core::MetadataEntry;

    let dir = tempfile::tempdir().unwrap();
    let dsn = dir.path().join("data.sqlite");
    let dsn = dsn.to_str().unwrap();
    let storage = create_storage(dsn).await.unwrap();

    let entry = MetadataEntry {
        data_id: "pending-corrupt-1".to_string(),
        data_size: 1,
        created_at: Utc::now(),
        modified_at: Utc::now(),
        owner: "t".to_string(),
        hashes: std::collections::HashMap::new(),
        metadata: std::collections::HashMap::new(),
        parent_id: None,
        tags: Vec::new(),
    };
    storage.save_pending_metadata(&entry).await.unwrap();

    let pool = common::corrupt::connect(dsn).await;
    sqlx::query("UPDATE pending_metadata SET data = ? WHERE data_id = ?")
        .bind("{not valid json")
        .bind(&entry.data_id)
        .execute(&pool)
        .await
        .unwrap();
    pool.close().await;

    let err = storage.get_pending_metadata().await.unwrap_err();
    match err {
        DataChainError::DataCorruption {
            category,
            table,
            key,
            reason,
        } => {
            assert_eq!(category, CorruptionCategory::Authoritative);
            assert_eq!(table, "pending_metadata");
            assert_eq!(key, entry.data_id);
            assert!(reason.starts_with("json_"));
        }
        other => panic!("期望 DataCorruption,实际: {:?}", other),
    }
}

#[tokio::test]
async fn get_pending_catalog_records_reports_structured_corruption_with_record_id_key() {
    use datachain::catalog::{CatalogPayload, CatalogRecord, Subject};

    let dir = tempfile::tempdir().unwrap();
    let dsn = dir.path().join("data.sqlite");
    let dsn = dsn.to_str().unwrap();
    let storage = create_storage(dsn).await.unwrap();

    let record = CatalogRecord {
        record_id: "catalog-corrupt-1".to_string(),
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
    };
    storage.save_pending_catalog_record(&record).await.unwrap();

    let pool = common::corrupt::connect(dsn).await;
    sqlx::query("UPDATE pending_catalog_records SET data = ? WHERE record_id = ?")
        .bind("{not valid json")
        .bind(&record.record_id)
        .execute(&pool)
        .await
        .unwrap();
    pool.close().await;

    let err = storage.get_pending_catalog_records().await.unwrap_err();
    match err {
        DataChainError::DataCorruption {
            category,
            table,
            key,
            reason,
        } => {
            assert_eq!(category, CorruptionCategory::Authoritative);
            assert_eq!(table, "pending_catalog_records");
            assert_eq!(key, record.record_id);
            assert!(reason.starts_with("json_"));
        }
        other => panic!("期望 DataCorruption,实际: {:?}", other),
    }
}
