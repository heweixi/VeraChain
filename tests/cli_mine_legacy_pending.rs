//! B19:CLI `chain mine` 对 `legacy_unverified` pending 身份交易 fail-closed 的特征测试。
//!
//! 现有行为(不改 src/):`run_chain(Mine)` 在挖矿前调用
//! `recover_pending_identity_transactions`,其内部的 `get_pending_identity_transactions`
//! 遇到 `status='pending' AND recovery_state != 'verified'` 的行返回
//! `DataChainError::StorageError("refusing to recover N unverifiable legacy pending identity transaction(s)")`,
//! 经 `exit_code_for` 映射为退出码 1(非数据损坏的 3)。失败发生在任何写操作之前,
//! 因此区块数与账本行均保持不变。对照组把该行改为 `verified` 后,同一命令应成功出块
//! 并把交易转为 committed。
//!
//! 旧版库由独立 sqlx 连接手工向 `identity_transactions` 插入 `legacy_unverified` 行构造
//! (与 migration_upgrade_from_legacy_pending.rs 同一思路)。

use std::process::Command;

use datachain::config::AppConfig;
use datachain::core::{Block, KeyTransactionEntry};
use datachain::storage::create_storage;
use sqlx::sqlite::SqlitePoolOptions;
use sqlx::{Pool, Sqlite};

const TX_ID: &str = "legacy-tx";

fn write_config(path: &std::path::Path, dsn: &str) {
    let mut config = AppConfig::default();
    config.database.dsn = dsn.to_string();
    config.blockchain.difficulty = 1;
    config.jwt.secret = "cli-mine-legacy-pending-test-secret-0123456789".to_string();
    config.claim_policy.min_weight = 1;
    std::fs::write(path, toml::to_string(&config).unwrap()).unwrap();
}

async fn connect(dsn: &str) -> Pool<Sqlite> {
    SqlitePoolOptions::new()
        .max_connections(1)
        .connect(&format!("sqlite:{}?mode=rwc", dsn))
        .await
        .unwrap()
}

fn legacy_entry() -> KeyTransactionEntry {
    KeyTransactionEntry {
        tx_type: "register".to_string(),
        target_key: "key-legacy".to_string(),
        role: "node".to_string(),
        label: "legacy".to_string(),
        signed_by: "key-legacy".to_string(),
        signature: "signature".to_string(),
        timestamp: 10,
        reason: String::new(),
    }
}

/// 经 create_storage 建库(迁移到最新)、写创世块,再用独立连接插入一条
/// pending + legacy_unverified 的身份交易行。
async fn build_db_with_legacy_pending(dsn: &str) {
    let storage = create_storage(dsn).await.unwrap();
    let mut genesis = Block::new(0, "0".to_string(), 1);
    genesis.mine();
    storage.save_block(&genesis).await.unwrap();
    drop(storage);

    let entry_json = serde_json::to_string(&legacy_entry()).unwrap();
    let pool = connect(dsn).await;
    sqlx::query(
        "INSERT INTO identity_transactions \
         (transaction_id, submitter_user_id, idempotency_key, request_fingerprint, entry, accepted_at, status, committed_block_index, recovery_state) \
         VALUES (?, 'user-a', NULL, 'legacy-fingerprint', ?, 10, 'pending', NULL, 'legacy_unverified')",
    )
    .bind(TX_ID)
    .bind(entry_json)
    .execute(&pool)
    .await
    .unwrap();
    pool.close().await;
}

fn run_cli(config_path: &std::path::Path, args: &[&str]) -> std::process::Output {
    let mut full_args = vec!["--config", config_path.to_str().unwrap()];
    full_args.extend_from_slice(args);
    Command::new(env!("CARGO_BIN_EXE_datachain"))
        .args(full_args)
        .output()
        .unwrap()
}

async fn block_count(pool: &Pool<Sqlite>) -> i64 {
    let (n,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM blocks")
        .fetch_one(pool)
        .await
        .unwrap();
    n
}

/// 返回 (status, recovery_state, committed_block_index)。
async fn ledger_row(pool: &Pool<Sqlite>) -> (String, String, Option<i64>) {
    sqlx::query_as(
        "SELECT status, recovery_state, committed_block_index FROM identity_transactions WHERE transaction_id = ?",
    )
    .bind(TX_ID)
    .fetch_one(pool)
    .await
    .unwrap()
}

#[tokio::test]
async fn chain_mine_refuses_legacy_unverified_pending_and_changes_nothing() {
    let directory = tempfile::tempdir().unwrap();
    let dsn = directory.path().join("datachain.sqlite");
    let dsn_str = dsn.to_str().unwrap();
    let config_path = directory.path().join("config.toml");
    build_db_with_legacy_pending(dsn_str).await;
    write_config(&config_path, dsn_str);

    let output = run_cli(&config_path, &["chain", "mine"]);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(
        output.status.code(),
        Some(1),
        "legacy_unverified 应以 StorageError 退出码 1(非数据损坏的 3),stderr: {}",
        stderr
    );
    assert!(
        stderr.contains("refusing to recover"),
        "stderr 应含 refusing to recover,实际: {}",
        stderr
    );
    assert!(
        stderr.contains("unverifiable legacy pending identity transaction"),
        "stderr 应含 unverifiable legacy pending identity transaction,实际: {}",
        stderr
    );

    let pool = connect(dsn_str).await;
    assert_eq!(block_count(&pool).await, 1, "拒绝恢复时不得挖出新块");
    assert_eq!(
        ledger_row(&pool).await,
        ("pending".to_string(), "legacy_unverified".to_string(), None),
        "账本行不得被改动"
    );
    pool.close().await;
}

#[tokio::test]
async fn chain_mine_succeeds_once_row_is_marked_verified() {
    let directory = tempfile::tempdir().unwrap();
    let dsn = directory.path().join("datachain.sqlite");
    let dsn_str = dsn.to_str().unwrap();
    let config_path = directory.path().join("config.toml");
    build_db_with_legacy_pending(dsn_str).await;
    write_config(&config_path, dsn_str);

    // 对照:同一库,仅把 recovery_state 改为 verified。
    let pool = connect(dsn_str).await;
    sqlx::query(
        "UPDATE identity_transactions SET recovery_state = 'verified' WHERE transaction_id = ?",
    )
    .bind(TX_ID)
    .execute(&pool)
    .await
    .unwrap();

    let output = run_cli(&config_path, &["chain", "mine"]);
    assert_eq!(
        output.status.code(),
        Some(0),
        "verified 的 pending 应能正常出块,stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    assert_eq!(block_count(&pool).await, 2, "应挖出第二个区块");
    assert_eq!(
        ledger_row(&pool).await,
        ("committed".to_string(), "verified".to_string(), Some(1)),
        "交易应转为 committed 并记录区块索引 1"
    );
    pool.close().await;
}
