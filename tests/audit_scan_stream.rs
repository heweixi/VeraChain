//! C1(B7):`scan_auth_audit_log` 流式化的特征测试(重构保护网)。
//!
//! 这些测试在旧的 `fetch_all` 实现上应当通过,重构为 `fetch + try_next` 后必须保持通过:
//! - 大表(约 2 万行)扫描返回行数正确;
//! - 中间某行 `ts` 被写成文本时返回固定词表的 `DataCorruption`,且不回显被写入的值;
//! - 启动权威源扫描在审计表损坏时仍返回 Ok(审计只是证据)。
//!
//! 只经公开 seam:`Storage::scan_auth_audit_log` 与
//! `scan_authoritative_sources_and_ensure_projections`;批量写入与损坏注入用独立连接。
mod common;

use std::sync::Arc;

use datachain::cli::server::scan_authoritative_sources_and_ensure_projections;
use datachain::core::create_chain;
use datachain::error::{CorruptionCategory, DataChainError};
use datachain::storage::{create_storage, Storage};

/// 批量写入的审计行数。
const BULK_ROWS: i64 = 20_000;

/// 递归 CTE 一次插入 `BULK_ROWS` 行合法审计行(列以 008 迁移为准)。
/// `user_id` 形如 `bulk-<n>`,便于定位中间行。
const BULK_INSERT_SQL: &str = "WITH RECURSIVE seq(n) AS ( \
        SELECT 1 UNION ALL SELECT n + 1 FROM seq WHERE n < 20000 \
     ) \
     INSERT INTO auth_audit_log \
        (ts, event_type, user_id, username_attempted, session_id, ip_hash, user_agent, result, reason) \
     SELECT 1800000000 + n, 'login_success', 'bulk-' || n, NULL, NULL, NULL, 'bulk-ua', 'success', 'bulk' \
     FROM seq";

struct Env {
    chain: Arc<datachain::core::Chain>,
    storage: Arc<Storage>,
    dsn: String,
    _dir: tempfile::TempDir,
}

async fn new_env() -> Env {
    let dir = tempfile::tempdir().unwrap();
    let dsn = dir.path().join("dc.db").to_str().unwrap().to_string();
    let storage = create_storage(&dsn).await.unwrap();
    let chain = create_chain(1, 100);
    let genesis = chain.init();
    storage.save_block(&genesis).await.unwrap();
    Env {
        chain,
        storage,
        dsn,
        _dir: dir,
    }
}

impl Env {
    async fn sql(&self, sql: &str) {
        let pool = common::corrupt::connect(&self.dsn).await;
        common::corrupt::execute_sql(&pool, sql).await;
        pool.close().await;
    }

    /// 用独立连接批量写入 `BULK_ROWS` 行。
    async fn insert_bulk(&self) {
        self.sql(BULK_INSERT_SQL).await;
    }

    /// 按 `user_id = bulk-<n>` 查中间行的审计主键 id。
    async fn audit_id_of_bulk(&self, n: i64) -> i64 {
        let pool = common::corrupt::connect(&self.dsn).await;
        let id: i64 = sqlx::query_scalar("SELECT id FROM auth_audit_log WHERE user_id = ?")
            .bind(format!("bulk-{}", n))
            .fetch_one(&pool)
            .await
            .unwrap();
        pool.close().await;
        id
    }
}

#[tokio::test]
async fn scan_returns_row_count_for_large_audit_table() {
    let env = new_env().await;
    let before = env.storage.scan_auth_audit_log().await.unwrap();

    env.insert_bulk().await;

    let after = env.storage.scan_auth_audit_log().await.unwrap();
    assert_eq!(
        after - before,
        BULK_ROWS as usize,
        "扫描返回值应等于新增行数(before={}, after={})",
        before,
        after
    );
}

#[tokio::test]
async fn scan_reports_corrupt_middle_row_with_id_key_and_fixed_reason() {
    let env = new_env().await;
    env.insert_bulk().await;

    let middle_id = env.audit_id_of_bulk(BULK_ROWS / 2).await;
    env.sql(&format!(
        "UPDATE auth_audit_log SET ts = 'TAMPERED-VALUE' WHERE id = {}",
        middle_id
    ))
    .await;

    let err = env
        .storage
        .scan_auth_audit_log()
        .await
        .expect_err("ts 被写成文本必须被扫描发现");

    // 先按引用检查 Display/Debug 不回显,再解构字段。
    let display = format!("{}", err);
    let debug = format!("{:?}", err);
    assert!(
        !display.contains("TAMPERED-VALUE"),
        "Display 不得回显被写入的值: {}",
        display
    );
    assert!(
        !debug.contains("TAMPERED-VALUE"),
        "Debug 不得回显被写入的值: {}",
        debug
    );

    match err {
        DataChainError::DataCorruption {
            category,
            table,
            key,
            reason,
        } => {
            assert_eq!(category, CorruptionCategory::Authoritative);
            assert_eq!(table, "auth_audit_log");
            assert_eq!(key, middle_id.to_string(), "key 应为损坏行的自增主键 id");
            assert_eq!(reason, "invalid_column:ts");
        }
        other => panic!("期望 DataCorruption,实际 {:?}", other),
    }
}

#[tokio::test]
async fn startup_scan_still_ok_when_audit_table_is_corrupt() {
    let env = new_env().await;
    env.insert_bulk().await;
    let middle_id = env.audit_id_of_bulk(BULK_ROWS / 2).await;
    env.sql(&format!(
        "UPDATE auth_audit_log SET ts = 'TAMPERED-VALUE' WHERE id = {}",
        middle_id
    ))
    .await;

    // 直接扫描确实会报错(确认损坏已生效),但启动权威源扫描只告警、不阻塞。
    assert!(env.storage.scan_auth_audit_log().await.is_err());
    scan_authoritative_sources_and_ensure_projections(&env.chain, &env.storage)
        .await
        .expect("审计日志是证据而非访问决策依据,损坏不得阻塞启动");
}
