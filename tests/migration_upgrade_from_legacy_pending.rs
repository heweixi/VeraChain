//! A6:旧版 pending 迁移库升级演练。
//!
//! 背景:某些旧部署把 identity_transactions(现 010)与 recovery_state(现 011)当作
//! 版本 7、8 登记过,而主线的 007/008 是 sessions 与登录限速/审计表,因此该库的
//! `schema_migrations` MAX(version)=8,新代码会跳过 007/008,直接从 009 开始:
//! 009 的 `ALTER TABLE sessions ADD COLUMN ip_hint` 因 sessions 不存在而失败。
//!
//! 本测试固化两件事(均经公开 `Storage::new` 入口,旧库由独立 sqlx 连接手工构造):
//! 1. 升级失败是干净的:迁移事务回滚,原有 blocks / identity_transactions 数据不丢,
//!    `schema_migrations` 仍为 MAX=8;
//! 2. 手工修复演练(删除误登记的版本 7、8)后重新升级,会在 011 的
//!    `ADD COLUMN recovery_state` 处因列已存在而失败,说明修复还需要运维额外处理列,
//!    不是单靠删版本号就能完成。
use datachain::storage::Storage;
use sqlx::sqlite::SqlitePoolOptions;
use sqlx::{Pool, Sqlite};

const MIGRATIONS_001_TO_006: [&str; 6] = [
    include_str!("../migrations/001_base.sql"),
    include_str!("../migrations/002_pending_aggregations.sql"),
    include_str!("../migrations/003_anchor_outbox.sql"),
    include_str!("../migrations/004_revoked_refresh_tokens.sql"),
    include_str!("../migrations/005_metadata_projection.sql"),
    include_str!("../migrations/006_catalog_semantic_records.sql"),
];
const IDENTITY_TRANSACTIONS: &str = include_str!("../migrations/010_identity_transactions.sql");
const IDENTITY_RECOVERY_STATE: &str =
    include_str!("../migrations/011_identity_transaction_recovery_state.sql");

async fn connect(dsn: &str) -> Pool<Sqlite> {
    SqlitePoolOptions::new()
        .max_connections(1)
        .connect(&format!("sqlite:{}?mode=rwc", dsn))
        .await
        .unwrap()
}

/// 与 Storage::apply_migrations 相同的切分方式:按 `;` 切分并跳过空语句。
async fn run_script(pool: &Pool<Sqlite>, sql: &str) {
    for statement in sql.split(';').map(str::trim).filter(|s| !s.is_empty()) {
        sqlx::query(statement).execute(pool).await.unwrap();
    }
}

/// 手工构造旧库:001-006 + 当年的 identity 两个迁移(登记为 7、8),
/// 并写入一条区块与一条 pending 身份交易。
async fn build_legacy_db(dsn: &str) {
    let pool = connect(dsn).await;
    sqlx::query(
        "CREATE TABLE schema_migrations (version INTEGER PRIMARY KEY, applied_at DATETIME DEFAULT CURRENT_TIMESTAMP)",
    )
    .execute(&pool)
    .await
    .unwrap();
    for sql in MIGRATIONS_001_TO_006 {
        run_script(&pool, sql).await;
    }
    run_script(&pool, IDENTITY_TRANSACTIONS).await;
    run_script(&pool, IDENTITY_RECOVERY_STATE).await;
    for version in 1..=8i64 {
        sqlx::query("INSERT INTO schema_migrations (version) VALUES (?)")
            .bind(version)
            .execute(&pool)
            .await
            .unwrap();
    }
    sqlx::query(
        "INSERT INTO blocks (block_index, timestamp, previous_hash, merkle_root, nonce, difficulty, hash, data) \
         VALUES (0, 0, '0', 'root', 0, 0, 'legacy-hash', '{}')",
    )
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO identity_transactions \
         (transaction_id, submitter_user_id, idempotency_key, request_fingerprint, entry, accepted_at, status, committed_block_index) \
         VALUES ('legacy-tx', 'user-a', NULL, 'legacy-fingerprint', '{}', 10, 'pending', NULL)",
    )
    .execute(&pool)
    .await
    .unwrap();
    pool.close().await;
}

/// 打开 Storage 并要求失败,返回错误文本(Storage 未实现 Debug,不能 unwrap_err)。
async fn open_expecting_error(dsn: &str) -> String {
    match Storage::new(dsn).await {
        Ok(_) => panic!("旧库升级应当失败,实际成功"),
        Err(e) => e.to_string(),
    }
}

async fn max_version(pool: &Pool<Sqlite>) -> i64 {
    let (version,): (i64,) = sqlx::query_as("SELECT MAX(version) FROM schema_migrations")
        .fetch_one(pool)
        .await
        .unwrap();
    version
}

async fn count(pool: &Pool<Sqlite>, table: &str) -> i64 {
    let (n,): (i64,) = sqlx::query_as(&format!("SELECT COUNT(*) FROM {}", table))
        .fetch_one(pool)
        .await
        .unwrap();
    n
}

#[tokio::test]
async fn legacy_pending_db_upgrade_fails_cleanly_and_manual_repair_drill_is_documented() {
    let dir = tempfile::tempdir().unwrap();
    let dsn = dir.path().join("legacy-pending.sqlite");
    let dsn = dsn.to_str().unwrap();
    build_legacy_db(dsn).await;

    // 1) MAX(version)=8 跳过主线 007/008,009 在不存在的 sessions 表上 ALTER 失败。
    let err = open_expecting_error(dsn).await;
    assert!(
        err.contains("no such table: sessions"),
        "期望 009 因 sessions 不存在而失败,实际: {}",
        err
    );

    // 2) 失败后数据未损坏:迁移事务已回滚,区块与身份账本保留,版本号仍为 8,sessions 未被创建。
    let pool = connect(dsn).await;
    assert_eq!(count(&pool, "blocks").await, 1);
    assert_eq!(count(&pool, "identity_transactions").await, 1);
    assert_eq!(max_version(&pool).await, 8);
    let sessions_table: Option<(String,)> =
        sqlx::query_as("SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'sessions'")
            .fetch_optional(&pool)
            .await
            .unwrap();
    assert!(
        sessions_table.is_none(),
        "失败的升级不得留下半成品 sessions 表"
    );
    let (recovery_state,): (String,) = sqlx::query_as(
        "SELECT recovery_state FROM identity_transactions WHERE transaction_id = 'legacy-tx'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(recovery_state, "legacy_unverified");

    // 3) 手工修复演练:删除误登记的版本 7、8 后重新升级。007-010 依次成功提交,
    //    但 011 的 ADD COLUMN recovery_state 因列已存在而失败。
    sqlx::query("DELETE FROM schema_migrations WHERE version IN (7, 8)")
        .execute(&pool)
        .await
        .unwrap();
    pool.close().await;

    let err = open_expecting_error(dsn).await;
    assert!(
        err.contains("duplicate column name"),
        "期望 011 因 recovery_state 列已存在而失败,实际: {}",
        err
    );

    // 4) 再次确认数据仍完整:每个迁移各自一个事务,011 失败只回滚自己。
    let pool = connect(dsn).await;
    assert_eq!(count(&pool, "blocks").await, 1);
    assert_eq!(count(&pool, "identity_transactions").await, 1);
    assert_eq!(max_version(&pool).await, 10);
    pool.close().await;
}
