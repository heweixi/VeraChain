//! S1:权威源严格读取 —— blocks/users/versions 损坏时必须返回结构化
//! `DataChainError::DataCorruption{category:Authoritative, table, key, reason}`,
//! 而不是裸 serde_json::Error 或泛化的 StorageError(String)。
//!
//! Red 基线(实施前):
//! - get_all_blocks 对非法 JSON 返回 DataChainError::SerializationError(serde_json::Error),
//!   不含 table/key 结构。
//! - get_all_users 对非法 JSON 返回 DataChainError::StorageError(String),
//!   该 String 由 `format!("invalid user metadata: {}", e)` 构造,`e` 的 Display
//!   可能回显被解析内容,不符合"禁止 JSON 片段"的脱敏要求,也没有 table/key 字段。
//! - get_all_versions 同理。

mod common;

use datachain::error::{CorruptionCategory, DataChainError};
use datachain::storage::create_storage;

#[tokio::test]
async fn get_all_blocks_reports_structured_corruption_with_block_index_key() {
    let dir = tempfile::tempdir().unwrap();
    let dsn = dir.path().join("data.sqlite");
    let dsn = dsn.to_str().unwrap();

    let storage = create_storage(dsn).await.unwrap();
    let mut genesis = datachain::core::Block::new(0, "0".to_string(), 1);
    genesis.mine();
    storage.save_block(&genesis).await.unwrap();

    let pool = common::corrupt::connect(dsn).await;
    common::corrupt::corrupt_block_json(&pool, 0).await;
    pool.close().await;

    let err = storage.get_all_blocks().await.unwrap_err();
    match err {
        DataChainError::DataCorruption {
            category,
            table,
            key,
            reason,
        } => {
            assert_eq!(category, CorruptionCategory::Authoritative);
            assert_eq!(table, "blocks");
            assert_eq!(key, "0", "blocks 的 key 用区块索引");
            assert!(
                reason.starts_with("json_"),
                "reason 必须来自固定词表, got: {}",
                reason
            );
        }
        other => panic!("期望 DataCorruption,实际: {:?}", other),
    }
}

#[tokio::test]
async fn get_block_reports_structured_corruption_with_block_index_key() {
    let dir = tempfile::tempdir().unwrap();
    let dsn = dir.path().join("data.sqlite");
    let dsn = dsn.to_str().unwrap();

    let storage = create_storage(dsn).await.unwrap();
    let mut genesis = datachain::core::Block::new(0, "0".to_string(), 1);
    genesis.mine();
    storage.save_block(&genesis).await.unwrap();

    let pool = common::corrupt::connect(dsn).await;
    common::corrupt::corrupt_block_json(&pool, 0).await;
    pool.close().await;

    let err = storage.get_block(0).await.unwrap_err();
    match err {
        DataChainError::DataCorruption {
            category,
            table,
            key,
            ..
        } => {
            assert_eq!(category, CorruptionCategory::Authoritative);
            assert_eq!(table, "blocks");
            assert_eq!(key, "0");
        }
        other => panic!("期望 DataCorruption,实际: {:?}", other),
    }
}

/// 核心脱敏断言:users 行里 password_hash="SECRET-XYZ",损坏后错误的 Display、
/// Debug 字符串都不得包含该值。users 的 key 用 user_id 主键,不用 email/username。
#[tokio::test]
async fn get_all_users_reports_structured_corruption_and_never_leaks_password_hash() {
    let dir = tempfile::tempdir().unwrap();
    let dsn = dir.path().join("data.sqlite");
    let dsn = dsn.to_str().unwrap();

    let storage = create_storage(dsn).await.unwrap();
    let user = datachain::auth::User::new(
        "tester".to_string(),
        "SECRET-XYZ".to_string(),
        "tester@example.com".to_string(),
        datachain::auth::Role::User,
    );
    storage.save_user(&user).await.unwrap();

    let pool = common::corrupt::connect(dsn).await;
    common::corrupt::corrupt_user_metadata(&pool, &user.user_id).await;
    pool.close().await;

    let err = storage.get_all_users().await.unwrap_err();
    let display = err.to_string();
    let debug = format!("{:?}", err);
    assert!(!display.contains("SECRET-XYZ"));
    assert!(!debug.contains("SECRET-XYZ"));

    match err {
        DataChainError::DataCorruption {
            category,
            table,
            key,
            reason,
        } => {
            assert_eq!(category, CorruptionCategory::Authoritative);
            assert_eq!(table, "users");
            assert_eq!(key, user.user_id, "users 的 key 用 user_id 主键");
            assert!(reason.starts_with("json_"));
        }
        other => panic!("期望 DataCorruption,实际: {:?}", other),
    }
}

#[tokio::test]
async fn get_all_versions_reports_structured_corruption_with_version_id_key() {
    let dir = tempfile::tempdir().unwrap();
    let dsn = dir.path().join("data.sqlite");
    let dsn = dsn.to_str().unwrap();

    let storage = create_storage(dsn).await.unwrap();
    let version = datachain::versioning::Version::new(
        "/tmp/a.txt".to_string(),
        "hash123".to_string(),
        10,
        "alice".to_string(),
        "init".to_string(),
    );
    storage.save_version(&version).await.unwrap();

    let pool = common::corrupt::connect(dsn).await;
    common::corrupt::corrupt_version_timestamp(&pool, &version.version_id).await;
    pool.close().await;

    let err = storage.get_all_versions().await.unwrap_err();
    match err {
        DataChainError::DataCorruption {
            category,
            table,
            key,
            ..
        } => {
            assert_eq!(category, CorruptionCategory::Authoritative);
            assert_eq!(table, "versions");
            assert_eq!(key, version.version_id);
        }
        other => panic!("期望 DataCorruption,实际: {:?}", other),
    }
}
