//! A3:认证安全状态(sessions、login_rate_counters)纳入启动权威源扫描;
//! auth_audit_log 只是证据,损坏不阻塞启动。
//!
//! 公开 seam:`scan_authoritative_sources_and_ensure_projections`;损坏由独立连接注入,
//! 利用 SQLite 非 STRICT 表允许写入类型不符的值。
mod common;

use std::sync::Arc;

use datachain::auth::{AuthService, LoginContext, LoginRequest, RegisterRequest};
use datachain::cli::server::scan_authoritative_sources_and_ensure_projections;
use datachain::core::create_chain;
use datachain::error::{CorruptionCategory, DataChainError};
use datachain::storage::{create_storage, Storage};

struct Env {
    chain: Arc<datachain::core::Chain>,
    storage: Arc<Storage>,
    dsn: String,
    _dir: tempfile::TempDir,
}

/// 建库 + 创世区块,并经 AuthService 公开入口登录一次:
/// 产生 sessions 行、login_rate_counters 行(ip/user 两行)与 auth_audit_log 行。
async fn env_with_auth_state() -> Env {
    let dir = tempfile::tempdir().unwrap();
    let dsn = dir.path().join("dc.db").to_str().unwrap().to_string();
    let storage = create_storage(&dsn).await.unwrap();
    let chain = create_chain(1, 100);
    let genesis = chain.init();
    storage.save_block(&genesis).await.unwrap();

    let service = AuthService::new("scan-test-secret".to_string(), 24, storage.clone());
    let user = service
        .register(&RegisterRequest {
            username: "scanuser".to_string(),
            password: "password123".to_string(),
            email: "scan@test.local".to_string(),
            role: None,
        })
        .unwrap();
    storage.save_user(&user).await.unwrap();
    service
        .login(
            &LoginRequest {
                username: "scanuser".to_string(),
                password: "password123".to_string(),
            },
            &LoginContext {
                client_ip: Some("198.51.100.9".to_string()),
                user_agent: Some("scan-test".to_string()),
            },
        )
        .await
        .unwrap();
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

    async fn scan(
        &self,
    ) -> datachain::error::Result<datachain::cli::server::StartupRecoveryResult> {
        scan_authoritative_sources_and_ensure_projections(&self.chain, &self.storage).await
    }
}

fn expect_corruption(err: DataChainError, table_expected: &str) -> String {
    match err {
        DataChainError::DataCorruption {
            category,
            table,
            key,
            reason,
        } => {
            assert_eq!(category, CorruptionCategory::Authoritative);
            assert_eq!(table, table_expected);
            assert!(!reason.is_empty());
            // reason 必须是固定词表,不得回显被写入的值。
            assert!(!reason.contains("TAMPERED-VALUE"), "reason={}", reason);
            key
        }
        other => panic!("期望 DataCorruption,实际 {:?}", other),
    }
}

#[tokio::test]
async fn healthy_auth_state_scans_ok() {
    let env = env_with_auth_state().await;
    env.scan().await.expect("健康的认证状态不应阻塞启动");
}

#[tokio::test]
async fn corrupt_session_row_fails_startup_scan_closed_with_session_id_key() {
    let env = env_with_auth_state().await;
    let session_id: (String,) = {
        let pool = common::corrupt::connect(&env.dsn).await;
        let row = sqlx::query_as("SELECT id FROM sessions LIMIT 1")
            .fetch_one(&pool)
            .await
            .unwrap();
        pool.close().await;
        row
    };
    env.sql("UPDATE sessions SET created_at = 'TAMPERED-VALUE'")
        .await;

    let err = env.scan().await.expect_err("sessions 损坏必须 fail-closed");
    let key = expect_corruption(err, "sessions");
    assert_eq!(key, session_id.0, "key 应为会话主键 id");
}

#[tokio::test]
async fn corrupt_login_rate_counter_row_fails_startup_scan_closed() {
    let env = env_with_auth_state().await;
    env.sql("UPDATE login_rate_counters SET count = 'TAMPERED-VALUE'")
        .await;

    let err = env
        .scan()
        .await
        .expect_err("login_rate_counters 损坏必须 fail-closed");
    let key = expect_corruption(err, "login_rate_counters");
    assert!(
        key.starts_with("ip:") || key.starts_with("user:"),
        "key 应为计数器主键 key 列,实际 {}",
        key
    );
    assert!(!key.contains("TAMPERED-VALUE"));
}

#[tokio::test]
async fn corrupt_audit_log_does_not_block_startup() {
    let env = env_with_auth_state().await;
    env.sql("UPDATE auth_audit_log SET ts = 'TAMPERED-VALUE'")
        .await;
    env.scan()
        .await
        .expect("审计日志是证据而非访问决策依据,损坏不得阻塞启动");
}
