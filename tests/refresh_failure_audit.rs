//! C5(B6):refresh 失败审计(`refresh_failure`)的行为测试。
//!
//! 本文件在实现前应为 Red:
//! - `AuthService::refresh_token_with_context(&str, &LoginContext)` 尚不存在(编译失败);
//! - 现有 refresh 失败路径不写任何审计行。
//!
//! seam:HTTP router oneshot(`/api/v1/auth/refresh`)+ `AuthService::refresh_token_with_context`
//! + `Storage::list_audit_events` 读审计表;只用公开 API。
mod common;

use std::net::SocketAddr;

use axum::extract::ConnectInfo;
use axum::http::StatusCode;
use axum::Router;
use common::*;
use datachain::api::{self, AppState};
use datachain::auth::{LoginContext, RefreshClaims, Role};
use datachain::error::DataChainError;
use datachain::storage::AuditEvent;
use jsonwebtoken::{encode, EncodingKey, Header};
use serde_json::{json, Value};
use tower::ServiceExt;

const PEER: &str = "203.0.113.9:44321";
const PLAIN_IP: &str = "203.0.113.9";

struct Fixture {
    router: Router,
    state: AppState,
    dsn: String,
    _dir: tempfile::TempDir,
}

struct Tokens {
    access: String,
    refresh: String,
    sid: String,
}

async fn fixture() -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let dsn = dir.path().join("dc.db").to_str().unwrap().to_string();
    let (state, _) = build_state(&dsn).await;
    seed_user(&state, "alice", "alicepass123", Role::User).await;
    let router = api::create_router(state.clone());
    Fixture {
        router,
        state,
        dsn,
        _dir: dir,
    }
}

impl Fixture {
    async fn login(&self) -> Tokens {
        let resp = self
            .router
            .clone()
            .oneshot(post(
                "/api/v1/auth/login",
                None,
                json!({"username": "alice", "password": "alicepass123"}),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_json(resp).await;
        let access = body["data"]["token"].as_str().unwrap().to_string();
        let refresh = body["data"]["refresh_token"].as_str().unwrap().to_string();
        let sid = self
            .state
            .auth_service
            .validate_token(&access)
            .unwrap()
            .sid
            .expect("登录签发的 access 应带 sid");
        Tokens {
            access,
            refresh,
            sid,
        }
    }

    /// 带对端地址的 refresh(经 HTTP)。
    async fn refresh(&self, token: &str) -> (StatusCode, Value) {
        let mut req = post(
            "/api/v1/auth/refresh",
            None,
            json!({"refresh_token": token}),
        );
        let peer: SocketAddr = PEER.parse().unwrap();
        req.extensions_mut().insert(ConnectInfo(peer));
        let resp = self.router.clone().oneshot(req).await.unwrap();
        (resp.status(), body_json(resp).await)
    }

    async fn events(&self) -> Vec<AuditEvent> {
        self.state.storage.list_audit_events(1000).await.unwrap()
    }

    async fn events_of(&self, event_type: &str) -> Vec<AuditEvent> {
        self.events()
            .await
            .into_iter()
            .filter(|e| e.event_type == event_type)
            .collect()
    }

    /// 断言恰有一行 `refresh_failure`,且 reason 为 `reason`,返回该行。
    async fn the_failure(&self, reason: &str) -> AuditEvent {
        let rows = self.events_of("refresh_failure").await;
        assert_eq!(rows.len(), 1, "应恰好一行 refresh_failure: {:?}", rows);
        let row = rows.into_iter().next().unwrap();
        assert_eq!(row.result, "failure");
        assert_eq!(row.reason.as_deref(), Some(reason));
        row
    }

    fn alice_id(&self) -> String {
        self.state.auth_service.get_user("alice").unwrap().user_id
    }
}

/// 手工签发一个已过期的 refresh token(密钥与 iss/aud 同正常令牌)。
fn expired_refresh_token(user_id: &str, family_id: &str) -> String {
    let now = chrono::Utc::now().timestamp();
    let claims = RefreshClaims {
        sub: user_id.to_string(),
        token_type: "refresh".to_string(),
        jti: uuid::Uuid::new_v4().to_string(),
        family_id: family_id.to_string(),
        exp: now - 3600,
        iat: now - 7200,
        iss: "datachain".to_string(),
        aud: "datachain-api".to_string(),
    };
    encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(JWT_SECRET.as_bytes()),
    )
    .unwrap()
}

fn invalid_token_message() -> String {
    DataChainError::InvalidToken.to_string()
}

#[tokio::test]
async fn garbage_token_writes_invalid_token_without_user_id() {
    let f = fixture().await;
    let (status, body) = f.refresh("this-is-not-a-jwt").await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body["success"], false);
    assert_eq!(body["error"].as_str().unwrap(), invalid_token_message());

    let row = f.the_failure("invalid_token").await;
    assert!(row.user_id.is_none(), "垃圾 token 无法确定用户");
    assert!(row.session_id.is_none());
}

#[tokio::test]
async fn access_token_used_as_refresh_is_invalid_token() {
    let f = fixture().await;
    let t = f.login().await;
    let (status, _) = f.refresh(&t.access).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    f.the_failure("invalid_token").await;
}

#[tokio::test]
async fn expired_token_writes_token_expired() {
    let f = fixture().await;
    let token = expired_refresh_token(&f.alice_id(), "some-family");
    let (status, _) = f.refresh(&token).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    f.the_failure("token_expired").await;
}

#[tokio::test]
async fn inactive_user_writes_user_inactive() {
    let f = fixture().await;
    let t = f.login().await;
    // 只改 SQLite 的 is_active,不撤销会话/family,走到"用户状态"检查。
    assert!(f
        .state
        .storage
        .set_user_active(&f.alice_id(), false)
        .await
        .unwrap());

    let (status, body) = f.refresh(&t.refresh).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body["error"].as_str().unwrap(), invalid_token_message());

    let row = f.the_failure("user_inactive").await;
    assert_eq!(row.user_id.as_deref(), Some(f.alice_id().as_str()));
}

#[tokio::test]
async fn refresh_after_deactivate_user_writes_session_revoked() {
    let f = fixture().await;
    let t = f.login().await;
    f.state
        .auth_service
        .deactivate_user(&f.alice_id())
        .await
        .unwrap();

    let (status, body) = f.refresh(&t.refresh).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body["error"].as_str().unwrap(), invalid_token_message());

    let row = f.the_failure("session_revoked").await;
    assert_eq!(row.user_id.as_deref(), Some(f.alice_id().as_str()));
    assert!(
        f.events_of("refresh_reuse_detected").await.is_empty(),
        "停用不是复用"
    );
}

#[tokio::test]
async fn refresh_after_logout_writes_session_revoked() {
    let f = fixture().await;
    let t = f.login().await;
    let resp = f
        .router
        .clone()
        .oneshot(post("/api/v1/auth/logout", Some(&t.access), json!({})))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);

    let (status, body) = f.refresh(&t.refresh).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body["error"].as_str().unwrap(), invalid_token_message());

    let row = f.the_failure("session_revoked").await;
    assert_eq!(row.user_id.as_deref(), Some(f.alice_id().as_str()));
    assert!(f.events_of("refresh_reuse_detected").await.is_empty());
}

#[tokio::test]
async fn refresh_when_session_row_is_gone_writes_session_invalid() {
    let f = fixture().await;
    let t = f.login().await;
    // 独立连接删掉会话行:family 未撤销、jti 未撤销,走到"会话校验"失败。
    let pool = common::corrupt::connect(&f.dsn).await;
    sqlx::query("DELETE FROM sessions WHERE id = ?")
        .bind(&t.sid)
        .execute(&pool)
        .await
        .unwrap();
    pool.close().await;

    let (status, body) = f.refresh(&t.refresh).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body["error"].as_str().unwrap(), invalid_token_message());

    let row = f.the_failure("session_invalid").await;
    assert_eq!(row.user_id.as_deref(), Some(f.alice_id().as_str()));
}

#[tokio::test]
async fn reuse_writes_only_reuse_event_and_no_refresh_failure() {
    let f = fixture().await;
    let t = f.login().await;
    let (status, _) = f.refresh(&t.refresh).await;
    assert_eq!(status, StatusCode::OK);

    let (status, body) = f.refresh(&t.refresh).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(
        body["error"].as_str().unwrap(),
        DataChainError::TokenReuseDetected.to_string(),
        "HTTP 体保持不变"
    );

    assert_eq!(f.events_of("refresh_reuse_detected").await.len(), 1);
    assert!(
        f.events_of("refresh_failure").await.is_empty(),
        "复用只记 refresh_reuse_detected,不重复记 refresh_failure"
    );
}

#[tokio::test]
async fn refresh_failure_rows_carry_ip_hash_of_the_peer() {
    let f = fixture().await;
    let (status, _) = f.refresh("garbage").await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    let row = f.the_failure("invalid_token").await;
    let expected = f.state.auth_service.hash_client_ip(PLAIN_IP);
    assert_eq!(row.ip_hash.as_deref(), Some(expected.as_str()));
    assert_eq!(expected.len(), 32);
}

#[tokio::test]
async fn refresh_token_with_context_records_ip_hash_and_old_api_delegates() {
    let f = fixture().await;
    let ctx = LoginContext {
        client_ip: Some(PLAIN_IP.to_string()),
        user_agent: Some("ua-test".to_string()),
    };
    let err = f
        .state
        .auth_service
        .refresh_token_with_context("garbage", &ctx)
        .await
        .expect_err("垃圾 token 应失败");
    assert!(matches!(err, DataChainError::InvalidToken), "{:?}", err);

    let row = f.the_failure("invalid_token").await;
    let expected = f.state.auth_service.hash_client_ip(PLAIN_IP);
    assert_eq!(row.ip_hash.as_deref(), Some(expected.as_str()));
    assert_eq!(row.user_agent.as_deref(), Some("ua-test"));

    // 旧签名保留并委托(default 上下文:无 ip_hash),仍写失败审计。
    let err = f
        .state
        .auth_service
        .refresh_token("garbage-2")
        .await
        .expect_err("垃圾 token 应失败");
    assert!(matches!(err, DataChainError::InvalidToken), "{:?}", err);
    let rows = f.events_of("refresh_failure").await;
    assert_eq!(rows.len(), 2);
    assert!(rows.iter().any(|r| r.ip_hash.is_none()));
}

#[tokio::test]
async fn refresh_failure_audit_never_contains_secrets() {
    let f = fixture().await;
    let t = f.login().await;
    let garbage = "garbage-token-ZZ-13579";
    let _ = f.refresh(garbage).await;
    let expired = expired_refresh_token(&f.alice_id(), "fam-expired-24680");
    let _ = f.refresh(&expired).await;
    // 登出后刷新(session_revoked)。
    let _ = f
        .router
        .clone()
        .oneshot(post("/api/v1/auth/logout", Some(&t.access), json!({})))
        .await
        .unwrap();
    let _ = f.refresh(&t.refresh).await;

    let claims = datachain::auth::JwtHandler::new(JWT_SECRET.to_string(), 24)
        .parse_refresh_claims(&t.refresh)
        .unwrap();
    let dump = format!("{:?}", f.events().await);
    assert!(
        dump.contains("refresh_failure"),
        "应有失败审计行,避免空表假阳性"
    );
    let needles = [
        garbage.to_string(),
        expired,
        t.access.clone(),
        t.refresh.clone(),
        claims.jti,
        claims.family_id,
        PLAIN_IP.to_string(),
        "fam-expired-24680".to_string(),
        "Bearer".to_string(),
    ];
    for needle in needles {
        assert!(!dump.contains(&needle), "审计表不得包含 {}", needle);
    }
}

#[tokio::test]
async fn audit_table_dropped_does_not_change_refresh_status() {
    let f = fixture().await;
    let t = f.login().await;
    let pool = common::corrupt::connect(&f.dsn).await;
    sqlx::query("DROP TABLE auth_audit_log")
        .execute(&pool)
        .await
        .unwrap();
    pool.close().await;

    // 垃圾 token:仍是 401(不因审计写失败变 500)。
    let (status, body) = f.refresh("garbage").await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body["error"].as_str().unwrap(), invalid_token_message());

    // 成功轮换仍 200;复用旧 token 仍是 401 + 复用文本。
    let (status, _) = f.refresh(&t.refresh).await;
    assert_eq!(status, StatusCode::OK);
    let (status, body) = f.refresh(&t.refresh).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(
        body["error"].as_str().unwrap(),
        DataChainError::TokenReuseDetected.to_string()
    );
}
