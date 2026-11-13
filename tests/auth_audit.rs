//! S7:认证审计日志(auth_audit_log)的行为测试。
//! 经 HTTP router oneshot 触发认证事件,经 Storage 公开方法读取审计表内容断言。
mod common;

use std::net::SocketAddr;
use std::time::Duration;

use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::{Request, StatusCode};
use axum::Router;
use common::*;
use datachain::api::{self, AppState};
use datachain::auth::{JwtHandler, Role};
use datachain::storage::{AuditEvent, AUDIT_RETENTION_SECS};
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

struct Tokens {
    access: String,
    refresh: String,
    sid: String,
}

impl Fixture {
    async fn login_raw(
        &self,
        username: &str,
        password: &str,
        peer: Option<&str>,
    ) -> (StatusCode, Value) {
        let mut req = post(
            "/api/v1/auth/login",
            None,
            json!({"username": username, "password": password}),
        );
        if let Some(peer) = peer {
            let peer: SocketAddr = peer.parse().unwrap();
            req.extensions_mut().insert(ConnectInfo(peer));
        }
        let resp = self.router.clone().oneshot(req).await.unwrap();
        (resp.status(), body_json(resp).await)
    }

    async fn login(&self, peer: Option<&str>) -> Tokens {
        let (status, body) = self.login_raw("alice", "alicepass123", peer).await;
        assert_eq!(status, StatusCode::OK);
        let access = body["data"]["token"].as_str().unwrap().to_string();
        let refresh = body["data"]["refresh_token"].as_str().unwrap().to_string();
        let sid = self
            .state
            .auth_service
            .validate_token(&access)
            .unwrap()
            .sid
            .unwrap();
        Tokens {
            access,
            refresh,
            sid,
        }
    }

    async fn refresh(&self, token: &str) -> StatusCode {
        self.router
            .clone()
            .oneshot(post(
                "/api/v1/auth/refresh",
                None,
                json!({"refresh_token": token}),
            ))
            .await
            .unwrap()
            .status()
    }

    async fn status(&self, req: Request<Body>) -> StatusCode {
        self.router.clone().oneshot(req).await.unwrap().status()
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

    fn alice_id(&self) -> String {
        self.state.auth_service.get_user("alice").unwrap().user_id
    }
}

#[tokio::test]
async fn wrong_password_writes_login_failure_row() {
    let f = fixture().await;
    let (status, _) = f.login_raw("alice", "wrong-password", Some(PEER)).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    let rows = f.events_of("login_failure").await;
    assert_eq!(rows.len(), 1, "一次错误登录应恰好写一行 login_failure");
    let row = &rows[0];
    assert_eq!(row.result, "failure");
    assert_eq!(row.user_id.as_deref(), Some(f.alice_id().as_str()));
    assert_eq!(row.username_attempted.as_deref(), Some("alice"));
    assert!(row.session_id.is_none());
    assert!(row.reason.is_some());
    assert!(row.ts > 0);
}

#[tokio::test]
async fn unknown_user_login_failure_has_no_user_id() {
    let f = fixture().await;
    let (status, _) = f.login_raw("Nobody", "whatever-pass", None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    let rows = f.events_of("login_failure").await;
    assert_eq!(rows.len(), 1);
    assert!(rows[0].user_id.is_none());
    assert_eq!(
        rows[0].username_attempted.as_deref(),
        Some("nobody"),
        "用户名应规范化为小写"
    );
}

#[tokio::test]
async fn successful_login_writes_login_success_with_session_and_hashed_ip() {
    let f = fixture().await;
    let t = f.login(Some(PEER)).await;

    let rows = f.events_of("login_success").await;
    assert_eq!(rows.len(), 1);
    let row = &rows[0];
    assert_eq!(row.result, "success");
    assert_eq!(row.user_id.as_deref(), Some(f.alice_id().as_str()));
    assert_eq!(row.session_id.as_deref(), Some(t.sid.as_str()));
    let ip_hash = row.ip_hash.as_deref().expect("有对端地址时应记录 ip_hash");
    assert_eq!(ip_hash.len(), 32);
    assert!(ip_hash.chars().all(|c| c.is_ascii_hexdigit()));
}

#[tokio::test]
async fn rate_limited_login_writes_login_locked() {
    let f = fixture().await;
    for _ in 0..5 {
        let (status, _) = f.login_raw("alice", "wrong-password", None).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }
    let (status, _) = f.login_raw("alice", "wrong-password", None).await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);

    let locked = f.events_of("login_locked").await;
    assert_eq!(locked.len(), 1);
    assert_eq!(locked[0].result, "denied");
    assert_eq!(locked[0].username_attempted.as_deref(), Some("alice"));
    assert_eq!(f.events_of("login_failure").await.len(), 5);
}

#[tokio::test]
async fn refresh_success_and_reuse_are_audited() {
    let f = fixture().await;
    let t = f.login(None).await;
    assert_eq!(f.refresh(&t.refresh).await, StatusCode::OK);

    let ok = f.events_of("refresh_success").await;
    assert_eq!(ok.len(), 1);
    assert_eq!(ok[0].session_id.as_deref(), Some(t.sid.as_str()));
    assert_eq!(ok[0].user_id.as_deref(), Some(f.alice_id().as_str()));

    // 复用旧 refresh。
    assert_eq!(f.refresh(&t.refresh).await, StatusCode::UNAUTHORIZED);
    let reuse = f.events_of("refresh_reuse_detected").await;
    assert_eq!(reuse.len(), 1);
    assert_eq!(reuse[0].result, "denied");
    assert_eq!(reuse[0].session_id.as_deref(), Some(t.sid.as_str()));
}

#[tokio::test]
async fn logout_logout_all_and_session_revocation_are_audited() {
    let f = fixture().await;
    let first = f.login(None).await;
    let second = f.login(None).await;
    let third = f.login(None).await;

    // 撤销第二个会话。
    let req = Request::builder()
        .method("DELETE")
        .uri(format!("/api/v1/auth/sessions/{}", second.sid))
        .header("authorization", format!("Bearer {}", first.access))
        .body(Body::empty())
        .unwrap();
    assert_eq!(f.status(req).await, StatusCode::NO_CONTENT);
    let revoked = f.events_of("session_revoked").await;
    assert_eq!(revoked.len(), 1);
    assert_eq!(revoked[0].session_id.as_deref(), Some(second.sid.as_str()));
    assert_eq!(revoked[0].user_id.as_deref(), Some(f.alice_id().as_str()));

    // 登出第三个会话。
    let status = f
        .status(post("/api/v1/auth/logout", Some(&third.access), json!({})))
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let logout = f.events_of("logout").await;
    assert_eq!(logout.len(), 1);
    assert_eq!(logout[0].session_id.as_deref(), Some(third.sid.as_str()));

    // 全部登出。
    let status = f
        .status(post(
            "/api/v1/auth/logout-all",
            Some(&first.access),
            json!({}),
        ))
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let all = f.events_of("logout_all").await;
    assert_eq!(all.len(), 1);
    assert_eq!(all[0].user_id.as_deref(), Some(f.alice_id().as_str()));
}

#[tokio::test]
async fn runtime_deactivate_and_activate_write_to_sqlite_and_audit() {
    let f = fixture().await;
    f.state.storage.set_active_cache_ttl(Duration::ZERO);
    let t = f.login(None).await;
    let user_id = f.alice_id();

    let revoked = f
        .state
        .auth_service
        .deactivate_user(&user_id)
        .await
        .unwrap();
    assert_eq!(revoked, 1, "应撤销该用户全部有效会话");
    assert!(!f.state.storage.is_user_active(&user_id).await.unwrap());
    let session = f.state.storage.get_session(&t.sid).await.unwrap().unwrap();
    assert!(session.revoked_at.is_some());
    let profile = get("/api/v1/auth/profile", Some(&t.access));
    assert_eq!(f.status(profile).await, StatusCode::UNAUTHORIZED);
    assert_eq!(f.refresh(&t.refresh).await, StatusCode::UNAUTHORIZED);
    let (status, _) = f.login_raw("alice", "alicepass123", None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "停用账户不能登录");

    f.state.auth_service.activate_user(&user_id).await.unwrap();
    assert!(f.state.storage.is_user_active(&user_id).await.unwrap());
    // 激活不恢复旧会话,但可重新登录。
    let profile = get("/api/v1/auth/profile", Some(&t.access));
    assert_eq!(f.status(profile).await, StatusCode::UNAUTHORIZED);
    let (status, _) = f.login_raw("alice", "alicepass123", None).await;
    assert_eq!(status, StatusCode::OK);

    let off = f.events_of("user_deactivated").await;
    assert_eq!(off.len(), 1);
    assert_eq!(off[0].user_id.as_deref(), Some(user_id.as_str()));
    assert_eq!(f.events_of("user_activated").await.len(), 1);
}

#[tokio::test]
async fn deactivating_unknown_user_is_an_error() {
    let f = fixture().await;
    assert!(f
        .state
        .auth_service
        .deactivate_user("no-such-user")
        .await
        .is_err());
    assert!(f
        .state
        .auth_service
        .activate_user("no-such-user")
        .await
        .is_err());
    assert!(f.events().await.is_empty(), "失败操作不写成功审计");
}

#[tokio::test]
async fn audit_table_never_contains_secrets() {
    let f = fixture().await;
    let wrong_password = "wrongpass-ZZ-98765";
    let _ = f.login_raw("alice", wrong_password, Some(PEER)).await;
    let t = f.login(Some(PEER)).await;
    let rotated = {
        let resp = f
            .router
            .clone()
            .oneshot(post(
                "/api/v1/auth/refresh",
                None,
                json!({"refresh_token": t.refresh}),
            ))
            .await
            .unwrap();
        body_json(resp).await
    };
    let new_access = rotated["data"]["token"].as_str().unwrap().to_string();
    let new_refresh = rotated["data"]["refresh_token"]
        .as_str()
        .unwrap()
        .to_string();
    let _ = f.refresh(&t.refresh).await; // 复用
    let _ = f
        .status(post(
            "/api/v1/auth/logout-all",
            Some(&new_access),
            json!({}),
        ))
        .await;

    let jwt = JwtHandler::new(JWT_SECRET.to_string(), 24);
    let jtis = [
        jwt.parse_refresh_claims(&t.refresh).unwrap().jti,
        jwt.parse_refresh_claims(&new_refresh).unwrap().jti,
    ];
    let dump = format!("{:?}", f.events().await);
    assert!(dump.contains("login_success"), "应有审计行,避免空表假阳性");
    let mut needles = vec![
        "alicepass123".to_string(),
        wrong_password.to_string(),
        t.access.clone(),
        t.refresh.clone(),
        new_access,
        new_refresh,
        PLAIN_IP.to_string(),
        "Bearer".to_string(),
    ];
    needles.extend(jtis);
    for needle in needles {
        assert!(!dump.contains(&needle), "审计表不得包含 {}", needle);
    }
}

#[tokio::test]
async fn newlines_and_ansi_sequences_in_username_are_escaped() {
    let f = fixture().await;
    let evil = "ev\nil\r\u{1b}[31mred\u{7}";
    let (status, _) = f.login_raw(evil, "whatever-pass", None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    let rows = f.events_of("login_failure").await;
    assert_eq!(rows.len(), 1);
    let stored = rows[0].username_attempted.as_deref().unwrap();
    assert!(
        !stored.chars().any(|c| c.is_control()),
        "不得含原始控制字符: {:?}",
        stored
    );
    assert!(stored.contains("\\n") && stored.contains("\\r"));
    assert!(stored.contains("\\x1b"), "ESC 应被转义: {}", stored);
}

#[tokio::test]
async fn long_username_and_user_agent_are_truncated() {
    let f = fixture().await;
    let long_name = "u".repeat(500);
    let mut req = post(
        "/api/v1/auth/login",
        None,
        json!({"username": long_name, "password": "whatever-pass"}),
    );
    req.headers_mut()
        .insert("user-agent", "a".repeat(600).parse().unwrap());
    assert_eq!(f.status(req).await, StatusCode::UNAUTHORIZED);

    let rows = f.events_of("login_failure").await;
    assert_eq!(rows.len(), 1);
    assert!(
        rows[0]
            .username_attempted
            .as_deref()
            .unwrap()
            .chars()
            .count()
            <= 128
    );
    assert!(rows[0].user_agent.as_deref().unwrap().chars().count() <= 200);
}

#[tokio::test]
async fn audit_write_failure_does_not_block_authentication() {
    let f = fixture().await;
    // 另开一个连接把审计表删掉,模拟审计写入持续失败。
    let pool = sqlx::sqlite::SqlitePoolOptions::new()
        .max_connections(1)
        .connect(&format!("sqlite:{}?mode=rw", f.dsn))
        .await
        .unwrap();
    sqlx::query("DROP TABLE auth_audit_log")
        .execute(&pool)
        .await
        .unwrap();

    let t = f.login(None).await;
    let (status, _) = f.login_raw("alice", "wrong-password", None).await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "审计失败不得把 401 变 500"
    );
    assert_eq!(f.refresh(&t.refresh).await, StatusCode::OK);
    let status = f
        .status(post("/api/v1/auth/logout", Some(&t.access), json!({})))
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn purge_removes_only_rows_older_than_retention() {
    let f = fixture().await;
    let now = chrono::Utc::now().timestamp();
    let mut old = AuditEvent::new("login_failure", "failure");
    old.ts = now - AUDIT_RETENTION_SECS - 60;
    let mut recent = AuditEvent::new("login_failure", "failure");
    recent.ts = now - AUDIT_RETENTION_SECS + 3600;
    f.state.storage.append_audit_event(&old).await.unwrap();
    f.state.storage.append_audit_event(&recent).await.unwrap();

    let removed = f
        .state
        .storage
        .purge_audit_before(now - AUDIT_RETENTION_SECS)
        .await
        .unwrap();
    assert_eq!(removed, 1);
    let left = f.events().await;
    assert_eq!(left.len(), 1);
    assert_eq!(left[0].ts, recent.ts);
    assert_eq!(AUDIT_RETENTION_SECS, 90 * 24 * 3600);
}
