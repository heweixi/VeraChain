//! S5:鉴权中间件按会话与用户状态(SQLite 权威)校验访问令牌的行为测试。
//! 经 HTTP router oneshot 访问受保护的 `/api/v1/auth/profile`;WS 握手见 websocket_integration。
mod common;
use std::time::Duration;

use axum::extract::Extension;
use axum::http::StatusCode;
use axum::routing::get as route_get;
use axum::{middleware, Router};
use common::*;
use datachain::api::{self, AppState};
use datachain::auth::{Claims, JwtHandler, Role};
use datachain::storage::SessionRecord;
use tower::ServiceExt;

struct Fixture {
    router: Router,
    state: AppState,
    token: String,
    sid: String,
    user_id: String,
    refresh_token: String,
    _dir: tempfile::TempDir,
}

async fn fixture() -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let dsn = dir.path().join("dc.db");
    let (state, _) = build_state(dsn.to_str().unwrap()).await;
    seed_user(&state, "alice", "alicepass123", Role::User).await;
    let user_id = state.auth_service.get_user("alice").unwrap().user_id;
    let router = api::create_router(state.clone());
    let resp = router
        .clone()
        .oneshot(post(
            "/api/v1/auth/login",
            None,
            serde_json::json!({"username": "alice", "password": "alicepass123"}),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_json(resp).await;
    let token = body["data"]["token"].as_str().unwrap().to_string();
    let refresh_token = body["data"]["refresh_token"].as_str().unwrap().to_string();
    let sid = state
        .auth_service
        .validate_token(&token)
        .unwrap()
        .sid
        .expect("登录签发的 access 应带 sid");
    Fixture {
        router,
        state,
        token,
        sid,
        user_id,
        refresh_token,
        _dir: dir,
    }
}

impl Fixture {
    async fn profile_status(&self, token: &str) -> StatusCode {
        self.router
            .clone()
            .oneshot(get("/api/v1/auth/profile", Some(token)))
            .await
            .unwrap()
            .status()
    }

    /// 用同一密钥手工签发 access token(sid 可选/可伪造),模拟旧 token 或异常 token。
    fn mint(&self, role: Role, sid: Option<&str>) -> String {
        JwtHandler::new(JWT_SECRET.to_string(), 24)
            .generate_access_token(&self.user_id, "alice", role, sid)
            .unwrap()
    }
}

#[tokio::test]
async fn active_session_and_user_are_accepted() {
    let f = fixture().await;
    assert_eq!(f.profile_status(&f.token).await, StatusCode::OK);
}

#[tokio::test]
async fn revoked_session_rejects_previously_issued_access_token() {
    let f = fixture().await;
    assert_eq!(f.profile_status(&f.token).await, StatusCode::OK);
    assert!(f
        .state
        .storage
        .revoke_session(&f.sid, "logout", 3600)
        .await
        .unwrap());
    assert_eq!(
        f.profile_status(&f.token).await,
        StatusCode::UNAUTHORIZED,
        "会话撤销后旧 access token 必须立刻失效"
    );
}

#[tokio::test]
async fn token_with_unknown_sid_is_rejected() {
    let f = fixture().await;
    let token = f.mint(Role::User, Some("no-such-session"));
    assert_eq!(f.profile_status(&token).await, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn token_for_expired_session_is_rejected() {
    let f = fixture().await;
    let now = chrono::Utc::now().timestamp();
    f.state
        .storage
        .create_session(&SessionRecord {
            id: "expired-sid".to_string(),
            user_id: f.user_id.clone(),
            refresh_family: "fam".to_string(),
            created_at: now - 100,
            last_seen_at: now - 100,
            expires_at: now - 10,
            revoked_at: None,
            revoke_reason: None,
            ip_hash: None,
            user_agent: None,
        })
        .await
        .unwrap();
    let token = f.mint(Role::User, Some("expired-sid"));
    assert_eq!(f.profile_status(&token).await, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn token_whose_sid_belongs_to_another_user_is_rejected() {
    let f = fixture().await;
    seed_user(&f.state, "bob", "bobpass123456", Role::User).await;
    let bob_id = f.state.auth_service.get_user("bob").unwrap().user_id;
    let now = chrono::Utc::now().timestamp();
    f.state
        .storage
        .create_session(&SessionRecord {
            id: "bobs-sid".to_string(),
            user_id: bob_id,
            refresh_family: "fam-b".to_string(),
            created_at: now,
            last_seen_at: now,
            expires_at: now + 3600,
            revoked_at: None,
            revoke_reason: None,
            ip_hash: None,
            user_agent: None,
        })
        .await
        .unwrap();
    let token = f.mint(Role::User, Some("bobs-sid"));
    assert_eq!(f.profile_status(&token).await, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn disabling_user_in_sqlite_takes_effect_immediately_and_reenable_restores() {
    let f = fixture().await;
    // 先让缓存里记下 active=true。
    assert_eq!(f.profile_status(&f.token).await, StatusCode::OK);
    assert!(f
        .state
        .storage
        .set_user_active(&f.user_id, false)
        .await
        .unwrap());
    assert_eq!(
        f.profile_status(&f.token).await,
        StatusCode::UNAUTHORIZED,
        "禁用写入路径必须同步清缓存,不能等 TTL"
    );
    assert!(f
        .state
        .storage
        .set_user_active(&f.user_id, true)
        .await
        .unwrap());
    assert_eq!(f.profile_status(&f.token).await, StatusCode::OK);
}

#[tokio::test]
async fn legacy_token_without_sid_only_checks_user_active() {
    let f = fixture().await;
    // refresh 签发的 access 暂不带 sid,属于"无 sid 旧 token"。
    let resp = f
        .router
        .clone()
        .oneshot(post(
            "/api/v1/auth/refresh",
            None,
            serde_json::json!({"refresh_token": f.refresh_token}),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let legacy = body_json(resp).await["data"]["token"]
        .as_str()
        .unwrap()
        .to_string();
    assert!(f
        .state
        .auth_service
        .validate_token(&legacy)
        .unwrap()
        .sid
        .is_none());

    assert_eq!(f.profile_status(&legacy).await, StatusCode::OK);
    f.state
        .storage
        .set_user_active(&f.user_id, false)
        .await
        .unwrap();
    assert_eq!(f.profile_status(&legacy).await, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn database_failure_is_fail_closed_for_session_tokens() {
    let f = fixture().await;
    assert_eq!(f.profile_status(&f.token).await, StatusCode::OK);
    f.state.storage.close().await;
    assert_eq!(
        f.profile_status(&f.token).await,
        StatusCode::UNAUTHORIZED,
        "查库失败必须 fail-closed 返回 401"
    );
}

#[tokio::test]
async fn database_failure_is_fail_closed_for_legacy_tokens_when_cache_disabled() {
    let f = fixture().await;
    f.state.storage.set_active_cache_ttl(Duration::ZERO);
    let legacy = f.mint(Role::User, None);
    assert_eq!(f.profile_status(&legacy).await, StatusCode::OK);
    f.state.storage.close().await;
    assert_eq!(f.profile_status(&legacy).await, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn active_cache_serves_within_ttl_and_ttl_is_configurable() {
    let f = fixture().await;
    f.state
        .storage
        .set_active_cache_ttl(Duration::from_secs(60));
    let legacy = f.mint(Role::User, None);
    assert_eq!(f.profile_status(&legacy).await, StatusCode::OK);
    // 连接池关闭后,TTL 内的 is_active 由缓存提供:证明没有每请求查库。
    f.state.storage.close().await;
    assert_eq!(f.profile_status(&legacy).await, StatusCode::OK);
}

#[tokio::test]
async fn token_role_must_match_current_user_role() {
    let f = fixture().await;
    let forged = f.mint(Role::Admin, None);
    assert_eq!(f.profile_status(&forged).await, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn optional_auth_ignores_revoked_session_token_but_keeps_valid_one() {
    let f = fixture().await;
    let app = Router::new()
        .route(
            "/who",
            route_get(|claims: Option<Extension<Claims>>| async move {
                match claims {
                    Some(Extension(c)) => format!("user:{}", c.sub),
                    None => "anonymous".to_string(),
                }
            }),
        )
        .layer(middleware::from_fn_with_state(
            f.state.clone(),
            api::optional_auth_middleware,
        ));
    let who = |token: String| {
        let app = app.clone();
        async move {
            let resp = app.oneshot(get("/who", Some(&token))).await.unwrap();
            assert_eq!(resp.status(), StatusCode::OK, "optional 认证从不返回 401");
            let bytes = http_body_util::BodyExt::collect(resp.into_body())
                .await
                .unwrap()
                .to_bytes();
            String::from_utf8(bytes.to_vec()).unwrap()
        }
    };
    assert_eq!(who(f.token.clone()).await, format!("user:{}", f.user_id));
    f.state
        .storage
        .revoke_session(&f.sid, "logout", 3600)
        .await
        .unwrap();
    assert_eq!(who(f.token.clone()).await, "anonymous");
}
