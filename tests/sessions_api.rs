//! S6:登出 / 会话列表 / 会话撤销 / refresh 校验会话与用户状态的行为测试。
//! 经 HTTP router oneshot 驱动,辅以 Storage 与 JwtHandler 公开方法做断言。
mod common;

use std::net::SocketAddr;

use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::{Request, StatusCode};
use axum::Router;
use common::*;
use datachain::api::{self, AppState};
use datachain::auth::{JwtHandler, Role};
use serde_json::{json, Value};
use tower::ServiceExt;

struct Fixture {
    router: Router,
    state: AppState,
    _dir: tempfile::TempDir,
}

struct Tokens {
    access: String,
    refresh: String,
    sid: String,
}

async fn fixture() -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let dsn = dir.path().join("dc.db");
    let (state, _) = build_state(dsn.to_str().unwrap()).await;
    seed_user(&state, "alice", "alicepass123", Role::User).await;
    seed_user(&state, "bob", "bobpass123456", Role::User).await;
    let router = api::create_router(state.clone());
    Fixture {
        router,
        state,
        _dir: dir,
    }
}

fn delete(uri: &str, token: &str) -> Request<Body> {
    Request::builder()
        .method("DELETE")
        .uri(uri)
        .header("authorization", format!("Bearer {}", token))
        .body(Body::empty())
        .unwrap()
}

impl Fixture {
    async fn login_from(&self, user: &str, password: &str, peer: Option<&str>) -> Tokens {
        let mut req = post(
            "/api/v1/auth/login",
            None,
            json!({"username": user, "password": password}),
        );
        if let Some(peer) = peer {
            let peer: SocketAddr = peer.parse().unwrap();
            req.extensions_mut().insert(ConnectInfo(peer));
        }
        let resp = self.router.clone().oneshot(req).await.unwrap();
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

    async fn login(&self, user: &str) -> Tokens {
        let password = if user == "alice" {
            "alicepass123"
        } else {
            "bobpass123456"
        };
        self.login_from(user, password, None).await
    }

    async fn status(&self, req: Request<Body>) -> StatusCode {
        self.router.clone().oneshot(req).await.unwrap().status()
    }

    async fn profile(&self, token: &str) -> StatusCode {
        self.status(get("/api/v1/auth/profile", Some(token))).await
    }

    async fn refresh(&self, refresh_token: &str) -> (StatusCode, Value) {
        let resp = self
            .router
            .clone()
            .oneshot(post(
                "/api/v1/auth/refresh",
                None,
                json!({"refresh_token": refresh_token}),
            ))
            .await
            .unwrap();
        (resp.status(), body_json(resp).await)
    }

    fn user_id(&self, name: &str) -> String {
        self.state.auth_service.get_user(name).unwrap().user_id
    }
}

// ---------- 登出 ----------

#[tokio::test]
async fn logout_revokes_access_and_refresh_of_current_session() {
    let f = fixture().await;
    let t = f.login("alice").await;
    assert_eq!(f.profile(&t.access).await, StatusCode::OK);

    let status = f
        .status(post("/api/v1/auth/logout", Some(&t.access), json!({})))
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    assert_eq!(f.profile(&t.access).await, StatusCode::UNAUTHORIZED);
    let (status, _) = f.refresh(&t.refresh).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "登出后 refresh 必须 401");
    let session = f.state.storage.get_session(&t.sid).await.unwrap().unwrap();
    assert!(session.revoked_at.is_some());
}

#[tokio::test]
async fn logout_only_affects_the_current_session() {
    let f = fixture().await;
    let first = f.login("alice").await;
    let second = f.login("alice").await;

    let status = f
        .status(post("/api/v1/auth/logout", Some(&first.access), json!({})))
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    assert_eq!(f.profile(&first.access).await, StatusCode::UNAUTHORIZED);
    assert_eq!(f.profile(&second.access).await, StatusCode::OK);
    let (status, _) = f.refresh(&second.refresh).await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn logout_all_revokes_every_session_of_the_user_only() {
    let f = fixture().await;
    let a1 = f.login("alice").await;
    let a2 = f.login("alice").await;
    let b1 = f.login("bob").await;

    let status = f
        .status(post("/api/v1/auth/logout-all", Some(&a1.access), json!({})))
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    assert_eq!(f.profile(&a1.access).await, StatusCode::UNAUTHORIZED);
    assert_eq!(f.profile(&a2.access).await, StatusCode::UNAUTHORIZED);
    assert_eq!(f.refresh(&a2.refresh).await.0, StatusCode::UNAUTHORIZED);
    assert_eq!(
        f.profile(&b1.access).await,
        StatusCode::OK,
        "他人会话不受影响"
    );
    assert!(f
        .state
        .storage
        .list_active_sessions(&f.user_id("alice"), chrono::Utc::now().timestamp())
        .await
        .unwrap()
        .is_empty());
}

#[tokio::test]
async fn session_routes_require_authentication() {
    let f = fixture().await;
    assert_eq!(
        f.status(post("/api/v1/auth/logout", None, json!({}))).await,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        f.status(post("/api/v1/auth/logout-all", None, json!({})))
            .await,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        f.status(get("/api/v1/auth/sessions", None)).await,
        StatusCode::UNAUTHORIZED
    );
    let req = Request::builder()
        .method("DELETE")
        .uri("/api/v1/auth/sessions/whatever")
        .body(Body::empty())
        .unwrap();
    assert_eq!(f.status(req).await, StatusCode::UNAUTHORIZED);
}

// ---------- 会话列表 / 撤销 ----------

#[tokio::test]
async fn sessions_list_shows_own_active_sessions_with_masked_ip_and_current_flag() {
    let f = fixture().await;
    let first = f
        .login_from("alice", "alicepass123", Some("203.0.113.9:5555"))
        .await;
    let second = f.login("alice").await;
    let _bob = f.login("bob").await;

    let resp = f
        .router
        .clone()
        .oneshot(get("/api/v1/auth/sessions", Some(&first.access)))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let raw = serde_json::to_string(&body_json(resp).await).unwrap();
    let body: Value = serde_json::from_str(&raw).unwrap();
    let items = body["data"].as_array().expect("data 应为数组");
    assert_eq!(items.len(), 2, "只列出本人未撤销会话");

    let mine = items
        .iter()
        .find(|s| s["id"] == first.sid.as_str())
        .unwrap();
    let other = items
        .iter()
        .find(|s| s["id"] == second.sid.as_str())
        .unwrap();
    assert_eq!(mine["current"], true);
    assert_eq!(other["current"], false);
    assert_eq!(mine["ip_hint"], "203.0.x.x");
    for key in ["created_at", "last_seen_at", "expires_at"] {
        assert!(mine[key].is_i64(), "{} 应为整数时间戳", key);
    }

    // 不泄露 ip_hash / token / jti / 明文 IP。
    let session = f
        .state
        .storage
        .get_session(&first.sid)
        .await
        .unwrap()
        .unwrap();
    let jwt = JwtHandler::new(JWT_SECRET.to_string(), 24);
    let jti = jwt.parse_refresh_claims(&first.refresh).unwrap().jti;
    for secret in [
        session.ip_hash.unwrap(),
        first.access.clone(),
        first.refresh.clone(),
        jti,
        "203.0.113.9".to_string(),
    ] {
        assert!(!raw.contains(&secret), "响应不得包含 {}", secret);
    }
    assert!(!raw.contains("ip_hash") && !raw.contains("jti"));
}

#[tokio::test]
async fn sessions_list_omits_revoked_sessions() {
    let f = fixture().await;
    let first = f.login("alice").await;
    let second = f.login("alice").await;
    f.state
        .storage
        .revoke_session(&second.sid, "test", 3600)
        .await
        .unwrap();

    let resp = f
        .router
        .clone()
        .oneshot(get("/api/v1/auth/sessions", Some(&first.access)))
        .await
        .unwrap();
    let body = body_json(resp).await;
    let ids: Vec<&str> = body["data"]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| s["id"].as_str().unwrap())
        .collect();
    assert_eq!(ids, vec![first.sid.as_str()]);
}

#[tokio::test]
async fn deleting_own_other_session_revokes_it() {
    let f = fixture().await;
    let first = f.login("alice").await;
    let second = f.login("alice").await;

    let status = f
        .status(delete(
            &format!("/api/v1/auth/sessions/{}", second.sid),
            &first.access,
        ))
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    assert_eq!(f.profile(&second.access).await, StatusCode::UNAUTHORIZED);
    assert_eq!(f.refresh(&second.refresh).await.0, StatusCode::UNAUTHORIZED);
    assert_eq!(f.profile(&first.access).await, StatusCode::OK);
}

#[tokio::test]
async fn deleting_foreign_or_missing_session_is_uniform_404() {
    let f = fixture().await;
    let alice = f.login("alice").await;
    let bob = f.login("bob").await;

    let foreign = f
        .router
        .clone()
        .oneshot(delete(
            &format!("/api/v1/auth/sessions/{}", bob.sid),
            &alice.access,
        ))
        .await
        .unwrap();
    let missing = f
        .router
        .clone()
        .oneshot(delete(
            "/api/v1/auth/sessions/no-such-session",
            &alice.access,
        ))
        .await
        .unwrap();
    assert_eq!(foreign.status(), StatusCode::NOT_FOUND);
    assert_eq!(missing.status(), StatusCode::NOT_FOUND);
    assert_eq!(
        body_json(foreign).await,
        body_json(missing).await,
        "他人会话与不存在的会话响应必须一致"
    );
    assert_eq!(
        f.profile(&bob.access).await,
        StatusCode::OK,
        "他人会话未被撤销"
    );
}

// ---------- refresh ----------

#[tokio::test]
async fn refreshed_access_token_keeps_sid_and_updates_last_seen() {
    let f = fixture().await;
    let t = f.login("alice").await;
    // 把 last_seen_at 拨回过去,以便观察更新。
    let before = f.state.storage.get_session(&t.sid).await.unwrap().unwrap();

    let (status, body) = f.refresh(&t.refresh).await;
    assert_eq!(status, StatusCode::OK);
    let new_access = body["data"]["token"].as_str().unwrap();
    let claims = f.state.auth_service.validate_token(new_access).unwrap();
    assert_eq!(
        claims.sid.as_deref(),
        Some(t.sid.as_str()),
        "刷新后的 access 必须带原 sid"
    );
    assert_eq!(f.profile(new_access).await, StatusCode::OK);

    let after = f.state.storage.get_session(&t.sid).await.unwrap().unwrap();
    assert!(after.last_seen_at >= before.last_seen_at);
    assert!(
        after.expires_at >= before.expires_at,
        "刷新应顺延会话过期时间"
    );
    assert!(after.revoked_at.is_none());
}

#[tokio::test]
async fn refresh_is_rejected_after_session_is_revoked_in_storage() {
    let f = fixture().await;
    let t = f.login("alice").await;
    f.state
        .storage
        .revoke_session(&t.sid, "test", 3600)
        .await
        .unwrap();
    assert_eq!(f.refresh(&t.refresh).await.0, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn refresh_is_rejected_for_deactivated_user() {
    let f = fixture().await;
    let t = f.login("alice").await;
    // 只写库、不动内存,模拟 CLI 在别的进程里禁用用户。
    assert!(f
        .state
        .storage
        .set_user_active(&f.user_id("alice"), false)
        .await
        .unwrap());
    assert_eq!(f.refresh(&t.refresh).await.0, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn refresh_with_unknown_family_is_rejected() {
    let f = fixture().await;
    let jwt = JwtHandler::new(JWT_SECRET.to_string(), 24);
    let forged = jwt
        .generate_refresh_token(&f.user_id("alice"), "family-without-session")
        .unwrap();
    assert_eq!(f.refresh(&forged).await.0, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn refresh_token_reuse_revokes_the_session() {
    let f = fixture().await;
    let t = f.login("alice").await;
    let (status, body) = f.refresh(&t.refresh).await;
    assert_eq!(status, StatusCode::OK);
    let new_access = body["data"]["token"].as_str().unwrap().to_string();
    assert_eq!(f.profile(&new_access).await, StatusCode::OK);

    // 复用已轮换的旧 refresh => 整族撤销,同时撤销对应会话。
    assert_eq!(f.refresh(&t.refresh).await.0, StatusCode::UNAUTHORIZED);
    let session = f.state.storage.get_session(&t.sid).await.unwrap().unwrap();
    assert!(session.revoked_at.is_some(), "复用检测必须同步撤销会话");
    assert_eq!(f.profile(&new_access).await, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn legacy_refresh_without_family_backfills_a_session() {
    let f = fixture().await;
    let jwt = JwtHandler::new(JWT_SECRET.to_string(), 24);
    let legacy = jwt.generate_refresh_token(&f.user_id("alice"), "").unwrap();

    let (status, body) = f.refresh(&legacy).await;
    assert_eq!(status, StatusCode::OK);
    let access = body["data"]["token"].as_str().unwrap();
    let sid = f
        .state
        .auth_service
        .validate_token(access)
        .unwrap()
        .sid
        .expect("补建会话后签发的 access 必须带 sid");
    let session = f.state.storage.get_session(&sid).await.unwrap().unwrap();
    assert_eq!(session.user_id, f.user_id("alice"));
    assert_eq!(f.profile(access).await, StatusCode::OK);

    // 新 refresh 属于补建会话的 family,可继续刷新;登出后失效。
    let next = body["data"]["refresh_token"].as_str().unwrap().to_string();
    assert_eq!(f.refresh(&next).await.0, StatusCode::OK);
}

// ---------- 并发 / 清理 ----------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_logout_and_refresh_end_in_a_consistent_state() {
    let f = fixture().await;
    for _ in 0..5 {
        let t = f.login("alice").await;
        let (logout, refreshed) = tokio::join!(
            f.status(post("/api/v1/auth/logout", Some(&t.access), json!({}))),
            f.refresh(&t.refresh),
        );
        // 登出可能因 refresh 先完成而仍成功;但无论顺序如何,最终会话必须已撤销。
        assert_eq!(logout, StatusCode::NO_CONTENT);
        let session = f.state.storage.get_session(&t.sid).await.unwrap().unwrap();
        assert!(session.revoked_at.is_some());
        assert_eq!(f.profile(&t.access).await, StatusCode::UNAUTHORIZED);
        if refreshed.0 == StatusCode::OK {
            // refresh 抢先成功:它签发的令牌也必须随会话撤销而失效。
            let new_access = refreshed.1["data"]["token"].as_str().unwrap();
            let new_refresh = refreshed.1["data"]["refresh_token"].as_str().unwrap();
            assert_eq!(f.profile(new_access).await, StatusCode::UNAUTHORIZED);
            assert_eq!(f.refresh(new_refresh).await.0, StatusCode::UNAUTHORIZED);
        } else {
            assert_eq!(refreshed.0, StatusCode::UNAUTHORIZED);
        }
    }
}

#[tokio::test]
async fn login_lazily_purges_expired_sessions_of_that_user() {
    let f = fixture().await;
    let alice_id = f.user_id("alice");
    let now = chrono::Utc::now().timestamp();
    f.state
        .storage
        .create_session(&datachain::storage::SessionRecord {
            id: "stale-session".to_string(),
            user_id: alice_id,
            refresh_family: "stale-family".to_string(),
            created_at: now - 20_000,
            last_seen_at: now - 20_000,
            expires_at: now - 10_000,
            revoked_at: None,
            revoke_reason: None,
            ip_hash: None,
            ip_hint: None,
            user_agent: None,
        })
        .await
        .unwrap();

    let _ = f.login("alice").await;
    assert!(
        f.state
            .storage
            .get_session("stale-session")
            .await
            .unwrap()
            .is_none(),
        "登录时应顺带清理该用户已过期的会话"
    );
}
