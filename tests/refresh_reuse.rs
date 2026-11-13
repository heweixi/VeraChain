//! A7:refresh token 复用 / 并发双花分支的行为测试。
//!
//! 经 HTTP router oneshot 驱动(公开 seam),用 Storage 公开读方法核对会话状态。
//! 复用与撤销原因的区分通过响应体里的错误文本体现:
//! `TokenReuseDetected` 与 `InvalidToken` 的 Display 文本不同。
//!
//! 未覆盖的精确分支:`touch_session` 返回 false 且会话撤销原因以 `refresh token` 开头。
//! 该分支需要"jti 抢占成功之后、touch_session 之前,另一请求恰好整族撤销该会话",
//! 经公开入口无法确定性构造(只能靠并发时序偶发命中),因此这里只断言它的可达后果:
//! 并发双花时至多一个请求成功,其余必为 401(复用文本),且整族最终失效。
mod common;

use axum::http::StatusCode;
use common::*;
use datachain::api::{self, AppState};
use datachain::auth::Role;
use datachain::error::DataChainError;
use serde_json::{json, Value};
use tower::ServiceExt;

struct Fixture {
    router: axum::Router,
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
    let router = api::create_router(state.clone());
    Fixture {
        router,
        state,
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

    async fn profile_status(&self, access: &str) -> StatusCode {
        self.router
            .clone()
            .oneshot(get("/api/v1/auth/profile", Some(access)))
            .await
            .unwrap()
            .status()
    }
}

fn reuse_message() -> String {
    DataChainError::TokenReuseDetected.to_string()
}

fn assert_reuse_rejection(status: StatusCode, body: &Value) {
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body["success"], false);
    assert_eq!(
        body["error"].as_str().unwrap(),
        reuse_message(),
        "应判定为 TokenReuseDetected: {}",
        body
    );
}

#[tokio::test]
async fn reusing_a_rotated_refresh_token_is_reported_as_reuse_and_revokes_the_family() {
    let f = fixture().await;
    let t = f.login().await;

    let (status, body) = f.refresh(&t.refresh).await;
    assert_eq!(status, StatusCode::OK);
    let new_access = body["data"]["token"].as_str().unwrap().to_string();
    let new_refresh = body["data"]["refresh_token"].as_str().unwrap().to_string();
    assert_ne!(new_refresh, t.refresh);
    assert_eq!(f.profile_status(&new_access).await, StatusCode::OK);

    // 复用已被轮换的旧 refresh => 401 且明确是"复用"(不是普通无效令牌)。
    let (status, body) = f.refresh(&t.refresh).await;
    assert_reuse_rejection(status, &body);
    assert_ne!(
        body["error"].as_str().unwrap(),
        DataChainError::InvalidToken.to_string()
    );

    // 整族撤销:会话已撤销,原因标明 refresh token 复用。
    let session = f.state.storage.get_session(&t.sid).await.unwrap().unwrap();
    assert!(session.revoked_at.is_some(), "复用检测必须撤销该族会话");
    assert!(
        session
            .revoke_reason
            .as_deref()
            .is_some_and(|r| r.starts_with("refresh token")),
        "撤销原因应为 refresh token 复用: {:?}",
        session.revoke_reason
    );

    // 此前合法的新 refresh 与新 access 都随整族撤销失效。
    let (status, body) = f.refresh(&new_refresh).await;
    assert_reuse_rejection(status, &body);
    assert_eq!(
        f.profile_status(&new_access).await,
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn refresh_after_logout_is_plain_invalid_token_not_reuse() {
    let f = fixture().await;
    let t = f.login().await;

    let resp = f
        .router
        .clone()
        .oneshot(post("/api/v1/auth/logout", Some(&t.access), json!({})))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);

    // 因登出而被撤销的族不是复用攻击:返回普通 InvalidToken,且不改写撤销原因。
    let (status, body) = f.refresh(&t.refresh).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(
        body["error"].as_str().unwrap(),
        DataChainError::InvalidToken.to_string()
    );
    let session = f.state.storage.get_session(&t.sid).await.unwrap().unwrap();
    assert_eq!(session.revoke_reason.as_deref(), Some("logout"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_refresh_with_same_token_never_yields_two_successes() {
    let f = fixture().await;
    let t = f.login().await;

    let (a, b) = tokio::join!(f.refresh(&t.refresh), f.refresh(&t.refresh));

    let results = [a, b];
    let winners: Vec<&(StatusCode, Value)> = results
        .iter()
        .filter(|(status, _)| *status == StatusCode::OK)
        .collect();
    // 一个旧 token 绝不能兑换出两对新令牌。
    assert!(winners.len() <= 1, "并发双花最多一个成功: {:?}", results);
    // 失败方必为 401 且判定为复用/双花。
    for (status, body) in results.iter().filter(|(s, _)| *s != StatusCode::OK) {
        assert_reuse_rejection(*status, body);
    }
    assert!(
        results.iter().any(|(s, _)| *s != StatusCode::OK),
        "至少有一个请求必须被拒绝"
    );

    // 抢占失败方触发整族撤销:会话已撤销,胜出方(若有)的新令牌也失效。
    let session = f.state.storage.get_session(&t.sid).await.unwrap().unwrap();
    assert!(session.revoked_at.is_some(), "双花必须整族撤销会话");
    if let Some((_, body)) = winners.first() {
        let new_access = body["data"]["token"].as_str().unwrap();
        let new_refresh = body["data"]["refresh_token"].as_str().unwrap();
        assert_eq!(f.profile_status(new_access).await, StatusCode::UNAUTHORIZED);
        let (status, body) = f.refresh(new_refresh).await;
        assert_reuse_rejection(status, &body);
    }
}
