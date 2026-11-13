//! C6(B3):改密 API `POST /api/v1/auth/password` 的行为测试。
//!
//! 本文件在实现前应为 Red:路由不存在(404/405)、`password_changed` 等审计事件与
//! 独立的 `pwchg:<user_id>` 限速门均未实现。
//!
//! 公开 seam:HTTP router oneshot(登录、改密、profile、refresh)+ `Storage::list_audit_events`。
//! bcrypt 慢,限速用例统一用小阈值(`login_user_max_attempts = 2`)。

mod common;

use std::sync::Arc;

use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use axum::Router;
use common::*;
use datachain::api::{self, AppState};
use datachain::auth::{AuthService, AuthSettings, JwtHandler, LoginLimits, Role};
use datachain::storage::AuditEvent;
use serde_json::{json, Value};
use tower::ServiceExt;

const OLD: &str = "alicepass123";
const NEW: &str = "brand-new-pass-456";

struct Fixture {
    router: Router,
    state: AppState,
    dsn: String,
    _dir: tempfile::TempDir,
}

struct Tokens {
    access: String,
    refresh: String,
}

struct Resp {
    status: StatusCode,
    retry_after: Option<String>,
    body: Value,
}

fn small_limits() -> AuthSettings {
    AuthSettings {
        login_limits: LoginLimits {
            user_max_attempts: 2,
            ip_max_attempts: 1000,
            window_secs: 900,
        },
        ..AuthSettings::default()
    }
}

async fn fixture() -> Fixture {
    fixture_with(None).await
}

async fn fixture_with(settings: Option<AuthSettings>) -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let dsn = dir.path().join("pw.db").to_str().unwrap().to_string();
    let (mut state, storage) = build_state(&dsn).await;
    if let Some(s) = settings {
        state.auth_service = Arc::new(AuthService::with_settings(
            JWT_SECRET.to_string(),
            storage.clone(),
            s,
        ));
    }
    seed_user(&state, "alice", OLD, Role::User).await;
    seed_user(&state, "bob", "bobpass123456", Role::User).await;
    let router = api::create_router(state.clone());
    Fixture {
        router,
        state,
        dsn,
        _dir: dir,
    }
}

async fn send(router: &Router, req: Request<Body>) -> Resp {
    let resp = router.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let retry_after = resp
        .headers()
        .get(header::RETRY_AFTER)
        .map(|v| v.to_str().unwrap().to_string());
    Resp {
        status,
        retry_after,
        body: body_json(resp).await,
    }
}

impl Fixture {
    async fn login_raw(&self, user: &str, pw: &str) -> Resp {
        send(
            &self.router,
            post(
                "/api/v1/auth/login",
                None,
                json!({"username": user, "password": pw}),
            ),
        )
        .await
    }

    async fn login(&self, user: &str, pw: &str) -> Tokens {
        let r = self.login_raw(user, pw).await;
        assert_eq!(r.status, StatusCode::OK, "登录应成功: {}", user);
        Tokens {
            access: r.body["data"]["token"].as_str().unwrap().to_string(),
            refresh: r.body["data"]["refresh_token"]
                .as_str()
                .unwrap()
                .to_string(),
        }
    }

    async fn change(&self, token: Option<&str>, old: &str, new: &str) -> Resp {
        send(
            &self.router,
            post(
                "/api/v1/auth/password",
                token,
                json!({"old_password": old, "new_password": new}),
            ),
        )
        .await
    }

    async fn profile(&self, token: &str) -> StatusCode {
        send(&self.router, get("/api/v1/auth/profile", Some(token)))
            .await
            .status
    }

    async fn refresh(&self, token: &str) -> StatusCode {
        send(
            &self.router,
            post(
                "/api/v1/auth/refresh",
                None,
                json!({"refresh_token": token}),
            ),
        )
        .await
        .status
    }

    async fn events_of(&self, event_type: &str) -> Vec<AuditEvent> {
        self.state
            .storage
            .list_audit_events(1000)
            .await
            .unwrap()
            .into_iter()
            .filter(|e| e.event_type == event_type)
            .collect()
    }

    fn alice_id(&self) -> String {
        self.state.auth_service.get_user("alice").unwrap().user_id
    }
}

// ---------- 成功路径 ----------

#[tokio::test]
async fn change_password_keeps_current_session_and_revokes_other_sessions() {
    let f = fixture().await;
    let a = f.login("alice", OLD).await;
    let b = f.login("alice", OLD).await;
    assert_eq!(f.profile(&a.access).await, StatusCode::OK);
    assert_eq!(f.profile(&b.access).await, StatusCode::OK);

    let r = f.change(Some(&a.access), OLD, NEW).await;
    assert_eq!(r.status, StatusCode::NO_CONTENT);

    // 当前会话 A 的 access / refresh 仍可用。
    assert_eq!(f.profile(&a.access).await, StatusCode::OK);
    assert_eq!(f.refresh(&a.refresh).await, StatusCode::OK);
    // 其他会话 B 的 access 与 refresh 均失效。
    assert_eq!(f.profile(&b.access).await, StatusCode::UNAUTHORIZED);
    assert_eq!(f.refresh(&b.refresh).await, StatusCode::UNAUTHORIZED);

    // 旧密码登录 401,新密码登录 200。
    assert_eq!(
        f.login_raw("alice", OLD).await.status,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(f.login_raw("alice", NEW).await.status, StatusCode::OK);
}

#[tokio::test]
async fn change_password_writes_password_changed_audit_with_revoked_count() {
    let f = fixture().await;
    let a = f.login("alice", OLD).await;
    let _b = f.login("alice", OLD).await;

    assert_eq!(
        f.change(Some(&a.access), OLD, NEW).await.status,
        StatusCode::NO_CONTENT
    );

    let rows = f.events_of("password_changed").await;
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].result, "success");
    assert_eq!(rows[0].reason.as_deref(), Some("revoked 1 other sessions"));
    assert_eq!(rows[0].user_id.as_deref(), Some(f.alice_id().as_str()));

    // 审计原因不得包含密码明文。
    let reason = rows[0].reason.clone().unwrap_or_default();
    assert!(!reason.contains(OLD) && !reason.contains(NEW));
}

#[tokio::test]
async fn new_password_persists_across_state_rebuild_with_same_dsn() {
    let f = fixture().await;
    let a = f.login("alice", OLD).await;
    assert_eq!(
        f.change(Some(&a.access), OLD, NEW).await.status,
        StatusCode::NO_CONTENT
    );

    // 同 dsn 重建 state/service(模拟重启),用户与哈希从库中重新加载。
    let (state2, _) = build_state(&f.dsn).await;
    let router2 = api::create_router(state2);
    let ok = send(
        &router2,
        post(
            "/api/v1/auth/login",
            None,
            json!({"username": "alice", "password": NEW}),
        ),
    )
    .await;
    assert_eq!(ok.status, StatusCode::OK, "重启后新密码应可登录");
    let bad = send(
        &router2,
        post(
            "/api/v1/auth/login",
            None,
            json!({"username": "alice", "password": OLD}),
        ),
    )
    .await;
    assert_eq!(bad.status, StatusCode::UNAUTHORIZED, "重启后旧密码应失效");
}

#[tokio::test]
async fn login_after_change_does_not_write_back_stale_hash() {
    // 回归:login 成功路径不得再整条覆盖内存用户(会把旧哈希写回)。
    let f = fixture().await;
    let a = f.login("alice", OLD).await;
    assert_eq!(
        f.change(Some(&a.access), OLD, NEW).await.status,
        StatusCode::NO_CONTENT
    );
    // 连续用新密码登录两次(每次成功登录会更新 last_login),旧密码始终无效。
    assert_eq!(f.login_raw("alice", NEW).await.status, StatusCode::OK);
    assert_eq!(f.login_raw("alice", NEW).await.status, StatusCode::OK);
    assert_eq!(
        f.login_raw("alice", OLD).await.status,
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn change_password_does_not_affect_other_users_sessions() {
    let f = fixture().await;
    let a = f.login("alice", OLD).await;
    let bob = f.login("bob", "bobpass123456").await;
    assert_eq!(
        f.change(Some(&a.access), OLD, NEW).await.status,
        StatusCode::NO_CONTENT
    );
    assert_eq!(f.profile(&bob.access).await, StatusCode::OK);
}

#[tokio::test]
async fn legacy_access_token_without_sid_revokes_all_sessions_on_change() {
    let f = fixture().await;
    let a = f.login("alice", OLD).await;
    let b = f.login("alice", OLD).await;
    let legacy = JwtHandler::new(JWT_SECRET.to_string(), 24)
        .generate_access_token(&f.alice_id(), "alice", Role::User, None)
        .unwrap();
    assert_eq!(f.profile(&legacy).await, StatusCode::OK);

    let r = f.change(Some(&legacy), OLD, NEW).await;
    assert_eq!(r.status, StatusCode::NO_CONTENT);

    // 无 sid 无法确定"当前会话",已知限制:撤销全部会话。
    assert_eq!(f.profile(&a.access).await, StatusCode::UNAUTHORIZED);
    assert_eq!(f.profile(&b.access).await, StatusCode::UNAUTHORIZED);
    assert_eq!(f.refresh(&a.refresh).await, StatusCode::UNAUTHORIZED);
    assert_eq!(f.login_raw("alice", NEW).await.status, StatusCode::OK);

    let rows = f.events_of("password_changed").await;
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].reason.as_deref(), Some("revoked 2 other sessions"));
}

// ---------- 旧密码错 / 限速 ----------

#[tokio::test]
async fn wrong_old_password_is_401_with_no_change_and_audited() {
    let f = fixture().await;
    let a = f.login("alice", OLD).await;
    let b = f.login("alice", OLD).await;

    let r = f.change(Some(&a.access), "not-the-old-pass", NEW).await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED);
    assert_eq!(r.body["error"], "invalid credentials");

    // 密码未变,会话未动。
    assert_eq!(f.login_raw("alice", OLD).await.status, StatusCode::OK);
    assert_eq!(
        f.login_raw("alice", NEW).await.status,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(f.profile(&b.access).await, StatusCode::OK);

    let rows = f.events_of("password_change_failure").await;
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].result, "failure");
    assert_eq!(rows[0].reason.as_deref(), Some("bad old password"));
    assert_eq!(rows[0].user_id.as_deref(), Some(f.alice_id().as_str()));
    assert!(f.events_of("password_changed").await.is_empty());
}

#[tokio::test]
async fn repeated_bad_old_password_locks_change_with_429_and_login_is_unaffected() {
    let f = fixture_with(Some(small_limits())).await;
    let a = f.login("alice", OLD).await;

    assert_eq!(
        f.change(Some(&a.access), "bad-old-pass-1", NEW)
            .await
            .status,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        f.change(Some(&a.access), "bad-old-pass-2", NEW)
            .await
            .status,
        StatusCode::UNAUTHORIZED
    );
    let locked = f.change(Some(&a.access), "bad-old-pass-3", NEW).await;
    assert_eq!(locked.status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(locked.body["error"], "too many attempts");
    let retry: u64 = locked
        .retry_after
        .expect("429 必须带 Retry-After")
        .parse()
        .unwrap();
    assert!((1..=900).contains(&retry), "Retry-After={}", retry);

    // 锁内即使旧密码正确也 429,且密码未变。
    let r = f.change(Some(&a.access), OLD, NEW).await;
    assert_eq!(r.status, StatusCode::TOO_MANY_REQUESTS);
    assert!(r.retry_after.is_some());
    assert!(!f.events_of("password_change_locked").await.is_empty());
    assert!(f.events_of("password_changed").await.is_empty());

    // 该用户正常登录不受改密锁影响(旧密码仍有效),也不是 429。
    let login = f.login_raw("alice", OLD).await;
    assert_eq!(login.status, StatusCode::OK, "改密锁不得影响登录");
    assert_eq!(
        f.login_raw("alice", NEW).await.status,
        StatusCode::UNAUTHORIZED
    );

    // 审计:两次失败 + 至少两次 locked(触发锁的那次与锁内那次)。
    assert_eq!(f.events_of("password_change_failure").await.len(), 2);
    assert!(f.events_of("password_change_locked").await.len() >= 2);
}

// ---------- new == old ----------

#[tokio::test]
async fn new_equal_to_old_is_400() {
    let f = fixture().await;
    let a = f.login("alice", OLD).await;
    let r = f.change(Some(&a.access), OLD, OLD).await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST);
    assert_eq!(
        r.body["error"],
        "new password must differ from old password"
    );
    // 密码未变。
    assert_eq!(f.login_raw("alice", OLD).await.status, StatusCode::OK);
}

#[tokio::test]
async fn wrong_old_password_with_same_new_password_is_401_not_400() {
    // 检查顺序:旧密码通过后才比较新旧相同,避免探测。
    let f = fixture().await;
    let a = f.login("alice", OLD).await;
    let r = f
        .change(Some(&a.access), "wrong-old-pass-1", "wrong-old-pass-1")
        .await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED);
    assert_eq!(r.body["error"], "invalid credentials");
}

// ---------- 密码策略 ----------

#[tokio::test]
async fn too_short_new_password_is_400() {
    let f = fixture().await;
    let a = f.login("alice", OLD).await;
    let r = f.change(Some(&a.access), OLD, "short1").await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST);
    assert_eq!(r.body["error"], "password too short");
}

#[tokio::test]
async fn too_long_new_password_over_72_bytes_is_400() {
    let f = fixture().await;
    let a = f.login("alice", OLD).await;
    let ok_72 = "a".repeat(72);
    let too_long = "a".repeat(73);
    let r = f.change(Some(&a.access), OLD, &too_long).await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST);
    assert_eq!(r.body["error"], "password too long");
    // 恰 72 字节合法。
    assert_eq!(
        f.change(Some(&a.access), OLD, &ok_72).await.status,
        StatusCode::NO_CONTENT
    );
}

#[tokio::test]
async fn new_password_with_nul_is_400() {
    let f = fixture().await;
    let a = f.login("alice", OLD).await;
    let r = f.change(Some(&a.access), OLD, "valid\u{0}password1").await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST);
    assert_eq!(r.body["error"], "password contains invalid characters");
}

#[tokio::test]
async fn policy_failures_do_not_consume_quota() {
    // 阈值为 2:若策略失败也耗配额,10 次之后正确旧密码会被 429。
    let f = fixture_with(Some(small_limits())).await;
    let a = f.login("alice", OLD).await;
    for _ in 0..10 {
        let r = f.change(Some(&a.access), OLD, "short1").await;
        assert_eq!(r.status, StatusCode::BAD_REQUEST);
    }
    let r = f.change(Some(&a.access), OLD, NEW).await;
    assert_eq!(r.status, StatusCode::NO_CONTENT, "策略失败不得耗配额");
    assert!(f.events_of("password_change_failure").await.is_empty());
}

// ---------- 鉴权 / 请求体 ----------

#[tokio::test]
async fn change_password_requires_authentication() {
    let f = fixture().await;
    let r = f.change(None, OLD, NEW).await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn missing_fields_are_422() {
    let f = fixture().await;
    let a = f.login("alice", OLD).await;
    let r = send(
        &f.router,
        post(
            "/api/v1/auth/password",
            Some(&a.access),
            json!({"old_password": OLD}),
        ),
    )
    .await;
    assert_eq!(r.status, StatusCode::UNPROCESSABLE_ENTITY);
    let r = send(
        &f.router,
        post(
            "/api/v1/auth/password",
            Some(&a.access),
            json!({"new_password": NEW}),
        ),
    )
    .await;
    assert_eq!(r.status, StatusCode::UNPROCESSABLE_ENTITY);
}

// ---------- 并发 ----------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_changes_end_in_a_consistent_state() {
    let f = fixture().await;
    let a = f.login("alice", OLD).await;
    let b = f.login("alice", OLD).await;
    let new1 = "concurrent-new-pass-1";
    let new2 = "concurrent-new-pass-2";

    let (r1, r2) = tokio::join!(
        f.change(Some(&a.access), OLD, new1),
        f.change(Some(&b.access), OLD, new2),
    );
    // 后到的请求可能已看到新哈希而 401;但至少一个成功,不得出现 5xx。
    for r in [&r1, &r2] {
        assert!(
            r.status == StatusCode::NO_CONTENT || r.status == StatusCode::UNAUTHORIZED,
            "意外状态 {}",
            r.status
        );
    }
    assert!(r1.status == StatusCode::NO_CONTENT || r2.status == StatusCode::NO_CONTENT);

    // 最终恰有一个新密码可登录,旧密码不可登录。
    let ok1 = f.login_raw("alice", new1).await.status == StatusCode::OK;
    let ok2 = f.login_raw("alice", new2).await.status == StatusCode::OK;
    assert!(ok1 ^ ok2, "恰有一个新密码可登录: ok1={} ok2={}", ok1, ok2);
    assert_eq!(
        f.login_raw("alice", OLD).await.status,
        StatusCode::UNAUTHORIZED
    );
    if r1.status == StatusCode::UNAUTHORIZED {
        assert!(ok2 && !ok1);
    }
    if r2.status == StatusCode::UNAUTHORIZED {
        assert!(ok1 && !ok2);
    }
}
