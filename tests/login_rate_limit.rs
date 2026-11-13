//! S3:登录限速(账户+IP 双维度)、统一失败响应与恒定时间的行为测试。
//! 经 HTTP router oneshot(无 ConnectInfo,回退占位 IP key)与 AuthService 公开方法驱动。

mod common;

use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::http::{header, StatusCode};
use common::*;
use datachain::api;
use datachain::auth::{
    AuthService, LoginContext, LoginLimits, LoginRequest, RegisterRequest, Role,
};
use datachain::error::DataChainError;
use datachain::storage::create_storage;
use serde_json::Value;
use tower::ServiceExt;

async fn try_login(
    router: &axum::Router,
    username: &str,
    password: &str,
) -> (StatusCode, Option<String>, Value) {
    let resp = router
        .clone()
        .oneshot(post(
            "/api/v1/auth/login",
            None,
            serde_json::json!({"username": username, "password": password}),
        ))
        .await
        .unwrap();
    let status = resp.status();
    let retry_after = resp
        .headers()
        .get(header::RETRY_AFTER)
        .map(|v| v.to_str().unwrap().to_string());
    (status, retry_after, body_json(resp).await)
}

/// 固定在某个窗口起点之后 10 秒,使一个测试内的所有尝试必落在同一固定窗口。
fn pin_clock(storage: &datachain::storage::Storage) {
    let now: i64 = 1_800_000_000 - (1_800_000_000 % 900) + 10;
    storage.set_clock(Arc::new(move || now));
}

async fn router_with_alice(dir: &tempfile::TempDir) -> (axum::Router, Arc<AuthService>) {
    let dsn = dir.path().join("dc.db");
    let (state, storage) = build_state(dsn.to_str().unwrap()).await;
    pin_clock(&storage);
    seed_user(&state, "alice", "alicepass123", Role::User).await;
    seed_user(&state, "bob", "bobpass123456", Role::User).await;
    let auth = state.auth_service.clone();
    (api::create_router(state), auth)
}

#[tokio::test]
async fn sixth_failed_login_is_rate_limited_with_retry_after() {
    let dir = tempfile::tempdir().unwrap();
    let (router, _) = router_with_alice(&dir).await;

    for attempt in 1..=5 {
        let (status, retry_after, body) = try_login(&router, "alice", "wrong-password").await;
        assert_eq!(
            status,
            StatusCode::UNAUTHORIZED,
            "第 {} 次应为 401",
            attempt
        );
        assert!(retry_after.is_none());
        assert_eq!(body["error"], "invalid credentials");
    }

    let (status, retry_after, body) = try_login(&router, "alice", "wrong-password").await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS, "第 6 次应被限速");
    let secs: u64 = retry_after
        .expect("429 必须带 Retry-After")
        .parse()
        .expect("Retry-After 应为秒数");
    assert!(
        (1..=900).contains(&secs),
        "Retry-After={} 应在 1..=900",
        secs
    );
    assert_eq!(body["error"], "too many attempts");
}

#[tokio::test]
async fn locked_user_cannot_login_even_with_correct_password_but_others_can() {
    let dir = tempfile::tempdir().unwrap();
    let (router, _) = router_with_alice(&dir).await;

    for _ in 0..5 {
        try_login(&router, "alice", "wrong-password").await;
    }
    let (status, _, _) = try_login(&router, "alice", "alicepass123").await;
    assert_eq!(
        status,
        StatusCode::TOO_MANY_REQUESTS,
        "锁定期间正确密码也应 429"
    );

    let (status, _, _) = try_login(&router, "bob", "bobpass123456").await;
    assert_eq!(status, StatusCode::OK, "其他用户名不受影响");
}

#[tokio::test]
async fn successful_login_does_not_clear_accumulated_failures() {
    let dir = tempfile::tempdir().unwrap();
    let (router, _) = router_with_alice(&dir).await;

    for _ in 0..4 {
        let (status, _, _) = try_login(&router, "alice", "wrong-password").await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }
    let (status, _, _) = try_login(&router, "alice", "alicepass123").await;
    assert_eq!(status, StatusCode::OK);
    // 成功登录只归还自己的名额,不清零已累积的 4 次失败:
    // 第 5 次失败仍是 401,第 6 次尝试起被限速。
    let (status, _, _) = try_login(&router, "alice", "wrong-password").await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let (status, _, _) = try_login(&router, "alice", "wrong-password").await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
}

#[tokio::test]
async fn case_variant_account_success_cannot_reset_victim_counter() {
    let dir = tempfile::tempdir().unwrap();
    let dsn = dir.path().join("dc.db");
    let (state, storage) = build_state(dsn.to_str().unwrap()).await;
    pin_clock(&storage);
    seed_user(&state, "carol", "carolpass123", Role::User).await;
    // 攻击者注册大小写变体:限速 key 归一化后与受害者相同。
    seed_user(&state, "CAROL", "attackerpass1", Role::User).await;
    let router = api::create_router(state);

    for _ in 0..4 {
        let (status, _, _) = try_login(&router, "carol", "wrong-password").await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }
    let (status, _, _) = try_login(&router, "CAROL", "attackerpass1").await;
    assert_eq!(status, StatusCode::OK);
    // 攻击者的成功登录不得抵消对受害者累积的 4 次失败:
    // 第 5 次失败仍 401,之后必须被限速。
    let (status, _, _) = try_login(&router, "carol", "wrong-password").await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let (status, _, _) = try_login(&router, "carol", "wrong-password").await;
    assert_eq!(
        status,
        StatusCode::TOO_MANY_REQUESTS,
        "大小写变体账户的成功登录不应重置受害者用户名计数"
    );
}

#[tokio::test]
async fn unknown_user_wrong_password_and_disabled_account_look_identical() {
    let dir = tempfile::tempdir().unwrap();
    let (router, auth) = router_with_alice(&dir).await;
    let bob_id = auth.get_user("bob").unwrap().user_id;
    auth.deactivate_user(&bob_id).await.unwrap();

    let unknown = try_login(&router, "nobody", "whatever-pass").await;
    let wrong = try_login(&router, "alice", "wrong-password").await;
    let disabled = try_login(&router, "bob", "bobpass123456").await;

    for (status, retry_after, body) in [&unknown, &wrong, &disabled] {
        assert_eq!(*status, StatusCode::UNAUTHORIZED);
        assert!(retry_after.is_none());
        assert_eq!(body["error"], "invalid credentials");
    }
    assert_eq!(unknown.2, wrong.2, "响应体必须逐字节同形");
    assert_eq!(wrong.2, disabled.2, "响应体必须逐字节同形");
}

async fn service_with_limits(
    dir: &tempfile::TempDir,
    limits: LoginLimits,
) -> (AuthService, Arc<datachain::storage::Storage>) {
    let path = dir.path().join("svc.db");
    let storage = create_storage(path.to_str().unwrap()).await.unwrap();
    pin_clock(&storage);
    let service = AuthService::new("svc-test-secret".to_string(), 24, storage.clone())
        .with_login_limits(limits);
    for name in ["u1", "u2", "u3", "u4", "u5"] {
        let user = service
            .register(&RegisterRequest {
                username: name.to_string(),
                password: "password123".to_string(),
                email: format!("{}@test.local", name),
                role: None,
            })
            .unwrap();
        // 启用状态以 SQLite 为权威,用户需落库才能登录。
        storage.save_user(&user).await.unwrap();
    }
    (service, storage)
}

fn login_req(username: &str, password: &str) -> LoginRequest {
    LoginRequest {
        username: username.to_string(),
        password: password.to_string(),
    }
}

fn ctx(ip: &str) -> LoginContext {
    LoginContext {
        client_ip: Some(ip.to_string()),
        user_agent: None,
    }
}

#[tokio::test]
async fn ip_dimension_limits_attempts_across_usernames_per_ip() {
    let dir = tempfile::tempdir().unwrap();
    let (service, _) = service_with_limits(
        &dir,
        LoginLimits {
            user_max_attempts: 100,
            ip_max_attempts: 3,
            window_secs: 900,
        },
    )
    .await;

    // 同一 IP 对不同用户名连续失败 3 次仍是凭据错误。
    for name in ["u1", "u2", "u3"] {
        let err = service
            .login(&login_req(name, "bad-password"), &ctx("198.51.100.7"))
            .await
            .unwrap_err();
        assert!(
            matches!(err, DataChainError::InvalidCredentials),
            "{:?}",
            err
        );
    }
    // 第 4 次(不同用户名)被 IP 维度限速,且带正的重试秒数。
    let err = service
        .login(&login_req("u4", "bad-password"), &ctx("198.51.100.7"))
        .await
        .unwrap_err();
    match err {
        DataChainError::TooManyAttempts { retry_after_secs } => {
            assert!((1..=900).contains(&retry_after_secs))
        }
        other => panic!("期望 TooManyAttempts,实际 {:?}", other),
    }
    // 另一个 IP 不受影响。
    service
        .login(&login_req("u4", "password123"), &ctx("198.51.100.8"))
        .await
        .expect("其他 IP 应可登录");
}

#[tokio::test]
async fn lockout_survives_service_restart_because_counters_are_persisted() {
    let dir = tempfile::tempdir().unwrap();
    let limits = LoginLimits {
        user_max_attempts: 2,
        ip_max_attempts: 100,
        window_secs: 900,
    };
    let (service, storage) = service_with_limits(&dir, limits).await;
    for _ in 0..2 {
        let _ = service
            .login(&login_req("u1", "bad-password"), &ctx("198.51.100.7"))
            .await;
    }

    // 同一 Storage 上重建 AuthService(模拟进程重启),用户需重新加载。
    let restarted = AuthService::new("svc-test-secret".to_string(), 24, storage.clone())
        .with_login_limits(limits);
    for user in service.get_all_users() {
        restarted.load_user(user);
    }
    let err = restarted
        .login(&login_req("u1", "password123"), &ctx("198.51.100.7"))
        .await
        .unwrap_err();
    assert!(
        matches!(err, DataChainError::TooManyAttempts { .. }),
        "重启后仍应处于锁定: {:?}",
        err
    );
}

fn median(mut v: Vec<Duration>) -> Duration {
    v.sort();
    v[v.len() / 2]
}

#[tokio::test]
async fn unknown_user_login_costs_comparable_time_to_wrong_password() {
    let dir = tempfile::tempdir().unwrap();
    let (service, _) = service_with_limits(&dir, LoginLimits::default()).await;

    let mut wrong = Vec::new();
    let mut unknown = Vec::new();
    for i in 0..3 {
        let start = Instant::now();
        let _ = service
            .login(&login_req("u5", "bad-password"), &ctx("198.51.100.20"))
            .await;
        wrong.push(start.elapsed());

        // 每次用不同的不存在用户名,避免触发用户名维度限速。
        let start = Instant::now();
        let _ = service
            .login(
                &login_req(&format!("ghost-{}", i), "bad-password"),
                &ctx("198.51.100.21"),
            )
            .await;
        unknown.push(start.elapsed());
    }
    let wrong = median(wrong);
    let unknown = median(unknown);
    // 宽松断言:不存在的用户不得走"免哈希快速路径"。
    assert!(
        unknown * 2 >= wrong,
        "unknown={:?} 明显快于 wrong={:?},存在用户枚举时序侧信道",
        unknown,
        wrong
    );
}

/// 可控时钟:返回共享原子值,测试按需拨动。
fn fixed_clock(now: Arc<std::sync::atomic::AtomicI64>) -> Arc<dyn Fn() -> i64 + Send + Sync> {
    Arc::new(move || now.load(std::sync::atomic::Ordering::SeqCst))
}

/// 窗口跨越(固定窗口按 epoch 对齐):窗口末尾失败 5 次后,进入新窗口计数从 0 重新开始;
/// 同一窗口内第 6 次必须 429。时间完全由注入时钟控制,不依赖墙钟。
#[tokio::test]
async fn failed_attempts_reset_when_clock_crosses_window_boundary() {
    use std::sync::atomic::{AtomicI64, Ordering};

    let dir = tempfile::tempdir().unwrap();
    let (service, storage) = service_with_limits(&dir, LoginLimits::default()).await;
    // 任意 epoch 对齐的窗口起点(900 的整数倍)。
    let window_start: i64 = 1_800_000_000 - (1_800_000_000 % 900);
    let now = Arc::new(AtomicI64::new(window_start + 895));
    storage.set_clock(fixed_clock(now.clone()));

    // 窗口末尾(距边界 5 秒)连续失败 5 次,均为 401。
    for attempt in 1..=5 {
        let err = service
            .login(&login_req("u1", "bad-password"), &ctx("198.51.100.30"))
            .await
            .unwrap_err();
        assert!(
            matches!(err, DataChainError::InvalidCredentials),
            "第 {} 次应为 InvalidCredentials: {:?}",
            attempt,
            err
        );
    }
    // 同一窗口内第 6 次被限速,Retry-After 恰为到窗口末尾的剩余秒数。
    match service
        .login(&login_req("u1", "bad-password"), &ctx("198.51.100.30"))
        .await
        .unwrap_err()
    {
        DataChainError::TooManyAttempts { retry_after_secs } => {
            assert_eq!(retry_after_secs, 5)
        }
        other => panic!("期望 TooManyAttempts,实际 {:?}", other),
    }

    // 时钟越过边界进入新窗口:计数从 0 开始,同一用户可再次尝试 5 次且为 401。
    now.store(window_start + 901, Ordering::SeqCst);
    for attempt in 1..=5 {
        let err = service
            .login(&login_req("u1", "bad-password"), &ctx("198.51.100.30"))
            .await
            .unwrap_err();
        assert!(
            matches!(err, DataChainError::InvalidCredentials),
            "新窗口第 {} 次应为 InvalidCredentials: {:?}",
            attempt,
            err
        );
    }
    // 新窗口内第 6 次再次被限速,剩余秒数 = 900 - 1。
    match service
        .login(&login_req("u1", "bad-password"), &ctx("198.51.100.30"))
        .await
        .unwrap_err()
    {
        DataChainError::TooManyAttempts { retry_after_secs } => {
            assert_eq!(retry_after_secs, 899)
        }
        other => panic!("期望 TooManyAttempts,实际 {:?}", other),
    }
}
