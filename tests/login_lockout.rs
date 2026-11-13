//! C4(B5):用户名维度指数退避锁定(login_lockouts)的行为测试。
//!
//! 本文件在实现前应为 Red:
//! - 现有实现按固定窗口限速,首锁 Retry-After 是"窗口剩余秒数"而非 `lockout.base_secs`;
//! - 不存在 `login_lockouts` 表(迁移 012),审计 reason 也不是 `account locked`。
//!
//! 时间完全由注入时钟(`Storage::set_clock`)控制;bcrypt 慢,统一用小阈值
//! (`login_user_max_attempts = 2`)。限速窗口取 86400 秒且起点对齐,使一个测试内的
//! 所有操作落在同一固定窗口,从而能区分"锁定到期后清空窗口计数"与"自然换窗口"。

mod common;

use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::http::{header, StatusCode};
use common::*;
use datachain::api;
use datachain::auth::{
    AuthService, AuthSettings, LockoutPolicy, LoginContext, LoginLimits, LoginRequest,
    RegisterRequest, Role,
};
use datachain::error::DataChainError;
use datachain::storage::{create_storage, AuditEvent, Storage};
use tower::ServiceExt;

/// 86400 的整数倍(= 20833 * 86400),即 86400 秒固定窗口的起点。
const T0: i64 = 1_799_971_200;
const SECRET: &str = "lockout-test-secret-0123456789-abcdef";
const IP: &str = "198.51.100.7";
const GOOD: &str = "password123";

const POLICY: LockoutPolicy = LockoutPolicy {
    base_secs: 900,
    max_secs: 3600,
    reset_secs: 86_400,
};

fn settings(user_max: i64, ip_max: i64) -> AuthSettings {
    AuthSettings {
        login_limits: LoginLimits {
            user_max_attempts: user_max,
            ip_max_attempts: ip_max,
            window_secs: 86_400,
        },
        lockout: POLICY,
        ..AuthSettings::default()
    }
}

struct Fixture {
    service: AuthService,
    storage: Arc<Storage>,
    clock: Arc<AtomicI64>,
    dsn: String,
    _dir: tempfile::TempDir,
}

fn attach_clock(storage: &Storage, start: i64) -> Arc<AtomicI64> {
    let clock = Arc::new(AtomicI64::new(start));
    let c = clock.clone();
    storage.set_clock(Arc::new(move || c.load(Ordering::SeqCst)));
    clock
}

async fn register(service: &AuthService, storage: &Storage, name: &str) {
    let user = service
        .register(&RegisterRequest {
            username: name.to_string(),
            password: GOOD.to_string(),
            email: format!("{}@test.local", name),
            role: None,
        })
        .unwrap();
    storage.save_user(&user).await.unwrap();
}

/// 建库、注入时钟(T0+10)、用 user_max=2 / ip_max=1000 的设置注册 `names` 中的用户。
async fn fixture(names: &[&str]) -> Fixture {
    fixture_with(names, settings(2, 1000)).await
}

async fn fixture_with(names: &[&str], s: AuthSettings) -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let dsn = dir.path().join("lockout.db").to_str().unwrap().to_string();
    let storage = create_storage(&dsn).await.unwrap();
    let clock = attach_clock(&storage, T0 + 10);
    let service = AuthService::with_settings(SECRET.to_string(), storage.clone(), s);
    for name in names {
        register(&service, &storage, name).await;
    }
    Fixture {
        service,
        storage,
        clock,
        dsn,
        _dir: dir,
    }
}

fn req(username: &str, password: &str) -> LoginRequest {
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

impl Fixture {
    fn set_now(&self, t: i64) {
        self.clock.store(t, Ordering::SeqCst);
    }

    fn now(&self) -> i64 {
        self.clock.load(Ordering::SeqCst)
    }

    async fn attempt(&self, user: &str, pw: &str) -> DataChainError {
        self.service
            .login(&req(user, pw), &ctx(IP))
            .await
            .expect_err("期望登录失败")
    }

    async fn expect_bad_credentials(&self, user: &str) {
        let err = self.attempt(user, "bad-password").await;
        assert!(
            matches!(err, DataChainError::InvalidCredentials),
            "期望 InvalidCredentials,实际 {:?}",
            err
        );
    }

    /// 取得"本次是否被拒"为 TooManyAttempts 的 Retry-After,否则 panic。
    async fn expect_locked(&self, user: &str, pw: &str) -> u64 {
        match self.attempt(user, pw).await {
            DataChainError::TooManyAttempts { retry_after_secs } => retry_after_secs,
            other => panic!("期望 TooManyAttempts,实际 {:?}", other),
        }
    }

    /// 连续失败 user_max(=2) 次均为 401,第 3 次触发锁定,返回其 Retry-After。
    async fn trip(&self, user: &str) -> u64 {
        self.expect_bad_credentials(user).await;
        self.expect_bad_credentials(user).await;
        self.expect_locked(user, "bad-password").await
    }

    async fn audit(&self) -> Vec<AuditEvent> {
        self.storage.list_audit_events(1000).await.unwrap()
    }

    async fn lockout_rows(&self) -> i64 {
        let pool = common::corrupt::connect(&self.dsn).await;
        let (n,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM login_lockouts")
            .fetch_one(&pool)
            .await
            .unwrap();
        pool.close().await;
        n
    }
}

#[tokio::test]
async fn first_lock_retry_after_is_base_and_correct_password_is_rejected_while_locked() {
    let f = fixture(&["alice", "bob"]).await;
    let retry = f.trip("alice").await;
    assert_eq!(retry, 900, "首锁 Retry-After 应为 lockout.base_secs");

    // 锁内正确密码也被拒。
    let retry = f.expect_locked("alice", GOOD).await;
    assert_eq!(retry, 900);

    // 其他用户名不受影响。
    f.service
        .login(&req("bob", GOOD), &ctx(IP))
        .await
        .expect("其他用户名不应被锁");
}

#[tokio::test]
async fn retry_after_decreases_with_clock_and_lock_expires_exactly_at_locked_until() {
    let f = fixture(&["alice"]).await;
    assert_eq!(f.trip("alice").await, 900); // locked_until = T0+910

    f.set_now(T0 + 310);
    assert_eq!(f.expect_locked("alice", GOOD).await, 600);
    f.set_now(T0 + 909);
    assert_eq!(f.expect_locked("alice", GOOD).await, 1, "至少为 1 秒");

    // 到期后(now >= locked_until)正确密码可登录。
    f.set_now(T0 + 911);
    f.service
        .login(&req("alice", GOOD), &ctx(IP))
        .await
        .expect("锁到期后应可登录");
}

#[tokio::test]
async fn lock_levels_double_up_to_cap_and_each_expiry_grants_full_quota() {
    let f = fixture(&["alice"]).await;

    assert_eq!(f.trip("alice").await, 900); // locked_until = T0+910
    f.set_now(T0 + 911);
    // 锁到期后拥有完整配额:两次失败仍为 401(窗口同一个,说明旧计数已被清除),第 3 次再锁。
    assert_eq!(f.trip("alice").await, 1800, "第二次锁 2*base");
    f.set_now(T0 + 911 + 1801);
    assert_eq!(f.trip("alice").await, 3600, "第三次锁 4*base 恰为 max");
    f.set_now(T0 + 911 + 1801 + 3601);
    assert_eq!(f.trip("alice").await, 3600, "第四次封顶 lockout.max_secs");
}

#[tokio::test]
async fn level_resets_to_base_after_silence_longer_than_reset_secs() {
    let f = fixture(&["alice"]).await;
    assert_eq!(f.trip("alice").await, 900); // locked_until = T0+910
    f.set_now(T0 + 911);
    assert_eq!(f.trip("alice").await, 1800); // locked_until = T0+911+1800 = T0+2711

    // 距上次锁定结束静默满 reset_secs 之后再锁:回到 base。
    f.set_now(T0 + 2711 + 86_400);
    assert_eq!(f.trip("alice").await, 900);
}

#[tokio::test]
async fn successful_login_does_not_downgrade_lock_level() {
    let f = fixture(&["alice"]).await;
    assert_eq!(f.trip("alice").await, 900);
    f.set_now(T0 + 911);
    f.service
        .login(&req("alice", GOOD), &ctx(IP))
        .await
        .expect("锁到期后成功登录");
    // 成功登录不降级:再次触发锁定仍是第 2 级。
    assert_eq!(f.trip("alice").await, 1800);
}

#[tokio::test]
async fn unknown_user_gets_the_same_lock_sequence_as_existing_user() {
    let f = fixture(&["alice"]).await;
    // 同一序列:900 → (到期) → 1800;存在与不存在的用户名完全同形。
    assert_eq!(f.trip("alice").await, 900);
    assert_eq!(f.trip("ghost").await, 900);
    assert_eq!(f.expect_locked("alice", "bad-password").await, 900);
    assert_eq!(f.expect_locked("ghost", "bad-password").await, 900);

    f.set_now(T0 + 911);
    assert_eq!(f.trip("alice").await, 1800);
    assert_eq!(f.trip("ghost").await, 1800);
}

/// 锁内不跑 bcrypt:被锁请求只做一次 DB 读,耗时应远小于一次需要 bcrypt 的失败登录。
/// 该断言依赖时序(宽松 2 倍);若在极低 bcrypt cost 的环境下不稳定,
/// 退化为只依赖上面的"响应同形"断言。
#[tokio::test]
async fn locked_requests_skip_bcrypt_for_existing_and_unknown_users() {
    let f = fixture(&["alice"]).await;

    // 基准:一次会触发 bcrypt 的失败登录(取两个用户各一次的较小值)。
    let start = Instant::now();
    f.expect_bad_credentials("alice").await;
    let t_known = start.elapsed();
    let start = Instant::now();
    f.expect_bad_credentials("ghost").await;
    let t_unknown = start.elapsed();
    let bcrypt_call = t_known.min(t_unknown);

    // 补满配额并锁定。
    f.expect_bad_credentials("alice").await;
    f.expect_locked("alice", "bad-password").await;
    f.expect_bad_credentials("ghost").await;
    f.expect_locked("ghost", "bad-password").await;

    for user in ["alice", "ghost"] {
        let mut best = Duration::MAX;
        for _ in 0..3 {
            let start = Instant::now();
            f.expect_locked(user, GOOD).await;
            best = best.min(start.elapsed());
        }
        assert!(
            best * 2 < bcrypt_call,
            "{} 锁内耗时 {:?} 应远小于 bcrypt 失败登录 {:?}(锁内不应跑 bcrypt)",
            user,
            best,
            bcrypt_call
        );
    }
}

#[tokio::test]
async fn lock_survives_restart_with_same_dsn() {
    let f = fixture(&["alice"]).await;
    assert_eq!(f.trip("alice").await, 900);
    f.set_now(T0 + 100);

    // 同一 dsn 全新建 Storage + AuthService(模拟进程重启),用户从库中重新加载。
    let storage2 = create_storage(&f.dsn).await.unwrap();
    let _clock2 = attach_clock(&storage2, T0 + 100);
    let service2 =
        AuthService::with_settings(SECRET.to_string(), storage2.clone(), settings(2, 1000));
    for user in storage2.get_all_users().await.unwrap() {
        service2.load_user(user);
    }
    match service2
        .login(&req("alice", GOOD), &ctx(IP))
        .await
        .expect_err("重启后仍应锁定")
    {
        DataChainError::TooManyAttempts { retry_after_secs } => {
            assert_eq!(
                retry_after_secs, 810,
                "剩余 locked_until(T0+910) - now(T0+100)"
            )
        }
        other => panic!("期望 TooManyAttempts,实际 {:?}", other),
    }
}

#[tokio::test]
async fn ip_dimension_stays_fixed_window_and_never_writes_lockout_rows() {
    // 用户名阈值很大,仅 IP 阈值(2)会触发;用不同用户名避免触发用户名维度。
    let f = fixture_with(&["u1", "u2", "u3"], settings(1000, 2)).await;
    f.expect_bad_credentials("u1").await;
    f.expect_bad_credentials("u2").await;
    let retry = f.expect_locked("u3", "bad-password").await;
    // 固定窗口:retry = 窗口末尾 - now = (T0+86400) - (T0+10)。不退避。
    assert_eq!(retry, 86_390);

    // 再触发一次仍是固定窗口剩余秒数(不升级)。
    f.set_now(T0 + 110);
    assert_eq!(f.expect_locked("u3", "bad-password").await, 86_290);

    assert_eq!(f.lockout_rows().await, 0, "IP 维度不得写 login_lockouts");
}

#[tokio::test]
async fn username_lock_writes_exactly_one_lockout_row() {
    let f = fixture(&["alice"]).await;
    assert_eq!(f.lockout_rows().await, 0);
    f.trip("alice").await;
    f.expect_locked("alice", GOOD).await;
    assert_eq!(f.lockout_rows().await, 1, "同一用户名只有一行锁定状态");
}

#[tokio::test]
async fn every_rejected_attempt_writes_login_locked_with_account_locked_reason() {
    let f = fixture(&["alice"]).await;
    f.trip("alice").await; // 第 3 次尝试触发锁定,本身即被拒
    f.expect_locked("alice", GOOD).await;
    f.expect_locked("alice", "bad-password").await;

    let events = f.audit().await;
    let locked: Vec<_> = events
        .iter()
        .filter(|e| e.event_type == "login_locked")
        .collect();
    assert_eq!(locked.len(), 3, "每次被拒都应写一行 login_locked");
    for e in &locked {
        assert_eq!(e.result, "denied");
        assert_eq!(e.reason.as_deref(), Some("account locked"));
        assert_eq!(e.username_attempted.as_deref(), Some("alice"));
    }
    // 锁内请求不计数、不验密:login_failure 只有锁定前的 2 次。
    assert_eq!(
        events
            .iter()
            .filter(|e| e.event_type == "login_failure")
            .count(),
        2
    );
}

#[tokio::test]
async fn http_retry_after_header_carries_escalated_lock_duration() {
    let dir = tempfile::tempdir().unwrap();
    let dsn = dir.path().join("http.db").to_str().unwrap().to_string();
    let (mut state, storage) = build_state(&dsn).await;
    let clock = attach_clock(&storage, T0 + 10);
    state.auth_service = Arc::new(AuthService::with_settings(
        JWT_SECRET.to_string(),
        storage.clone(),
        settings(2, 1000),
    ));
    seed_user(&state, "alice", GOOD, Role::User).await;
    let router = api::create_router(state);

    let login = |pw: &'static str| {
        let router = router.clone();
        async move {
            let resp = router
                .oneshot(post(
                    "/api/v1/auth/login",
                    None,
                    serde_json::json!({"username": "alice", "password": pw}),
                ))
                .await
                .unwrap();
            let status = resp.status();
            let retry = resp
                .headers()
                .get(header::RETRY_AFTER)
                .map(|v| v.to_str().unwrap().to_string());
            (status, retry, body_json(resp).await)
        }
    };

    assert_eq!(login("bad-password").await.0, StatusCode::UNAUTHORIZED);
    assert_eq!(login("bad-password").await.0, StatusCode::UNAUTHORIZED);
    let (status, retry, body) = login("bad-password").await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(retry.as_deref(), Some("900"));
    assert_eq!(body["error"], "too many attempts");

    clock.store(T0 + 911, Ordering::SeqCst);
    assert_eq!(login("bad-password").await.0, StatusCode::UNAUTHORIZED);
    assert_eq!(login("bad-password").await.0, StatusCode::UNAUTHORIZED);
    let (status, retry, _) = login("bad-password").await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(
        retry.as_deref(),
        Some("1800"),
        "Retry-After 上限应随 lockout.max_secs 放宽,不再截断到 900"
    );
}
