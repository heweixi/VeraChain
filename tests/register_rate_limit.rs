//! C4(B13):`POST /api/v1/auth/register` 按客户端 IP 限速的行为测试。
//!
//! 公开 seam:
//! - HTTP `POST /api/v1/auth/register` / `login`(router oneshot,手动注入 `ConnectInfo` 指定对端 IP);
//! - `Storage::get_all_users`、`Storage::list_audit_events`、`AuthService::hash_client_ip`;
//! - 真实二进制 `datachain user create ...`(同一 SQLite 文件,子进程用默认配置)。
//!
//! 实现前预期 Red:当前 register 没有限速,因此
//! - 第 3 次注册仍为 201(用例 1、3 的被限部分、2 的第 3 次、4 的前置 429);
//! - 无 `register_rate_limited` 审计(用例 5)。
//!
//! 用例 6(CLI 不受限)与"登录不受影响"在实现前后都应通过(回归性质)。
//!
//! 时钟:限速是 epoch 对齐的固定窗口,固定存储时钟避免耗时跨窗口导致计数重置而偶发失败。
//! 固定时钟取真实当前时间向下对齐到窗口整数倍再 +10 秒,每个用例只算一次后保持不变。
//! 每个用例只建一次 `build_state`(同 DSN 重复建会重复写创世块)。
mod common;

use std::net::SocketAddr;
use std::sync::Arc;

use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::{header, Request, StatusCode};
use axum::Router;
use common::*;
use datachain::api::{self, AppState};
use datachain::auth::{AuthService, AuthSettings, LoginLimits, Role};
use datachain::storage::AuditEvent;
use serde_json::{json, Value};
use tower::ServiceExt;

const WINDOW: i64 = 900;
const IP_A: &str = "198.51.100.1";
const IP_B: &str = "198.51.100.2";
const GOOD_PW: &str = "validpass123";

struct Fixture {
    router: Router,
    state: AppState,
    dsn: String,
    _dir: tempfile::TempDir,
}

struct Resp {
    status: StatusCode,
    retry_after: Option<String>,
    body: Value,
}

async fn fixture() -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let dsn = dir
        .path()
        .join("register-rate-limit.db")
        .to_str()
        .unwrap()
        .to_string();
    let (mut state, storage) = build_state(&dsn).await;
    let pinned = (chrono::Utc::now().timestamp() / WINDOW) * WINDOW + 10;
    storage.set_clock(Arc::new(move || pinned));
    state.auth_service = Arc::new(AuthService::with_settings(
        JWT_SECRET.to_string(),
        storage.clone(),
        AuthSettings {
            login_limits: LoginLimits {
                user_max_attempts: 1000,
                ip_max_attempts: 2,
                window_secs: WINDOW,
            },
            ..AuthSettings::default()
        },
    ));
    seed_user(&state, "alice", "alicepass123", Role::User).await;
    let router = api::create_router(state.clone());
    Fixture {
        router,
        state,
        dsn,
        _dir: dir,
    }
}

fn with_peer(mut req: Request<Body>, ip: &str) -> Request<Body> {
    let peer: SocketAddr = format!("{}:40000", ip).parse().unwrap();
    req.extensions_mut().insert(ConnectInfo(peer));
    req
}

impl Fixture {
    async fn send(&self, req: Request<Body>) -> Resp {
        let resp = self.router.clone().oneshot(req).await.unwrap();
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

    async fn register(&self, ip: &str, username: &str, password: &str) -> Resp {
        let req = with_peer(
            post(
                "/api/v1/auth/register",
                None,
                json!({
                    "username": username,
                    "password": password,
                    "email": format!("{}@test.local", username),
                }),
            ),
            ip,
        );
        self.send(req).await
    }

    async fn login(&self, ip: &str, username: &str, password: &str) -> Resp {
        let req = with_peer(
            post(
                "/api/v1/auth/login",
                None,
                json!({"username": username, "password": password}),
            ),
            ip,
        );
        self.send(req).await
    }

    async fn count_users_named(&self, username: &str) -> usize {
        self.state
            .storage
            .get_all_users()
            .await
            .unwrap()
            .iter()
            .filter(|u| u.username == username)
            .count()
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

    async fn run_cli(&self, args: &[&str]) -> std::process::Output {
        tokio::process::Command::new(env!("CARGO_BIN_EXE_datachain"))
            .args(["--config", "/nonexistent/datachain-test.toml"])
            .args(args)
            .env("DATACHAIN_JWT_SECRET", JWT_SECRET)
            .env("DATACHAIN_DATABASE_DSN", &self.dsn)
            .output()
            .await
            .unwrap()
    }
}

fn assert_rate_limited(r: &Resp) {
    assert_eq!(
        r.status,
        StatusCode::TOO_MANY_REQUESTS,
        "应为 429, body={}",
        r.body
    );
    let secs: u64 = r
        .retry_after
        .as_deref()
        .expect("429 必须带 Retry-After")
        .parse()
        .unwrap();
    assert!(
        (1..=900).contains(&secs),
        "Retry-After 应在 1..=900: {}",
        secs
    );
    assert_eq!(r.body["success"], false);
    assert_eq!(r.body["error"], "too many attempts");
}

// ---------------------------------------------------------------- 用例

/// 1. 同一 IP 前 2 次注册 201,第 3 次(新用户名)429,被拒用户不入库。
#[tokio::test]
async fn third_register_from_same_ip_is_rate_limited() {
    let f = fixture().await;
    for name in ["bob", "carol"] {
        let r = f.register(IP_A, name, GOOD_PW).await;
        assert_eq!(r.status, StatusCode::CREATED, "{} body={}", name, r.body);
    }
    let r = f.register(IP_A, "dave", GOOD_PW).await;
    assert_rate_limited(&r);
    assert_eq!(f.count_users_named("dave").await, 0, "被拒用户不应入库");
    assert_eq!(f.count_users_named("bob").await, 1);
    assert_eq!(f.count_users_named("carol").await, 1);
}

/// 2. 失败注册(短密码 400)也计数,且不归还名额。
#[tokio::test]
async fn failed_registrations_also_count_towards_limit() {
    let f = fixture().await;
    for name in ["bob", "carol"] {
        let r = f.register(IP_A, name, "short").await;
        assert_eq!(r.status, StatusCode::BAD_REQUEST, "body={}", r.body);
    }
    let r = f.register(IP_A, "dave", GOOD_PW).await;
    assert_rate_limited(&r);
    assert_eq!(f.count_users_named("dave").await, 0);
}

/// 3. 不同 IP 互不影响。
#[tokio::test]
async fn different_ips_have_independent_register_buckets() {
    let f = fixture().await;
    for name in ["bob", "carol"] {
        let r = f.register(IP_A, name, GOOD_PW).await;
        assert_eq!(r.status, StatusCode::CREATED, "body={}", r.body);
    }
    assert_rate_limited(&f.register(IP_A, "dave", GOOD_PW).await);

    let r = f.register(IP_B, "erin", GOOD_PW).await;
    assert_eq!(
        r.status,
        StatusCode::CREATED,
        "IP-B 不应受 IP-A 影响: {}",
        r.body
    );
    assert_eq!(f.count_users_named("erin").await, 1);
}

/// 4. 注册被限后,同一 IP 的合法登录仍 200(`reg:` 与 `ip:` key 互不影响)。
#[tokio::test]
async fn register_limit_does_not_affect_login_for_same_ip() {
    let f = fixture().await;
    for name in ["bob", "carol"] {
        let r = f.register(IP_A, name, GOOD_PW).await;
        assert_eq!(r.status, StatusCode::CREATED, "body={}", r.body);
    }
    assert_rate_limited(&f.register(IP_A, "dave", GOOD_PW).await);

    let r = f.login(IP_A, "alice", "alicepass123").await;
    assert_eq!(
        r.status,
        StatusCode::OK,
        "登录不应被注册限速影响: {}",
        r.body
    );
}

/// 5. 审计:被拒写 `register_rate_limited`。
#[tokio::test]
async fn rate_limited_register_writes_audit_event() {
    let f = fixture().await;
    for name in ["bob", "carol"] {
        let r = f.register(IP_A, name, GOOD_PW).await;
        assert_eq!(r.status, StatusCode::CREATED, "body={}", r.body);
    }
    assert!(
        f.events_of("register_rate_limited").await.is_empty(),
        "未超限前不应有该审计"
    );
    assert_rate_limited(&f.register(IP_A, "dave", GOOD_PW).await);

    let events = f.events_of("register_rate_limited").await;
    assert_eq!(events.len(), 1, "被拒一次应恰好一条审计: {:?}", events);
    let e = &events[0];
    assert_eq!(e.result, "denied");
    assert_eq!(e.reason.as_deref(), Some("rate limit exceeded"));
    assert_eq!(
        e.ip_hash.as_deref(),
        Some(f.state.auth_service.hash_client_ip(IP_A).as_str()),
        "ip_hash 应为该 IP 的摘要"
    );
    assert!(e.user_id.is_none(), "user_id 应为空: {:?}", e);
}

/// 6. CLI `user create` 不受限(子进程用默认配置,与服务设置无关)。
#[tokio::test]
async fn cli_user_create_is_not_rate_limited() {
    let f = fixture().await;
    for name in ["u1", "u2", "u3"] {
        let email = format!("{}@test.local", name);
        let out = f
            .run_cli(&[
                "user",
                "create",
                "--username",
                name,
                "--password",
                GOOD_PW,
                "--email",
                email.as_str(),
            ])
            .await;
        assert!(
            out.status.success(),
            "CLI 创建 {} 应退出 0; stdout={} stderr={}",
            name,
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        assert_eq!(f.count_users_named(name).await, 1, "{} 应入库", name);
    }
}
