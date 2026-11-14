//! C6(B8a):CLI `user unlock <username>` 的行为测试(C7 的 HTTP 用例稍后追加到本文件)。
//!
//! 公开 seam:HTTP login / change-password 触发锁定,真实二进制 `datachain user unlock <username>`,
//! `Storage::list_audit_events`。锁定状态在 SQLite 里:CLI 子进程只清库,
//! 服务侧(同一 DSN)每次请求读库,因此即时感知。
//!
//! 实现前预期 Red 原因:`unlock` 子命令不存在,clap 以非 0(通常 2)退出并报
//! `unrecognized subcommand`。
//! - 成功路径用例因退出码非 0 而失败;
//! - 失败路径(未知用户)用例的"非 0"断言会意外通过,所以另外断言输出不是
//!   clap 用法错误,并断言输出含用户名(clap 错误不会回显用户名),Red 阶段同样失败。
//!
//! 时钟:限速是 epoch 对齐的固定窗口,固定存储时钟避免耗时跨窗口导致计数重置而偶发失败。
//! 会话过期按真实时钟判断,所以固定时钟取真实当前时间向下对齐到窗口整数倍再 +10 秒,
//! 每个用例只算一次后保持不变。CLI 子进程用真实时钟,unlock 只删行,不依赖时钟。
//! 每个用例只建一次 `build_state`(同 DSN 重复建会重复写创世块)。

mod common;

use std::process::{Output, Stdio};
use std::sync::Arc;

use axum::http::{header, StatusCode};
use axum::Router;
use common::*;
use datachain::api::{self, AppState};
use datachain::auth::{AuthService, AuthSettings, LoginLimits, Role};
use datachain::storage::AuditEvent;
use serde_json::{json, Value};
use tower::ServiceExt;

const ALICE_PW: &str = "alicepass123";
const BOB_PW: &str = "bobpass123456";
const NEW_PW: &str = "brand-new-pass-456";
const WINDOW: i64 = 900;

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

fn settings(user_max: i64, ip_max: i64) -> AuthSettings {
    AuthSettings {
        login_limits: LoginLimits {
            user_max_attempts: user_max,
            ip_max_attempts: ip_max,
            window_secs: WINDOW,
        },
        ..AuthSettings::default()
    }
}

async fn fixture(s: AuthSettings) -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let dsn = dir.path().join("unlock.db").to_str().unwrap().to_string();
    let (mut state, storage) = build_state(&dsn).await;
    // 真实当前时间向下对齐到 WINDOW 的整数倍再 +10 秒,只算一次后固定。
    let pinned = (chrono::Utc::now().timestamp() / WINDOW) * WINDOW + 10;
    storage.set_clock(Arc::new(move || pinned));
    state.auth_service = Arc::new(AuthService::with_settings(
        JWT_SECRET.to_string(),
        storage.clone(),
        s,
    ));
    seed_user(&state, "alice", ALICE_PW, Role::User).await;
    seed_user(&state, "bob", BOB_PW, Role::User).await;
    let router = api::create_router(state.clone());
    Fixture {
        router,
        state,
        dsn,
        _dir: dir,
    }
}

/// 用户名维度小阈值(2),IP 维度放宽。
async fn user_fixture() -> Fixture {
    fixture(settings(2, 1000)).await
}

async fn send(router: &Router, req: axum::http::Request<axum::body::Body>) -> Resp {
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
    async fn login(&self, user: &str, pw: &str) -> Resp {
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

    async fn change(&self, token: &str, old: &str, new: &str) -> Resp {
        send(
            &self.router,
            post(
                "/api/v1/auth/password",
                Some(token),
                json!({"old_password": old, "new_password": new}),
            ),
        )
        .await
    }

    async fn access_token(&self, user: &str, pw: &str) -> String {
        let r = self.login(user, pw).await;
        assert_eq!(r.status, StatusCode::OK, "登录应成功: {}", user);
        r.body["data"]["token"].as_str().unwrap().to_string()
    }

    /// 连续两次错误密码均 401,第三次触发锁定(429),返回第三次的响应。
    async fn trip(&self, user: &str) -> Resp {
        for i in 0..2 {
            let r = self.login(user, "wrong-password").await;
            assert_eq!(r.status, StatusCode::UNAUTHORIZED, "第 {} 次失败应为 401", i + 1);
        }
        let r = self.login(user, "wrong-password").await;
        assert_eq!(r.status, StatusCode::TOO_MANY_REQUESTS, "第 3 次应触发锁定");
        r
    }

    async fn run_cli(&self, args: &[&str]) -> Output {
        tokio::process::Command::new(env!("CARGO_BIN_EXE_datachain"))
            .args(["--config", "/nonexistent/datachain-test.toml"])
            .args(args)
            .env("DATACHAIN_JWT_SECRET", JWT_SECRET)
            .env("DATACHAIN_DATABASE_DSN", &self.dsn)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .await
            .unwrap()
    }

    /// 执行 `user unlock <username>`,要求退出 0 且不是 clap 用法错误。
    async fn unlock_ok(&self, username: &str) -> Output {
        let out = self.run_cli(&["user", "unlock", username]).await;
        assert_not_clap_unknown_subcommand(&out);
        assert!(out.status.success(), "unlock 应退出 0: {}", describe(&out));
        out
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

    fn user_id(&self, name: &str) -> String {
        self.state.auth_service.get_user(name).unwrap().user_id
    }
}

fn retry_secs(r: &Resp) -> u64 {
    r.retry_after
        .as_deref()
        .expect("429 必须带 Retry-After")
        .parse()
        .unwrap()
}

fn text(out: &[u8]) -> String {
    String::from_utf8_lossy(out).into_owned()
}

fn combined(out: &Output) -> String {
    format!("{}{}", text(&out.stdout), text(&out.stderr))
}

fn describe(out: &Output) -> String {
    format!(
        "status={:?} stdout={} stderr={}",
        out.status,
        text(&out.stdout),
        text(&out.stderr)
    )
}

/// 防止 Red 阶段"子命令不存在"被误当作业务拒绝或成功。
fn assert_not_clap_unknown_subcommand(out: &Output) {
    let all = combined(out).to_lowercase();
    assert!(
        !all.contains("unrecognized subcommand") && !all.contains("usage:"),
        "unlock 子命令应存在,不应是 clap 用法错误: {}",
        describe(out)
    );
}

// ---------------------------------------------------------------- 用例

/// 1. 锁定 → 锁内正确密码也 429 → CLI unlock → 正确密码立即 200。
#[tokio::test]
async fn cli_unlock_clears_login_lock_and_correct_password_works_immediately() {
    let f = user_fixture().await;
    let locked = f.trip("alice").await;
    assert_eq!(retry_secs(&locked), 900);

    let inside = f.login("alice", ALICE_PW).await;
    assert_eq!(
        inside.status,
        StatusCode::TOO_MANY_REQUESTS,
        "锁内正确密码也应 429"
    );

    f.unlock_ok("alice").await;

    let after = f.login("alice", ALICE_PW).await;
    assert_eq!(after.status, StatusCode::OK, "解锁后正确密码应立即 200");
}

/// 2. 解锁后退避级别归零:再次触发锁定仍为 900 而不是 1800。
#[tokio::test]
async fn unlock_resets_backoff_level_so_next_lock_is_base_duration() {
    let f = user_fixture().await;
    assert_eq!(retry_secs(&f.trip("alice").await), 900);

    f.unlock_ok("alice").await;

    // 解锁清了窗口计数,需再失败 2 次后第 3 次才锁。
    assert_eq!(
        retry_secs(&f.trip("alice").await),
        900,
        "级别归零后再次锁定应为 base 900,而非 1800"
    );
}

/// 3. 大小写变体:`ALICE` 触发的锁被 `unlock alice` 清除(login key 经 normalize 小写)。
#[tokio::test]
async fn unlock_by_stored_username_clears_lock_made_with_uppercase_variant() {
    let f = user_fixture().await;
    let locked = f.trip("ALICE").await;
    assert_eq!(retry_secs(&locked), 900);
    assert_eq!(
        f.login("alice", ALICE_PW).await.status,
        StatusCode::TOO_MANY_REQUESTS,
        "大小写变体共用同一 key,小写登录也应被锁"
    );

    f.unlock_ok("alice").await;

    assert_eq!(f.login("alice", ALICE_PW).await.status, StatusCode::OK);
}

/// 4. pwchg 锁:连续旧密码错至 429;unlock 后用正确旧密码改密成功(204)。
#[tokio::test]
async fn unlock_clears_change_password_lock() {
    let f = user_fixture().await;
    let token = f.access_token("alice", ALICE_PW).await;

    for i in 1..=2 {
        let r = f.change(&token, &format!("bad-old-pass-{}", i), NEW_PW).await;
        assert_eq!(r.status, StatusCode::UNAUTHORIZED);
    }
    let locked = f.change(&token, "bad-old-pass-3", NEW_PW).await;
    assert_eq!(locked.status, StatusCode::TOO_MANY_REQUESTS);
    assert!(locked.retry_after.is_some());
    // 锁内正确旧密码也 429。
    assert_eq!(
        f.change(&token, ALICE_PW, NEW_PW).await.status,
        StatusCode::TOO_MANY_REQUESTS
    );

    f.unlock_ok("alice").await;

    let r = f.change(&token, ALICE_PW, NEW_PW).await;
    assert_eq!(r.status, StatusCode::NO_CONTENT, "解锁后正确旧密码应可改密");
    assert_eq!(f.login("alice", NEW_PW).await.status, StatusCode::OK);
}

/// 5. 不影响他人:bob 同样被锁,alice 解锁后 bob 仍 429。
#[tokio::test]
async fn unlock_does_not_affect_other_users() {
    let f = user_fixture().await;
    f.trip("alice").await;
    f.trip("bob").await;

    f.unlock_ok("alice").await;

    assert_eq!(f.login("alice", ALICE_PW).await.status, StatusCode::OK);
    let bob = f.login("bob", BOB_PW).await;
    assert_eq!(bob.status, StatusCode::TOO_MANY_REQUESTS, "bob 的锁不应被清除");
    assert_eq!(retry_secs(&bob), 900);
}

/// 6. 不清 IP 维度:IP 超限 429,unlock 后仍 429。
#[tokio::test]
async fn unlock_does_not_clear_ip_dimension() {
    // 用户名维度放宽,IP 维度阈值 2:第 3 次尝试(无论用户)触发 IP 超限。
    let f = fixture(settings(1000, 2)).await;
    for i in 0..2 {
        let r = f.login("alice", "wrong-password").await;
        assert_eq!(r.status, StatusCode::UNAUTHORIZED, "第 {} 次失败应为 401", i + 1);
    }
    let limited = f.login("alice", ALICE_PW).await;
    assert_eq!(limited.status, StatusCode::TOO_MANY_REQUESTS, "IP 超限应 429");

    f.unlock_ok("alice").await;

    let after = f.login("alice", ALICE_PW).await;
    assert_eq!(
        after.status,
        StatusCode::TOO_MANY_REQUESTS,
        "unlock 不应清除 IP 维度计数"
    );
    assert!(after.retry_after.is_some());
}

/// 7a. 审计:`login_unlocked`,user=alice,actor 为空,result success,reason `cleared locks=N counters=M`。
#[tokio::test]
async fn unlock_writes_login_unlocked_audit_without_actor() {
    let f = user_fixture().await;
    f.trip("alice").await;
    assert!(f.events_of("login_unlocked").await.is_empty());

    let out = f.unlock_ok("alice").await;

    let rows = f.events_of("login_unlocked").await;
    assert_eq!(rows.len(), 1, "应恰好一条 login_unlocked: {:?}", rows);
    let ev = &rows[0];
    assert_eq!(ev.user_id.as_deref(), Some(f.user_id("alice").as_str()));
    assert!(ev.actor_user_id.is_none(), "CLI 解锁无操作者");
    assert_eq!(ev.result, "success");
    let reason = ev.reason.as_deref().unwrap_or_default();
    assert!(
        reason.starts_with("cleared locks=1 counters="),
        "reason 应形如 `cleared locks=N counters=M` 且清除了 1 条锁: {:?}",
        reason
    );
    let counters = reason.trim_start_matches("cleared locks=1 counters=");
    assert!(
        !counters.is_empty() && counters.chars().all(|c| c.is_ascii_digit()),
        "counters 应为数字: {:?}",
        reason
    );

    // 审计与 CLI 输出不含密码。
    let dump = format!("{:?}", f.state.storage.list_audit_events(1000).await.unwrap());
    let cli_output = combined(&out);
    for secret in [ALICE_PW, "wrong-password"] {
        assert!(!dump.contains(secret), "审计不得含密码 {}", secret);
        assert!(!cli_output.contains(secret), "CLI 输出不得含密码 {}", secret);
    }
}

/// 7b. 幂等:无锁时 unlock 也成功退出 0 并写审计,可重复执行。
#[tokio::test]
async fn unlock_without_any_lock_succeeds_and_is_audited() {
    let f = user_fixture().await;

    f.unlock_ok("alice").await;
    f.unlock_ok("alice").await;

    let rows = f.events_of("login_unlocked").await;
    assert_eq!(rows.len(), 2, "每次 unlock 都应写审计: {:?}", rows);
    for ev in &rows {
        assert_eq!(ev.user_id.as_deref(), Some(f.user_id("alice").as_str()));
        assert!(ev.actor_user_id.is_none());
        assert_eq!(ev.result, "success");
        assert_eq!(
            ev.reason.as_deref(),
            Some("cleared locks=0 counters=0"),
            "无任何尝试记录时应全为 0"
        );
    }
    assert_eq!(f.login("alice", ALICE_PW).await.status, StatusCode::OK);
}

/// 8. 未知用户:非 0 且输出含用户名,且不写审计。
#[tokio::test]
async fn unlock_unknown_user_fails_and_mentions_username() {
    let f = user_fixture().await;
    let out = f.run_cli(&["user", "unlock", "ghost"]).await;
    assert_not_clap_unknown_subcommand(&out);
    assert!(!out.status.success(), "未知用户应非 0: {}", describe(&out));
    assert!(
        combined(&out).contains("ghost"),
        "输出应含用户名 ghost: {}",
        describe(&out)
    );
    assert!(f.events_of("login_unlocked").await.is_empty());
}
