//! C1(B9):bcrypt 不得阻塞 tokio 运行时线程。
//!
//! 本文件在实现前应为 Red:`login` / `change_password` / dummy 哈希目前在 async 函数内
//! 同步执行 bcrypt,在 `#[tokio::test]` 默认的 current_thread 运行时里会占满唯一线程,
//! 同一运行时内的 ticker 任务在 bcrypt 期间得不到调度(tick 数为 0-1)。
//!
//! 公开 seam:HTTP router oneshot + 同运行时内每 5ms 计数的 ticker。
//! 断言:请求期间 ticker 次数 >= max(3, 请求总耗时ms / 5 / 4)。

mod common;

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::Router;
use common::*;
use datachain::api;
use datachain::auth::Role;
use serde_json::{json, Value};
use tower::ServiceExt;

const PW: &str = "alicepass123";
const NEW_PW: &str = "brand-new-pass-456";
const TICK_MS: u64 = 5;

struct Measured {
    status: StatusCode,
    body: Value,
    elapsed_ms: u64,
    ticks: u64,
}

/// 并发运行 ticker 与一次请求,返回请求结果、总耗时与请求期间的 tick 次数。
async fn measure(router: &Router, req: Request<Body>) -> Measured {
    let done = Arc::new(AtomicBool::new(false));
    let ticks = Arc::new(AtomicU64::new(0));

    let ticker = {
        let done = done.clone();
        let ticks = ticks.clone();
        async move {
            while !done.load(Ordering::SeqCst) {
                tokio::time::sleep(Duration::from_millis(TICK_MS)).await;
                if !done.load(Ordering::SeqCst) {
                    ticks.fetch_add(1, Ordering::SeqCst);
                }
            }
        }
    };

    let request = {
        let done = done.clone();
        let router = router.clone();
        async move {
            let start = Instant::now();
            let resp = router.oneshot(req).await.unwrap();
            let status = resp.status();
            let body = body_json(resp).await;
            let elapsed_ms = start.elapsed().as_millis() as u64;
            done.store(true, Ordering::SeqCst);
            (status, body, elapsed_ms)
        }
    };

    let ((status, body, elapsed_ms), _) = tokio::join!(request, ticker);
    Measured {
        status,
        body,
        elapsed_ms,
        ticks: ticks.load(Ordering::SeqCst),
    }
}

fn assert_not_blocked(what: &str, m: &Measured) {
    // bcrypt cost 12 通常 >100ms;耗时过短说明没有真正执行 bcrypt,测试不具备判别力。
    assert!(
        m.elapsed_ms >= 20,
        "{}: 请求耗时仅 {}ms,未执行 bcrypt,无法判别是否阻塞运行时",
        what,
        m.elapsed_ms
    );
    let required = std::cmp::max(3, m.elapsed_ms / TICK_MS / 4);
    assert!(
        m.ticks >= required,
        "{}: 请求耗时 {}ms 期间 ticker 仅 tick {} 次(要求 >= {}),bcrypt 阻塞了运行时线程",
        what,
        m.elapsed_ms,
        m.ticks,
        required
    );
}

async fn fixture() -> (Router, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let dsn = dir.path().join("bcrypt.db").to_str().unwrap().to_string();
    let (state, _storage) = build_state(&dsn).await;
    seed_user(&state, "alice", PW, Role::User).await;
    let router = api::create_router(state);
    (router, dir)
}

#[tokio::test]
async fn login_with_correct_password_does_not_block_runtime() {
    let (router, _dir) = fixture().await;
    let req = post(
        "/api/v1/auth/login",
        None,
        json!({"username": "alice", "password": PW}),
    );
    let m = measure(&router, req).await;
    assert_eq!(m.status, StatusCode::OK, "登录应成功: {}", m.body);
    assert_not_blocked("登录(正确密码)", &m);
}

#[tokio::test]
async fn login_for_unknown_user_dummy_bcrypt_does_not_block_runtime() {
    let (router, _dir) = fixture().await;
    let req = post(
        "/api/v1/auth/login",
        None,
        json!({"username": "ghost", "password": "whatever-pass-123"}),
    );
    let m = measure(&router, req).await;
    assert_eq!(m.status, StatusCode::UNAUTHORIZED, "未知用户应 401");
    assert_not_blocked("登录(不存在用户,dummy bcrypt)", &m);
}

#[tokio::test]
async fn change_password_does_not_block_runtime() {
    let (router, _dir) = fixture().await;

    // 先登录取 token(此段不计入 ticker 断言)。
    let login = router
        .clone()
        .oneshot(post(
            "/api/v1/auth/login",
            None,
            json!({"username": "alice", "password": PW}),
        ))
        .await
        .unwrap();
    assert_eq!(login.status(), StatusCode::OK);
    let body = body_json(login).await;
    let token = body["data"]["token"].as_str().unwrap().to_string();

    let req = post(
        "/api/v1/auth/password",
        Some(&token),
        json!({"old_password": PW, "new_password": NEW_PW}),
    );
    let m = measure(&router, req).await;
    assert_eq!(m.status, StatusCode::NO_CONTENT, "改密应成功: {}", m.body);
    assert_not_blocked("改密(验旧密码 + 哈希新密码)", &m);
}
