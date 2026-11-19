//! B16/C2:CLI `user passwd <username>` 的 stdin 输入边界行为测试。
//!
//! 公开 seam:真实二进制 `datachain user passwd alice`,服务侧 router 观察登录效果。
//! 每个用例只 `build_state` 一次;CLI 子进程独立改库。
//!
//! 当前实现(take(1024) + read_line(String))预期:
//! - 用例 1(1500 个 a 无换行):截成 1024 字节后按 too long 拒绝,可能已通过;
//! - 用例 2(1023 个 a + "é"):1024 字节处截断在多字节字符中间,read_line 报 UTF-8 错误,
//!   输出不含 `password too long` → 失败(Red);
//! - 用例 3(非 UTF-8 字节):io 错误文本通常含 `UTF-8`,可能已通过;
//!   若文案被改写则需含 `UTF-8` 字样;
//! - 用例 4(恰好 72 字节):回归,应通过。
mod common;

use std::process::{Output, Stdio};

use axum::http::StatusCode;
use axum::Router;
use common::*;
use datachain::api::{self, AppState};
use datachain::auth::Role;
use datachain::storage::AuditEvent;
use serde_json::{json, Value};
use tokio::io::AsyncWriteExt;
use tower::ServiceExt;

const OLD_PASSWORD: &str = "alicepass123";

struct Fixture {
    router: Router,
    state: AppState,
    dsn: String,
    _dir: tempfile::TempDir,
}

async fn fixture() -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let dsn = dir
        .path()
        .join("passwd-input.db")
        .to_str()
        .unwrap()
        .to_string();
    let (state, _storage) = build_state(&dsn).await;
    seed_user(&state, "alice", OLD_PASSWORD, Role::User).await;
    let router = api::create_router(state.clone());
    Fixture {
        router,
        state,
        dsn,
        _dir: dir,
    }
}

impl Fixture {
    /// 真实二进制,stdin 为管道:写入 `stdin_bytes` 后立即关闭。
    async fn run_cli_with_stdin(&self, args: &[&str], stdin_bytes: &[u8]) -> Output {
        let mut child = tokio::process::Command::new(env!("CARGO_BIN_EXE_datachain"))
            .args(["--config", "/nonexistent/datachain-test.toml"])
            .args(args)
            .env("DATACHAIN_JWT_SECRET", JWT_SECRET)
            .env("DATACHAIN_DATABASE_DSN", &self.dsn)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let mut stdin = child.stdin.take().unwrap();
        if !stdin_bytes.is_empty() {
            // 进程可能提前退出,写管道失败时忽略。
            let _ = stdin.write_all(stdin_bytes).await;
        }
        drop(stdin);
        child.wait_with_output().await.unwrap()
    }

    async fn passwd(&self, username: &str, stdin_bytes: &[u8]) -> Output {
        self.run_cli_with_stdin(&["user", "passwd", username], stdin_bytes)
            .await
    }

    async fn login_raw(&self, username: &str, password: &str) -> (StatusCode, Value) {
        let resp = self
            .router
            .clone()
            .oneshot(post(
                "/api/v1/auth/login",
                None,
                json!({"username": username, "password": password}),
            ))
            .await
            .unwrap();
        (resp.status(), body_json(resp).await)
    }

    async fn login_status(&self, password: &str) -> StatusCode {
        self.login_raw("alice", password).await.0
    }

    async fn events(&self) -> Vec<AuditEvent> {
        self.state.storage.list_audit_events(1000).await.unwrap()
    }

    async fn password_reset_events(&self) -> Vec<AuditEvent> {
        self.events()
            .await
            .into_iter()
            .filter(|e| e.event_type == "password_reset")
            .collect()
    }
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

fn assert_not_clap_usage_error(out: &Output) {
    let all = combined(out).to_lowercase();
    assert!(
        !all.contains("unrecognized subcommand") && !all.contains("usage:"),
        "不应是 clap 用法错误: {}",
        describe(out)
    );
}

// ---------------------------------------------------------------- 用例

/// 1. 1500 个 'a' 且无换行:被拒为 too long,不回显密码,旧密码有效,无审计。
#[tokio::test]
async fn cli_passwd_rejects_1500_bytes_without_newline_as_too_long() {
    let f = fixture().await;
    let long = "a".repeat(1500);
    let out = f.passwd("alice", long.as_bytes()).await;
    assert!(!out.status.success(), "{}", describe(&out));
    assert_not_clap_usage_error(&out);
    let all = combined(&out);
    assert!(
        all.contains("password too long"),
        "应指出密码过长: {}",
        describe(&out)
    );
    assert!(!all.contains(&long), "输出不得含密码本体");

    assert_eq!(f.login_status(OLD_PASSWORD).await, StatusCode::OK);
    assert!(f.password_reset_events().await.is_empty());
}

/// 2. 第 1024 字节恰好截在多字节字符中间:仍应报 too long,而不是 UTF-8 错误。
#[tokio::test]
async fn cli_passwd_multibyte_split_at_limit_reports_too_long() {
    let f = fixture().await;
    // 1023 个 'a' + "é"(2 字节)+ 换行 = 1026 字节;第 1024 字节落在 "é" 中间。
    let input = format!("{}é\n", "a".repeat(1023));
    assert_eq!(input.len(), 1026);
    let out = f.passwd("alice", input.as_bytes()).await;
    assert!(!out.status.success(), "{}", describe(&out));
    assert_not_clap_usage_error(&out);
    assert!(
        combined(&out).contains("password too long"),
        "应指出密码过长而非 UTF-8 错误: {}",
        describe(&out)
    );

    assert_eq!(f.login_status(OLD_PASSWORD).await, StatusCode::OK);
    assert!(f.password_reset_events().await.is_empty());
}

/// 3. 非 UTF-8 字节:非 0,输出明确提到 UTF-8,旧密码有效,无审计。
#[tokio::test]
async fn cli_passwd_rejects_non_utf8_input_mentioning_utf8() {
    let f = fixture().await;
    let out = f.passwd("alice", b"\xff\xfe\xfd1234567\n").await;
    assert!(!out.status.success(), "{}", describe(&out));
    assert_not_clap_usage_error(&out);
    assert!(
        combined(&out).contains("UTF-8"),
        "应指出输入不是合法 UTF-8: {}",
        describe(&out)
    );

    assert_eq!(f.login_status(OLD_PASSWORD).await, StatusCode::OK);
    assert!(f.password_reset_events().await.is_empty());
}

/// 4. 回归:恰好 72 字节合法密码成功,并可登录。
#[tokio::test]
async fn cli_passwd_accepts_exactly_72_byte_password() {
    let f = fixture().await;
    let pw = "b".repeat(72);
    let out = f.passwd("alice", format!("{}\n", pw).as_bytes()).await;
    assert!(out.status.success(), "{}", describe(&out));

    assert_eq!(f.login_status(&pw).await, StatusCode::OK);
    assert_eq!(f.login_status(OLD_PASSWORD).await, StatusCode::UNAUTHORIZED);
}
