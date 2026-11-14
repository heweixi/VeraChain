//! C4(B11b):CLI `user passwd <username>` 的行为测试。
//!
//! 公开 seam:真实二进制 `datachain user passwd <username>`(新密码从 stdin 读一行),
//! 与服务侧 router(同一 SQLite DSN)观察效果。CLI 与服务是两个进程:
//! 服务侧每个用例只 `build_state` 一次;CLI 子进程独立改库。
//!
//! 实现前预期 Red 原因:`passwd` 子命令尚不存在,clap 以非 0(通常 2)退出并报
//! `unrecognized subcommand`。
//! - 成功路径用例(1/5/6)因退出码为非 0 而失败;
//! - 失败路径用例(2/3/4/7)的"非 0"断言会意外通过,所以它们另外断言
//!   输出不是 clap 的未知子命令错误,并断言具体的拒绝词(`too short`/`too long`/用户名),
//!   这样 Red 阶段也会失败。
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
    let dsn = dir.path().join("passwd.db").to_str().unwrap().to_string();
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

struct Tokens {
    access: String,
    refresh: String,
}

impl Fixture {
    /// 真实二进制,stdin 为管道:写入 `stdin_bytes` 后立即关闭(空切片即立刻 EOF)。
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
            // 进程可能提前退出(如参数错误),写管道失败时忽略。
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

    async fn login_tokens(&self) -> Tokens {
        let (status, body) = self.login_raw("alice", OLD_PASSWORD).await;
        assert_eq!(status, StatusCode::OK, "body={}", body);
        Tokens {
            access: body["data"]["token"].as_str().unwrap().to_string(),
            refresh: body["data"]["refresh_token"].as_str().unwrap().to_string(),
        }
    }

    async fn profile(&self, token: &str) -> StatusCode {
        self.router
            .clone()
            .oneshot(get("/api/v1/auth/profile", Some(token)))
            .await
            .unwrap()
            .status()
    }

    async fn refresh(&self, token: &str) -> StatusCode {
        self.router
            .clone()
            .oneshot(post(
                "/api/v1/auth/refresh",
                None,
                json!({"refresh_token": token}),
            ))
            .await
            .unwrap()
            .status()
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

    fn alice_id(&self) -> String {
        self.state.auth_service.get_user("alice").unwrap().user_id
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

/// 防止 Red 阶段"子命令不存在"被误当作业务拒绝。
fn assert_not_clap_unknown_subcommand(out: &Output) {
    let all = combined(out).to_lowercase();
    assert!(
        !all.contains("unrecognized subcommand") && !all.contains("usage:"),
        "passwd 子命令应存在,不应是 clap 用法错误: {}",
        describe(out)
    );
}

// ---------------------------------------------------------------- 用例

/// 1. 成功路径:改密、旧凭证全部失效、审计与输出不含密码。
#[tokio::test]
async fn cli_passwd_resets_password_revokes_sessions_and_audits() {
    let new_password = "newpass-12345";
    let f = fixture().await;
    let first = f.login_tokens().await;
    let second = f.login_tokens().await;
    assert_eq!(f.profile(&first.access).await, StatusCode::OK);
    assert_eq!(f.profile(&second.access).await, StatusCode::OK);

    let out = f.passwd("alice", b"newpass-12345\n").await;
    assert!(out.status.success(), "{}", describe(&out));

    assert_eq!(
        f.login_status(OLD_PASSWORD).await,
        StatusCode::UNAUTHORIZED,
        "旧密码应不能再登录"
    );
    assert_eq!(f.login_status(new_password).await, StatusCode::OK);

    for t in [&first, &second] {
        assert_eq!(
            f.profile(&t.access).await,
            StatusCode::UNAUTHORIZED,
            "旧 access 应失效"
        );
        assert_eq!(
            f.refresh(&t.refresh).await,
            StatusCode::UNAUTHORIZED,
            "旧 refresh 应失效"
        );
    }

    let resets = f.password_reset_events().await;
    assert_eq!(resets.len(), 1, "应恰好写一条 password_reset: {:?}", resets);
    let ev = &resets[0];
    assert_eq!(ev.user_id.as_deref(), Some(f.alice_id().as_str()));
    assert!(ev.actor_user_id.is_none(), "CLI 重置无操作者");
    assert_eq!(ev.result, "success");
    assert!(
        ev.reason
            .as_deref()
            .is_some_and(|r| r.starts_with("cli reset")),
        "reason 应以 `cli reset` 开头: {:?}",
        ev.reason
    );

    let dump = format!("{:?}", f.events().await);
    let cli_output = combined(&out);
    for secret in [new_password, OLD_PASSWORD] {
        assert!(!dump.contains(secret), "审计不得含密码 {}", secret);
        assert!(
            !cli_output.contains(secret),
            "CLI 输出不得含密码 {}",
            secret
        );
    }
}

/// 2. 策略失败:过短密码被拒,旧密码仍可登录,无审计。
#[tokio::test]
async fn cli_passwd_rejects_short_password() {
    let f = fixture().await;
    let out = f.passwd("alice", b"short\n").await;
    assert!(!out.status.success(), "{}", describe(&out));
    assert_not_clap_unknown_subcommand(&out);
    assert!(
        combined(&out).contains("too short"),
        "应指出密码过短: {}",
        describe(&out)
    );

    assert_eq!(f.login_status(OLD_PASSWORD).await, StatusCode::OK);
    assert_eq!(f.login_status("short").await, StatusCode::UNAUTHORIZED);
    assert!(f.password_reset_events().await.is_empty());
}

/// 3. 未知用户:非 0,输出含用户名。
#[tokio::test]
async fn cli_passwd_unknown_user_fails_and_mentions_username() {
    let f = fixture().await;
    let out = f.passwd("ghost", b"newpass-12345\n").await;
    assert!(!out.status.success(), "{}", describe(&out));
    assert_not_clap_unknown_subcommand(&out);
    let all = combined(&out);
    assert!(all.contains("ghost"), "错误信息应含用户名: {}", all);
    assert!(!all.contains("newpass-12345"), "输出不得含密码");
    assert!(f.password_reset_events().await.is_empty());
    assert_eq!(f.login_status(OLD_PASSWORD).await, StatusCode::OK);
}

/// 4. stdin 立即 EOF:非 0,密码未变。
#[tokio::test]
async fn cli_passwd_empty_stdin_fails_and_keeps_password() {
    let f = fixture().await;
    let out = f.passwd("alice", b"").await;
    assert!(!out.status.success(), "{}", describe(&out));
    assert_not_clap_unknown_subcommand(&out);
    assert_eq!(f.login_status(OLD_PASSWORD).await, StatusCode::OK);
    assert!(f.password_reset_events().await.is_empty());
}

/// 5. `\r\n` 结尾:只去掉行尾换行。
#[tokio::test]
async fn cli_passwd_strips_crlf_line_ending() {
    let f = fixture().await;
    let out = f.passwd("alice", b"crlf-pass-1234\r\n").await;
    assert!(out.status.success(), "{}", describe(&out));
    assert_eq!(f.login_status("crlf-pass-1234").await, StatusCode::OK);
    assert_eq!(
        f.login_status("crlf-pass-1234\r").await,
        StatusCode::UNAUTHORIZED,
        "\\r 不应成为密码的一部分"
    );
    assert_eq!(f.login_status(OLD_PASSWORD).await, StatusCode::UNAUTHORIZED);
}

/// 6. 前后空格原样保留。
#[tokio::test]
async fn cli_passwd_preserves_leading_and_trailing_spaces() {
    let f = fixture().await;
    let out = f.passwd("alice", b" spaced pass 99 \n").await;
    assert!(out.status.success(), "{}", describe(&out));
    assert_eq!(f.login_status(" spaced pass 99 ").await, StatusCode::OK);
    assert_eq!(
        f.login_status("spaced pass 99").await,
        StatusCode::UNAUTHORIZED,
        "空格不应被裁掉"
    );
}

/// 7. 超长密码(80 字节 > 72):被拒,旧密码仍可登录。
#[tokio::test]
async fn cli_passwd_rejects_overlong_password() {
    let f = fixture().await;
    let long = "a".repeat(80);
    let out = f.passwd("alice", format!("{}\n", long).as_bytes()).await;
    assert!(!out.status.success(), "{}", describe(&out));
    assert_not_clap_unknown_subcommand(&out);
    let all = combined(&out);
    assert!(all.contains("too long"), "应指出密码过长: {}", all);
    assert!(!all.contains(&long), "输出不得回显密码");

    assert_eq!(f.login_status(OLD_PASSWORD).await, StatusCode::OK);
    assert_eq!(f.login_status(&long).await, StatusCode::UNAUTHORIZED);
    assert!(f.password_reset_events().await.is_empty());
}
