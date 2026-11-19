//! C1(B14):CLI `user create --role` 解析行为测试。
//!
//! 公开 seam:真实二进制 `datachain user create --username .. --password .. --email .. [--role ..]`
//! (同一 SQLite 文件),库内状态经公开的 `Storage::get_all_users` 观察。
//!
//! `Role::from_str` 对大小写不敏感(`to_lowercase`),合法取值为 admin/user/auditor/guest。
//!
//! 实现前预期 Red:非法 `--role` 当前被静默降级为 user(退出码 0,库里有 user 角色用户),
//! 因此 `create_with_invalid_role_fails_and_creates_no_user` 失败;其余用例为回归,应保持通过。
mod common;

use std::sync::Arc;

use common::*;
use datachain::storage::Storage;

struct Fixture {
    storage: Arc<Storage>,
    dsn: String,
    _dir: tempfile::TempDir,
}

/// 每个用例只建一次 build_state(同 DSN 重复建会重复写创世块)。
async fn fixture() -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let dsn = dir
        .path()
        .join("cli-create-role.db")
        .to_str()
        .unwrap()
        .to_string();
    let (_state, storage) = build_state(&dsn).await;
    Fixture {
        storage,
        dsn,
        _dir: dir,
    }
}

impl Fixture {
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

    /// `role` 为 None 时不传 `--role`。
    async fn cli_create(
        &self,
        username: &str,
        password: &str,
        role: Option<&str>,
    ) -> std::process::Output {
        let email = format!("{}@test.local", username);
        let mut args = vec![
            "user",
            "create",
            "--username",
            username,
            "--password",
            password,
            "--email",
            email.as_str(),
        ];
        if let Some(r) = role {
            args.push("--role");
            args.push(r);
        }
        self.run_cli(&args).await
    }

    /// 返回该用户名的角色(Display 文本);不存在返回 None。
    async fn role_of(&self, username: &str) -> Option<String> {
        self.storage
            .get_all_users()
            .await
            .unwrap()
            .iter()
            .find(|u| u.username == username)
            .map(|u| u.role.to_string())
    }
}

fn combined(out: &std::process::Output) -> String {
    format!(
        "{}\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

#[tokio::test]
async fn create_with_admin_role_succeeds_and_stores_admin() {
    let f = fixture().await;
    let out = f.cli_create("root1", "rootpass123", Some("admin")).await;
    assert!(out.status.success(), "output={}", combined(&out));
    assert_eq!(f.role_of("root1").await.as_deref(), Some("admin"));
}

#[tokio::test]
async fn create_with_invalid_role_fails_and_creates_no_user() {
    let f = fixture().await;
    let password = "secretpass123";
    let out = f.cli_create("mallory", password, Some("adm1n")).await;
    let all = combined(&out);

    assert!(
        !out.status.success(),
        "非法角色必须以非 0 退出,实际 output={}",
        all
    );
    assert!(all.contains("无效角色"), "应提示无效角色,output={}", all);
    // 合法取值提示:列出全部允许值(auditor/guest 不会来自命令行回显)。
    for allowed in ["admin", "user", "auditor", "guest"] {
        assert!(
            all.contains(allowed),
            "应提示合法取值 {},output={}",
            allowed,
            all
        );
    }
    assert!(!all.contains(password), "输出不得包含密码,output={}", all);
    assert_eq!(f.role_of("mallory").await, None, "库里不应有该用户");
}

#[tokio::test]
async fn create_without_role_defaults_to_user() {
    let f = fixture().await;
    let out = f.cli_create("bob", "bobpass123", None).await;
    assert!(out.status.success(), "output={}", combined(&out));
    assert_eq!(f.role_of("bob").await.as_deref(), Some("user"));
}

#[tokio::test]
async fn create_with_role_is_case_insensitive_like_from_str() {
    // Role::from_str 使用 to_lowercase,故 `Admin` / `AUDITOR` 合法并归一为小写角色。
    let f = fixture().await;

    let out = f.cli_create("cap1", "cappass1234", Some("Admin")).await;
    assert!(out.status.success(), "output={}", combined(&out));
    assert_eq!(f.role_of("cap1").await.as_deref(), Some("admin"));

    let out = f.cli_create("up1", "uppass12345", Some("AUDITOR")).await;
    assert!(out.status.success(), "output={}", combined(&out));
    assert_eq!(f.role_of("up1").await.as_deref(), Some("auditor"));
}
