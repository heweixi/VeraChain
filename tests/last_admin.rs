//! C5(B10):最后一名活跃管理员保护的行为测试(TDD Red)。
//!
//! 公开 seam:`AuthService::deactivate_user_by`、HTTP
//! `POST /api/v1/admin/users/:user_id/deactivate`、真实二进制 `user deactivate <username>`、
//! `Storage::is_user_active`、`Storage::list_audit_events`。
//! 每个用例只调用一次 `build_state`(同 DSN 重复建会重复写创世块)。
//!
//! 实现前预期 Red 原因:
//! 1. `DataChainError::LastAdminProtected` 变体尚不存在 => 本文件编译失败(可接受的 Red);
//! 2. 即使变体存在,当前实现仍允许停用最后一名活跃管理员:CLI 退出 0、无
//!    `user_deactivate_denied` 审计、并发互停两边都成功。
//!
//! HTTP 层 409 `cannot deactivate the last active admin` 的构造说明:
//! 请求能通过中间件说明执行者是活跃管理员,所以纯 HTTP 下目标不可能是"唯一活跃管理员"
//! (执行者自己也是活跃管理员,且自停用先判定)。可确定性构造的办法是:执行者 token 的
//! 角色声明仍是 admin,但库里该用户已被降为 `role='user'`(独立连接 UPDATE,模拟另一进程改角色),
//! 此时库中活跃管理员只剩目标一个。该用例(用例 3b)依赖"中间件按 token 声明鉴权",
//! 若实现侧改为按库校验角色,该用例需调整。service 层断言(用例 3a)不依赖这一点。
mod common;

use std::process::Output;
use std::time::Duration;

use axum::http::StatusCode;
use axum::Router;
use common::*;
use datachain::api::{self, AppState};
use datachain::auth::{LoginContext, Role};
use datachain::error::DataChainError;
use datachain::storage::AuditEvent;
use serde_json::{json, Value};
use tower::ServiceExt;

const VICTIM_PW: &str = "victimpass123";

struct Fixture {
    router: Router,
    state: AppState,
    dsn: String,
    _dir: tempfile::TempDir,
}

fn password_of(name: &str) -> String {
    format!("{}-pass-1234", name)
}

/// 建库并播种 `admins` 中的管理员与普通用户 victim。
async fn fixture(admins: &[&str]) -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let dsn = dir.path().join("dc.db").to_str().unwrap().to_string();
    let (state, storage) = build_state(&dsn).await;
    storage.set_active_cache_ttl(Duration::ZERO);
    for name in admins {
        seed_user(&state, name, &password_of(name), Role::Admin).await;
    }
    seed_user(&state, "victim", VICTIM_PW, Role::User).await;
    let router = api::create_router(state.clone());
    Fixture {
        router,
        state,
        dsn,
        _dir: dir,
    }
}

impl Fixture {
    async fn login(&self, name: &str) -> String {
        let pw = if name == "victim" {
            VICTIM_PW.to_string()
        } else {
            password_of(name)
        };
        let resp = self
            .router
            .clone()
            .oneshot(post(
                "/api/v1/auth/login",
                None,
                json!({"username": name, "password": pw}),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK, "登录 {} 应成功", name);
        let body = body_json(resp).await;
        body["data"]["token"].as_str().unwrap().to_string()
    }

    fn id(&self, name: &str) -> String {
        self.state.auth_service.get_user(name).unwrap().user_id
    }

    async fn deactivate_http(&self, token: &str, target_id: &str) -> (StatusCode, Value) {
        let resp = self
            .router
            .clone()
            .oneshot(post(
                &format!("/api/v1/admin/users/{}/deactivate", target_id),
                Some(token),
                json!({}),
            ))
            .await
            .unwrap();
        (resp.status(), body_json(resp).await)
    }

    async fn activate_http(&self, token: &str, target_id: &str) -> (StatusCode, Value) {
        let resp = self
            .router
            .clone()
            .oneshot(post(
                &format!("/api/v1/admin/users/{}/activate", target_id),
                Some(token),
                json!({}),
            ))
            .await
            .unwrap();
        (resp.status(), body_json(resp).await)
    }

    async fn profile(&self, token: &str) -> StatusCode {
        self.router
            .clone()
            .oneshot(get("/api/v1/auth/profile", Some(token)))
            .await
            .unwrap()
            .status()
    }

    async fn run_cli(&self, args: &[&str]) -> Output {
        tokio::process::Command::new(env!("CARGO_BIN_EXE_datachain"))
            .args(["--config", "/nonexistent/datachain-test.toml"])
            .args(args)
            .env("DATACHAIN_JWT_SECRET", JWT_SECRET)
            .env("DATACHAIN_DATABASE_DSN", &self.dsn)
            .output()
            .await
            .unwrap()
    }

    async fn is_active(&self, user_id: &str) -> bool {
        self.state.storage.is_user_active(user_id).await.unwrap()
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

    /// 独立连接,绕过服务层直接读写库(模拟另一进程)。
    async fn pool(&self) -> sqlx::SqlitePool {
        sqlx::sqlite::SqlitePoolOptions::new()
            .max_connections(1)
            .connect(&format!("sqlite:{}?mode=rw", self.dsn))
            .await
            .unwrap()
    }
}

fn text(out: &[u8]) -> String {
    String::from_utf8_lossy(out).into_owned()
}

fn combined(out: &Output) -> String {
    format!("{}{}", text(&out.stdout), text(&out.stderr))
}

async fn active_admin_count(pool: &sqlx::SqlitePool) -> i64 {
    sqlx::query_scalar("SELECT COUNT(*) FROM users WHERE role = 'admin' AND is_active = 1")
        .fetch_one(pool)
        .await
        .unwrap()
}

// ---------- 用例 1:唯一活跃管理员 + CLI ----------

#[tokio::test]
async fn cli_cannot_deactivate_the_only_active_admin() {
    let f = fixture(&["root"]).await;
    let root_id = f.id("root");
    let victim_id = f.id("victim");

    let out = f.run_cli(&["user", "deactivate", "root"]).await;
    assert!(
        !out.status.success(),
        "停用唯一活跃管理员应非 0: {}",
        combined(&out)
    );
    assert!(
        combined(&out).contains("cannot deactivate the last active admin"),
        "输出应含固定错误词: {}",
        combined(&out)
    );
    assert!(f.is_active(&root_id).await, "root 必须仍是活跃");

    let denied = f.events_of("user_deactivate_denied").await;
    assert_eq!(denied.len(), 1, "应写一条拒绝审计");
    assert_eq!(denied[0].result, "denied");
    assert_eq!(denied[0].user_id.as_deref(), Some(root_id.as_str()));
    assert_eq!(denied[0].reason.as_deref(), Some("last active admin"));
    assert!(denied[0].actor_user_id.is_none(), "CLI 无操作者");
    assert!(
        f.events_of("user_deactivated").await.is_empty(),
        "被拒不得写成功审计"
    );

    // 普通用户不受保护影响。
    let out = f.run_cli(&["user", "deactivate", "victim"]).await;
    assert!(
        out.status.success(),
        "停用普通用户应成功: {}",
        combined(&out)
    );
    assert!(!f.is_active(&victim_id).await);
    assert!(f.is_active(&root_id).await);
}

// ---------- 用例 2:两个管理员 ----------

#[tokio::test]
async fn two_admins_http_and_cli_flow() {
    let f = fixture(&["root", "root2"]).await;
    let root = f.login("root").await;
    let root2 = f.login("root2").await;
    let root_id = f.id("root");
    let root2_id = f.id("root2");
    assert_eq!(f.profile(&root2).await, StatusCode::OK);

    // root 停用 root2:仍剩 root,允许。
    let (status, body) = f.deactivate_http(&root, &root2_id).await;
    assert_eq!(status, StatusCode::OK, "{}", body);
    assert_eq!(
        body["data"],
        json!({"user_id": root2_id, "is_active": false, "revoked_sessions": 1})
    );
    assert!(!f.is_active(&root2_id).await);
    assert_eq!(f.profile(&root2).await, StatusCode::UNAUTHORIZED);

    // root 停用自己:自停用先判定,不是 last admin 错误。
    let (status, body) = f.deactivate_http(&root, &root_id).await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(body["error"], "cannot deactivate yourself");
    assert!(f.is_active(&root_id).await);
    assert!(
        f.events_of("user_deactivate_denied").await.is_empty(),
        "自停用不写 last-admin 拒绝审计"
    );

    // CLI 停用 root(现为唯一活跃管理员)被拒。
    let out = f.run_cli(&["user", "deactivate", "root"]).await;
    assert!(!out.status.success(), "{}", combined(&out));
    assert!(combined(&out).contains("cannot deactivate the last active admin"));
    assert!(f.is_active(&root_id).await);
    assert_eq!(f.profile(&root).await, StatusCode::OK);

    // 再次停用已停用的 root2:幂等 200,无会话可撤销。
    let (status, body) = f.deactivate_http(&root, &root2_id).await;
    assert_eq!(status, StatusCode::OK, "{}", body);
    assert_eq!(
        body["data"],
        json!({"user_id": root2_id, "is_active": false, "revoked_sessions": 0})
    );
}

// ---------- 用例 3a:第三方场景(service 层) ----------

#[tokio::test]
async fn third_admin_scenario_service_layer_protects_last_admin() {
    let f = fixture(&["root", "root2", "root3"]).await;
    let root = f.login("root").await;
    let root2 = f.login("root2").await;
    let root3 = f.login("root3").await;
    let root_id = f.id("root");
    let root2_id = f.id("root2");
    let root3_id = f.id("root3");

    // root 停用 root2;root3 停用 root,root3 成为唯一活跃管理员。
    let (status, body) = f.deactivate_http(&root, &root2_id).await;
    assert_eq!(status, StatusCode::OK, "{}", body);
    let (status, body) = f.deactivate_http(&root3, &root_id).await;
    assert_eq!(status, StatusCode::OK, "{}", body);
    assert_eq!(f.profile(&root).await, StatusCode::UNAUTHORIZED);
    assert_eq!(f.profile(&root2).await, StatusCode::UNAUTHORIZED);
    assert_eq!(f.profile(&root3).await, StatusCode::OK);

    // 以已停用的 root 作为(过期的)执行者,目标为唯一活跃管理员 root3。
    let ctx = LoginContext::default();
    let r = f
        .state
        .auth_service
        .deactivate_user_by(Some(root_id.as_str()), &root3_id, &ctx)
        .await;
    assert!(
        matches!(r, Err(DataChainError::LastAdminProtected)),
        "应返回 LastAdminProtected,实际 {:?}",
        r
    );
    // 无操作者路径(CLI 使用)同样受保护。
    let r = f.state.auth_service.deactivate_user(&root3_id).await;
    assert!(matches!(r, Err(DataChainError::LastAdminProtected)));

    assert!(f.is_active(&root3_id).await);
    assert_eq!(
        f.profile(&root3).await,
        StatusCode::OK,
        "root3 会话不受影响"
    );

    let denied = f.events_of("user_deactivate_denied").await;
    assert_eq!(denied.len(), 2);
    assert!(denied.iter().all(|e| e.result == "denied"
        && e.user_id.as_deref() == Some(root3_id.as_str())
        && e.reason.as_deref() == Some("last active admin")));
    assert!(denied
        .iter()
        .any(|e| e.actor_user_id.as_deref() == Some(root_id.as_str())));
    assert!(denied.iter().any(|e| e.actor_user_id.is_none()));
}

// ---------- 用例 3b:HTTP 409 last admin ----------

#[tokio::test]
async fn http_returns_409_when_target_is_the_only_active_admin_in_db() {
    let f = fixture(&["root", "root2"]).await;
    let root = f.login("root").await;
    let root2 = f.login("root2").await;
    let root_id = f.id("root");
    let root2_id = f.id("root2");

    // 模拟另一进程把 root2 降为普通用户(仍活跃,token 声明仍是 admin)。
    let pool = f.pool().await;
    sqlx::query("UPDATE users SET role = 'user' WHERE user_id = ?")
        .bind(&root2_id)
        .execute(&pool)
        .await
        .unwrap();
    assert_eq!(active_admin_count(&pool).await, 1);

    let (status, body) = f.deactivate_http(&root2, &root_id).await;
    assert_eq!(status, StatusCode::CONFLICT, "{}", body);
    assert_eq!(body["error"], "cannot deactivate the last active admin");
    assert!(f.is_active(&root_id).await);
    assert_eq!(f.profile(&root).await, StatusCode::OK);

    let denied = f.events_of("user_deactivate_denied").await;
    assert_eq!(denied.len(), 1);
    assert_eq!(denied[0].user_id.as_deref(), Some(root_id.as_str()));
    assert_eq!(denied[0].actor_user_id.as_deref(), Some(root2_id.as_str()));
    assert_eq!(denied[0].reason.as_deref(), Some("last active admin"));
}

// ---------- 用例 4:并发互停 ----------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_mutual_deactivation_leaves_exactly_one_admin() {
    let f = fixture(&[]).await;
    let pool = f.pool().await;
    let ctx = LoginContext::default();

    for round in 0..10 {
        let a_name = format!("adm-a-{}", round);
        let b_name = format!("adm-b-{}", round);
        seed_user(&f.state, &a_name, &password_of(&a_name), Role::Admin).await;
        seed_user(&f.state, &b_name, &password_of(&b_name), Role::Admin).await;
        let a = f.id(&a_name);
        let b = f.id(&b_name);
        assert_eq!(active_admin_count(&pool).await, 2, "第 {} 轮起始", round);

        let svc = f.state.auth_service.clone();
        let (r1, r2) = tokio::join!(
            svc.deactivate_user_by(Some(a.as_str()), &b, &ctx),
            svc.deactivate_user_by(Some(b.as_str()), &a, &ctx),
        );
        let oks = [r1.is_ok(), r2.is_ok()].iter().filter(|x| **x).count();
        let protected = [&r1, &r2]
            .iter()
            .filter(|r| matches!(**r, Err(DataChainError::LastAdminProtected)))
            .count();
        assert_eq!(oks, 1, "第 {} 轮恰好一个成功: {:?} / {:?}", round, r1, r2);
        assert_eq!(
            protected, 1,
            "第 {} 轮恰好一个被保护: {:?} / {:?}",
            round, r1, r2
        );
        assert_eq!(
            active_admin_count(&pool).await,
            1,
            "第 {} 轮结束活跃管理员恰为 1",
            round
        );

        // 把本轮两人降级,不影响下一轮计数。
        sqlx::query("UPDATE users SET role = 'user' WHERE user_id IN (?, ?)")
            .bind(&a)
            .bind(&b)
            .execute(&pool)
            .await
            .unwrap();
        assert_eq!(active_admin_count(&pool).await, 0);
    }

    assert_eq!(f.events_of("user_deactivate_denied").await.len(), 10);
    assert_eq!(f.events_of("user_deactivated").await.len(), 10);
}

// ---------- 用例 5:非管理员与 activate 不受限 ----------

#[tokio::test]
async fn non_admin_deactivation_and_activate_are_unrestricted() {
    let f = fixture(&["root", "root2"]).await;
    let root = f.login("root").await;
    let victim = f.login("victim").await;
    let victim_id = f.id("victim");
    let root2_id = f.id("root2");

    // 普通用户停用不受保护影响。
    let (status, body) = f.deactivate_http(&root, &victim_id).await;
    assert_eq!(status, StatusCode::OK, "{}", body);
    assert_eq!(f.profile(&victim).await, StatusCode::UNAUTHORIZED);
    let (status, _) = f.activate_http(&root, &victim_id).await;
    assert_eq!(status, StatusCode::OK);
    assert!(f.is_active(&victim_id).await);

    // 停用管理员 root2 后 activate 恢复,不受"最后管理员"限制。
    let (status, _) = f.deactivate_http(&root, &root2_id).await;
    assert_eq!(status, StatusCode::OK);
    assert!(!f.is_active(&root2_id).await);
    let (status, body) = f.activate_http(&root, &root2_id).await;
    assert_eq!(status, StatusCode::OK, "{}", body);
    assert!(f.is_active(&root2_id).await);
    let _ = f.login("root2").await;

    // 恢复后两个管理员互相可停用(各一次),第二次因成为最后一个而被拒。
    let out = f.run_cli(&["user", "deactivate", "root2"]).await;
    assert!(out.status.success(), "{}", combined(&out));
    let out = f.run_cli(&["user", "deactivate", "root"]).await;
    assert!(!out.status.success(), "{}", combined(&out));

    // CLI activate 对已启用/已停用用户均不受限。
    let out = f.run_cli(&["user", "activate", "root2"]).await;
    assert!(out.status.success(), "{}", combined(&out));
    assert!(f.is_active(&root2_id).await);
}
