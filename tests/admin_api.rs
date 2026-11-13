//! C7:管理员接口(会话列出/撤销、停用/启用用户)的行为测试(TDD Red)。
//! 经 HTTP router oneshot 驱动,辅以 Storage / AuthService 公开方法断言。
//! 注意:build_state 同 dsn 不可重复调用(会重复写创世区块),每个用例只建一次。
mod common;

use std::net::SocketAddr;
use std::time::Duration;

use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::{Request, StatusCode};
use axum::Router;
use common::*;
use datachain::api::{self, AppState};
use datachain::auth::{JwtHandler, Role};
use datachain::storage::AuditEvent;
use serde_json::{json, Value};
use sqlx::Row;
use tower::ServiceExt;

const ADMIN_PW: &str = "adminpass1234";
const ADMIN2_PW: &str = "adminpass5678";
const VICTIM_PW: &str = "victimpass123";
const PEER: &str = "203.0.113.9:44321";
const PLAIN_IP: &str = "203.0.113.9";

struct Fixture {
    router: Router,
    state: AppState,
    dsn: String,
    _dir: tempfile::TempDir,
}

struct Tokens {
    access: String,
    refresh: String,
    sid: String,
}

async fn fixture() -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let dsn = dir.path().join("dc.db").to_str().unwrap().to_string();
    let (state, storage) = build_state(&dsn).await;
    // 禁用 is_active 缓存,保证"停用后立即 401"不依赖 TTL。
    storage.set_active_cache_ttl(Duration::ZERO);
    seed_user(&state, "root", ADMIN_PW, Role::Admin).await;
    seed_user(&state, "root2", ADMIN2_PW, Role::Admin).await;
    seed_user(&state, "victim", VICTIM_PW, Role::User).await;
    seed_user(&state, "auditor1", "auditorpass12", Role::Auditor).await;
    seed_user(&state, "guest1", "guestpass1234", Role::Guest).await;
    let router = api::create_router(state.clone());
    Fixture {
        router,
        state,
        dsn,
        _dir: dir,
    }
}

fn password_of(user: &str) -> &'static str {
    match user {
        "root" => ADMIN_PW,
        "root2" => ADMIN2_PW,
        "victim" => VICTIM_PW,
        "auditor1" => "auditorpass12",
        "guest1" => "guestpass1234",
        other => panic!("未知测试用户 {}", other),
    }
}

fn delete(uri: &str, token: Option<&str>) -> Request<Body> {
    let mut b = Request::builder().method("DELETE").uri(uri);
    if let Some(t) = token {
        b = b.header("authorization", format!("Bearer {}", t));
    }
    b.body(Body::empty()).unwrap()
}

impl Fixture {
    async fn login_raw(
        &self,
        user: &str,
        password: &str,
        peer: Option<&str>,
    ) -> (StatusCode, Value) {
        let mut req = post(
            "/api/v1/auth/login",
            None,
            json!({"username": user, "password": password}),
        );
        if let Some(peer) = peer {
            let peer: SocketAddr = peer.parse().unwrap();
            req.extensions_mut().insert(ConnectInfo(peer));
        }
        let resp = self.router.clone().oneshot(req).await.unwrap();
        (resp.status(), body_json(resp).await)
    }

    async fn login_from(&self, user: &str, peer: Option<&str>) -> Tokens {
        let (status, body) = self.login_raw(user, password_of(user), peer).await;
        assert_eq!(status, StatusCode::OK, "登录 {} 应成功: {}", user, body);
        let access = body["data"]["token"].as_str().unwrap().to_string();
        let refresh = body["data"]["refresh_token"].as_str().unwrap().to_string();
        let sid = self
            .state
            .auth_service
            .validate_token(&access)
            .unwrap()
            .sid
            .expect("登录签发的 access 应带 sid");
        Tokens {
            access,
            refresh,
            sid,
        }
    }

    async fn login(&self, user: &str) -> Tokens {
        self.login_from(user, None).await
    }

    async fn send(&self, req: Request<Body>) -> (StatusCode, Value) {
        let resp = self.router.clone().oneshot(req).await.unwrap();
        (resp.status(), body_json(resp).await)
    }

    async fn status(&self, req: Request<Body>) -> StatusCode {
        self.router.clone().oneshot(req).await.unwrap().status()
    }

    async fn profile(&self, token: &str) -> StatusCode {
        self.status(get("/api/v1/auth/profile", Some(token))).await
    }

    async fn refresh(&self, refresh_token: &str) -> StatusCode {
        self.status(post(
            "/api/v1/auth/refresh",
            None,
            json!({"refresh_token": refresh_token}),
        ))
        .await
    }

    fn user_id(&self, name: &str) -> String {
        self.state.auth_service.get_user(name).unwrap().user_id
    }

    async fn events(&self) -> Vec<AuditEvent> {
        self.state.storage.list_audit_events(1000).await.unwrap()
    }

    async fn events_of(&self, event_type: &str) -> Vec<AuditEvent> {
        self.events()
            .await
            .into_iter()
            .filter(|e| e.event_type == event_type)
            .collect()
    }

    // 四个管理员接口的请求构造。
    fn list_sessions(&self, target: &str, token: Option<&str>) -> Request<Body> {
        get(&format!("/api/v1/admin/users/{}/sessions", target), token)
    }
    fn revoke_sessions(&self, target: &str, token: Option<&str>) -> Request<Body> {
        delete(&format!("/api/v1/admin/users/{}/sessions", target), token)
    }
    fn deactivate(&self, target: &str, token: Option<&str>) -> Request<Body> {
        post(
            &format!("/api/v1/admin/users/{}/deactivate", target),
            token,
            json!({}),
        )
    }
    fn activate(&self, target: &str, token: Option<&str>) -> Request<Body> {
        post(
            &format!("/api/v1/admin/users/{}/activate", target),
            token,
            json!({}),
        )
    }
}

// ---------- 权限 ----------

#[tokio::test]
async fn non_admin_roles_get_403_on_all_admin_endpoints() {
    let f = fixture().await;
    let victim_id = f.user_id("victim");
    let victim = f.login("victim").await;

    for name in ["victim", "auditor1", "guest1"] {
        let t = if name == "victim" {
            Tokens {
                access: victim.access.clone(),
                refresh: victim.refresh.clone(),
                sid: victim.sid.clone(),
            }
        } else {
            f.login(name).await
        };
        let reqs = [
            f.list_sessions(&victim_id, Some(&t.access)),
            f.revoke_sessions(&victim_id, Some(&t.access)),
            f.deactivate(&victim_id, Some(&t.access)),
            f.activate(&victim_id, Some(&t.access)),
        ];
        for req in reqs {
            let label = format!("{} {}", req.method(), req.uri());
            let status = f.status(req).await;
            assert_eq!(status, StatusCode::FORBIDDEN, "{} 用 {} 应 403", label, name);
        }
    }

    // 403 不产生副作用。
    assert_eq!(f.profile(&victim.access).await, StatusCode::OK);
    assert!(f.state.storage.is_user_active(&victim_id).await.unwrap());
    assert!(f.events_of("admin_sessions_listed").await.is_empty());
    assert!(f.events_of("admin_sessions_revoked").await.is_empty());
    assert!(f.events_of("user_deactivated").await.is_empty());
    assert!(f.events_of("user_activated").await.is_empty());
}

#[tokio::test]
async fn admin_endpoints_require_authentication() {
    let f = fixture().await;
    let id = f.user_id("victim");
    let reqs = [
        f.list_sessions(&id, None),
        f.revoke_sessions(&id, None),
        f.deactivate(&id, None),
        f.activate(&id, None),
    ];
    for req in reqs {
        let label = format!("{} {}", req.method(), req.uri());
        assert_eq!(f.status(req).await, StatusCode::UNAUTHORIZED, "{}", label);
    }
}

#[tokio::test]
async fn unknown_admin_subpath_fails_closed_for_non_admin() {
    let f = fixture().await;
    let admin = f.login("root").await;
    let victim = f.login("victim").await;
    let auditor = f.login("auditor1").await;
    let guest = f.login("guest1").await;

    for uri in [
        "/api/v1/admin/users/x/unknown",
        "/api/v1/admin/nothing-here",
    ] {
        for t in [&victim, &auditor, &guest] {
            assert_eq!(
                f.status(get(uri, Some(&t.access))).await,
                StatusCode::FORBIDDEN,
                "非管理员访问未实现的 {} 必须 403(fail-closed)",
                uri
            );
        }
        assert_eq!(
            f.status(get(uri, Some(&admin.access))).await,
            StatusCode::NOT_FOUND,
            "管理员访问未实现的 {} 返回 404",
            uri
        );
        assert_eq!(
            f.status(get(uri, None)).await,
            StatusCode::UNAUTHORIZED,
            "无 token 访问 {} 返回 401",
            uri
        );
    }
}

// ---------- GET sessions ----------

#[tokio::test]
async fn admin_lists_target_sessions_without_sensitive_fields() {
    let f = fixture().await;
    let admin = f.login("root").await;
    let first = f.login_from("victim", Some(PEER)).await;
    let second = f.login("victim").await;
    let victim_id = f.user_id("victim");
    let admin_id = f.user_id("root");

    let resp = f
        .router
        .clone()
        .oneshot(f.list_sessions(&victim_id, Some(&admin.access)))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_json(resp).await;
    let raw = serde_json::to_string(&body).unwrap();
    let items = body["data"].as_array().expect("data 应为 SessionView 数组");
    assert_eq!(items.len(), 2, "只列出目标用户的未撤销会话");
    let ids: Vec<&str> = items.iter().map(|s| s["id"].as_str().unwrap()).collect();
    assert!(ids.contains(&first.sid.as_str()) && ids.contains(&second.sid.as_str()));
    assert!(!ids.contains(&admin.sid.as_str()), "不应混入管理员自己的会话");

    for item in items {
        let obj = item.as_object().unwrap();
        for key in ["id", "current", "created_at", "last_seen_at", "expires_at"] {
            assert!(obj.contains_key(key), "SessionView 应含 {}", key);
        }
        assert_eq!(item["current"], false, "管理员视角 current 恒为 false");
        for forbidden in [
            "ip_hash",
            "refresh_family",
            "family",
            "token",
            "refresh_token",
            "jti",
            "user_agent",
            "revoke_reason",
            "revoked_at",
        ] {
            assert!(!obj.contains_key(forbidden), "不得暴露字段 {}", forbidden);
        }
    }
    let mine = items.iter().find(|s| s["id"] == first.sid.as_str()).unwrap();
    assert_eq!(mine["ip_hint"], "203.0.x.x");

    // 响应体不含任何 token / jti / family / ip_hash / 明文 IP。
    let session = f
        .state
        .storage
        .get_session(&first.sid)
        .await
        .unwrap()
        .unwrap();
    let jwt = JwtHandler::new(JWT_SECRET.to_string(), 24);
    let jti = jwt.parse_refresh_claims(&first.refresh).unwrap().jti;
    for secret in [
        session.ip_hash.clone().unwrap(),
        session.refresh_family.clone(),
        first.access.clone(),
        first.refresh.clone(),
        admin.access.clone(),
        jti,
        PLAIN_IP.to_string(),
    ] {
        assert!(!raw.contains(&secret), "响应不得包含 {}", secret);
    }

    let listed = f.events_of("admin_sessions_listed").await;
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].actor_user_id.as_deref(), Some(admin_id.as_str()));
    assert_eq!(listed[0].user_id.as_deref(), Some(victim_id.as_str()));
    assert_eq!(listed[0].result, "success");
}

#[tokio::test]
async fn admin_list_sessions_of_unknown_user_is_404() {
    let f = fixture().await;
    let admin = f.login("root").await;
    let (status, body) = f
        .send(f.list_sessions("no-such-user", Some(&admin.access)))
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(body["error"], "user not found");
    assert!(f.events_of("admin_sessions_listed").await.is_empty());
}

// ---------- DELETE sessions ----------

#[tokio::test]
async fn admin_revokes_all_target_sessions_and_is_idempotent() {
    let f = fixture().await;
    let admin = f.login("root").await;
    let v1 = f.login("victim").await;
    let v2 = f.login("victim").await;
    let victim_id = f.user_id("victim");
    let admin_id = f.user_id("root");
    assert_eq!(f.profile(&v1.access).await, StatusCode::OK);

    let (status, body) = f
        .send(f.revoke_sessions(&victim_id, Some(&admin.access)))
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["data"], json!({"revoked": 2}));

    for t in [&v1, &v2] {
        assert_eq!(f.profile(&t.access).await, StatusCode::UNAUTHORIZED);
        assert_eq!(f.refresh(&t.refresh).await, StatusCode::UNAUTHORIZED);
    }
    // 管理员自身会话不受影响;目标用户仍是活跃状态,可重新登录。
    assert_eq!(f.profile(&admin.access).await, StatusCode::OK);
    assert_eq!(f.refresh(&admin.refresh).await, StatusCode::OK);
    assert!(f.state.storage.is_user_active(&victim_id).await.unwrap());
    let _ = f.login("victim").await;

    // 重复调用幂等:此时只剩刚登录的新会话,先撤销一次清空,再次调用得 0。
    let (status, body) = f
        .send(f.revoke_sessions(&victim_id, Some(&admin.access)))
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["data"]["revoked"], 1);
    let (status, body) = f
        .send(f.revoke_sessions(&victim_id, Some(&admin.access)))
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["data"], json!({"revoked": 0}));

    let rows = f.events_of("admin_sessions_revoked").await;
    assert_eq!(rows.len(), 3, "每次调用都应审计");
    let first_call = rows
        .iter()
        .find(|e| e.reason.as_deref() == Some("revoked 2 sessions"))
        .expect("应有 reason=`revoked 2 sessions` 的审计");
    assert_eq!(first_call.actor_user_id.as_deref(), Some(admin_id.as_str()));
    assert_eq!(first_call.user_id.as_deref(), Some(victim_id.as_str()));
    assert!(rows
        .iter()
        .any(|e| e.reason.as_deref() == Some("revoked 0 sessions")));
}

#[tokio::test]
async fn admin_revoke_sessions_of_unknown_user_is_404() {
    let f = fixture().await;
    let admin = f.login("root").await;
    let (status, body) = f
        .send(f.revoke_sessions("no-such-user", Some(&admin.access)))
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(body["error"], "user not found");
    assert!(f.events_of("admin_sessions_revoked").await.is_empty());
}

// ---------- deactivate ----------

#[tokio::test]
async fn admin_deactivates_user_revoking_sessions_idempotently() {
    let f = fixture().await;
    let admin = f.login("root").await;
    let v1 = f.login("victim").await;
    let v2 = f.login("victim").await;
    let victim_id = f.user_id("victim");
    let admin_id = f.user_id("root");

    let (status, body) = f.send(f.deactivate(&victim_id, Some(&admin.access))).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        body["data"],
        json!({"user_id": victim_id, "is_active": false, "revoked_sessions": 2})
    );

    // 目标无法登录,旧 token 全部失效。
    let (status, _) = f.login_raw("victim", VICTIM_PW, None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    for t in [&v1, &v2] {
        assert_eq!(f.profile(&t.access).await, StatusCode::UNAUTHORIZED);
        assert_eq!(f.refresh(&t.refresh).await, StatusCode::UNAUTHORIZED);
        let session = f.state.storage.get_session(&t.sid).await.unwrap().unwrap();
        assert!(session.revoked_at.is_some());
        assert_eq!(session.revoke_reason.as_deref(), Some("user deactivated"));
    }
    assert!(!f.state.storage.is_user_active(&victim_id).await.unwrap());
    assert_eq!(f.profile(&admin.access).await, StatusCode::OK);

    let rows = f.events_of("user_deactivated").await;
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].actor_user_id.as_deref(), Some(admin_id.as_str()));
    assert_eq!(rows[0].user_id.as_deref(), Some(victim_id.as_str()));

    // 幂等:再次停用成功且无会话可撤销。
    let (status, body) = f.send(f.deactivate(&victim_id, Some(&admin.access))).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        body["data"],
        json!({"user_id": victim_id, "is_active": false, "revoked_sessions": 0})
    );
    assert!(!f.state.storage.is_user_active(&victim_id).await.unwrap());
}

#[tokio::test]
async fn admin_cannot_deactivate_self() {
    let f = fixture().await;
    let admin = f.login("root").await;
    let admin_id = f.user_id("root");

    let (status, body) = f.send(f.deactivate(&admin_id, Some(&admin.access))).await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(body["error"], "cannot deactivate yourself");

    assert!(f.state.storage.is_user_active(&admin_id).await.unwrap());
    assert_eq!(f.profile(&admin.access).await, StatusCode::OK, "自己仍可用");
    assert_eq!(f.refresh(&admin.refresh).await, StatusCode::OK);
    let (status, _) = f.login_raw("root", ADMIN_PW, None).await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        f.events_of("user_deactivated").await.is_empty(),
        "自停用被拒不得写成功审计"
    );
}

#[tokio::test]
async fn deactivated_admin_token_is_rejected_immediately() {
    let f = fixture().await;
    let admin = f.login("root").await;
    let admin2 = f.login("root2").await;
    let admin2_id = f.user_id("root2");
    assert_eq!(f.profile(&admin2.access).await, StatusCode::OK);

    let (status, _) = f.send(f.deactivate(&admin2_id, Some(&admin.access))).await;
    assert_eq!(status, StatusCode::OK);

    assert_eq!(f.profile(&admin2.access).await, StatusCode::UNAUTHORIZED);
    let victim_id = f.user_id("victim");
    assert_eq!(
        f.status(f.list_sessions(&victim_id, Some(&admin2.access)))
            .await,
        StatusCode::UNAUTHORIZED,
        "被停用的管理员不能再调用管理员接口"
    );
    assert_eq!(f.refresh(&admin2.refresh).await, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn admin_deactivate_unknown_user_is_404() {
    let f = fixture().await;
    let admin = f.login("root").await;
    let (status, body) = f
        .send(f.deactivate("no-such-user", Some(&admin.access)))
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(body["error"], "user not found");
    assert!(f.events_of("user_deactivated").await.is_empty());
}

// ---------- activate ----------

#[tokio::test]
async fn admin_activates_user_without_restoring_old_sessions() {
    let f = fixture().await;
    let admin = f.login("root").await;
    let old = f.login("victim").await;
    let victim_id = f.user_id("victim");
    let admin_id = f.user_id("root");

    let (status, _) = f.send(f.deactivate(&victim_id, Some(&admin.access))).await;
    assert_eq!(status, StatusCode::OK);
    let (status, _) = f.login_raw("victim", VICTIM_PW, None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    let (status, body) = f.send(f.activate(&victim_id, Some(&admin.access))).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        body["data"],
        json!({"user_id": victim_id, "is_active": true})
    );
    assert!(f.state.storage.is_user_active(&victim_id).await.unwrap());

    // 旧会话不恢复,但可重新登录。
    assert_eq!(f.profile(&old.access).await, StatusCode::UNAUTHORIZED);
    assert_eq!(f.refresh(&old.refresh).await, StatusCode::UNAUTHORIZED);
    let fresh = f.login("victim").await;
    assert_eq!(f.profile(&fresh.access).await, StatusCode::OK);

    let rows = f.events_of("user_activated").await;
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].actor_user_id.as_deref(), Some(admin_id.as_str()));
    assert_eq!(rows[0].user_id.as_deref(), Some(victim_id.as_str()));

    // 幂等:对已启用用户再次启用仍 200。
    let (status, body) = f.send(f.activate(&victim_id, Some(&admin.access))).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["data"]["is_active"], true);
}

#[tokio::test]
async fn admin_activate_unknown_user_is_404() {
    let f = fixture().await;
    let admin = f.login("root").await;
    let (status, body) = f
        .send(f.activate("no-such-user", Some(&admin.access)))
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(body["error"], "user not found");
    assert!(f.events_of("user_activated").await.is_empty());
}

// ---------- 审计 actor / 迁移 / 脱敏 ----------

#[tokio::test]
async fn cli_path_audit_events_have_no_actor() {
    let f = fixture().await;
    let victim_id = f.user_id("victim");

    // CLI 路径使用原签名,不带操作者。
    f.state
        .auth_service
        .deactivate_user(&victim_id)
        .await
        .unwrap();
    f.state
        .auth_service
        .activate_user(&victim_id)
        .await
        .unwrap();

    let off = f.events_of("user_deactivated").await;
    let on = f.events_of("user_activated").await;
    assert_eq!(off.len(), 1);
    assert_eq!(on.len(), 1);
    assert!(off[0].actor_user_id.is_none(), "CLI 停用 actor 应为 None");
    assert!(on[0].actor_user_id.is_none(), "CLI 启用 actor 应为 None");
    assert_eq!(off[0].user_id.as_deref(), Some(victim_id.as_str()));
}

#[tokio::test]
async fn migration_013_adds_actor_user_id_column() {
    let f = fixture().await;
    let pool = sqlx::sqlite::SqlitePoolOptions::new()
        .max_connections(1)
        .connect(&format!("sqlite:{}?mode=rw", f.dsn))
        .await
        .unwrap();

    let columns: Vec<String> = sqlx::query("PRAGMA table_info(auth_audit_log)")
        .fetch_all(&pool)
        .await
        .unwrap()
        .iter()
        .map(|r| r.get::<String, _>("name"))
        .collect();
    assert!(
        columns.iter().any(|c| c == "actor_user_id"),
        "auth_audit_log 应有 actor_user_id 列,实际列: {:?}",
        columns
    );
    // 直接 SELECT 也应可用(列可空)。
    sqlx::query("SELECT actor_user_id FROM auth_audit_log LIMIT 1")
        .fetch_all(&pool)
        .await
        .unwrap();
}

#[tokio::test]
async fn admin_audit_dump_never_contains_secrets() {
    let f = fixture().await;
    let admin = f.login_from("root", Some(PEER)).await;
    let victim = f.login_from("victim", Some(PEER)).await;
    let victim_id = f.user_id("victim");

    assert_eq!(
        f.status(f.list_sessions(&victim_id, Some(&admin.access)))
            .await,
        StatusCode::OK
    );
    assert_eq!(
        f.status(f.revoke_sessions(&victim_id, Some(&admin.access)))
            .await,
        StatusCode::OK
    );
    assert_eq!(
        f.status(f.deactivate(&victim_id, Some(&admin.access)))
            .await,
        StatusCode::OK
    );
    assert_eq!(
        f.status(f.activate(&victim_id, Some(&admin.access))).await,
        StatusCode::OK
    );

    let jwt = JwtHandler::new(JWT_SECRET.to_string(), 24);
    let jtis = [
        jwt.parse_refresh_claims(&admin.refresh).unwrap().jti,
        jwt.parse_refresh_claims(&victim.refresh).unwrap().jti,
    ];
    let victim_family = f
        .state
        .storage
        .get_session(&victim.sid)
        .await
        .unwrap()
        .unwrap()
        .refresh_family;

    let dump = format!("{:?}", f.events().await);
    for ev in [
        "admin_sessions_listed",
        "admin_sessions_revoked",
        "user_deactivated",
        "user_activated",
    ] {
        assert!(dump.contains(ev), "应有审计事件 {},避免空表假阳性", ev);
    }
    let mut needles = vec![
        ADMIN_PW.to_string(),
        VICTIM_PW.to_string(),
        admin.access.clone(),
        admin.refresh.clone(),
        victim.access.clone(),
        victim.refresh.clone(),
        victim_family,
        PLAIN_IP.to_string(),
        "Bearer".to_string(),
    ];
    needles.extend(jtis);
    for needle in needles {
        assert!(!dump.contains(&needle), "审计表不得包含 {}", needle);
    }
}
