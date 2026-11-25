//! C2(B20/B21):已建立 WebSocket 连接的定时复核行为测试(TDD Red)。
//!
//! 实现前预期:用例 1-4 等不到服务端关闭而失败(当前连接从不复核),用例 5 通过。
//! 写法沿用 `websocket_integration.rs`:真实 axum 服务(随机端口)+ tokio-tungstenite 客户端。
//! 复核间隔经 `WsHub::set_revalidate_interval` 设为 200ms,保证各用例秒级完成。
//!
//! 判定口径:
//! - "被关闭":3 秒内从流上读到 Close 帧(close code 必须是 1008)或流结束;
//! - "保持":跨 1.5 秒(≥7 个复核间隔)未关闭,且随后发布的业务事件仍能收到。
mod common;

use std::time::Duration;

use common::{build_state, seed_user, JWT_SECRET};
use datachain::api::{self, AppState};
use datachain::auth::{Claims, Role};
use futures_util::StreamExt;
use jsonwebtoken::{encode, EncodingKey, Header};
use serde_json::{json, Value};
use tokio::net::TcpListener;
use tokio_tungstenite::connect_async;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode;
use tokio_tungstenite::tungstenite::Message as TMessage;

const REVALIDATE: Duration = Duration::from_millis(200);
const CLOSE_WITHIN: Duration = Duration::from_secs(3);
const HOLD_FOR: Duration = Duration::from_millis(1500);

const USER_PW: &str = "wspass123456";
const ADMIN_PW: &str = "adminpass1234";
const NEW_PW: &str = "brand-new-pass-456";

struct TestServer {
    addr: std::net::SocketAddr,
    state: AppState,
    _handle: tokio::task::JoinHandle<()>,
}

/// 启动真实服务,复核间隔设为 200ms。
async fn start_server() -> TestServer {
    let dir = tempfile::tempdir().unwrap().keep();
    let dsn = dir.join("ws-revalidate.db");
    let (state, _storage) = build_state(dsn.to_str().unwrap()).await;
    state.ws_hub.set_revalidate_interval(REVALIDATE);

    let app = api::create_router(state.clone());
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    tokio::time::sleep(Duration::from_millis(50)).await;
    TestServer {
        addr,
        state,
        _handle: handle,
    }
}

async fn login_token(server: &TestServer, username: &str, password: &str) -> String {
    let resp = reqwest::Client::new()
        .post(format!("http://{}/api/v1/auth/login", server.addr))
        .json(&json!({"username": username, "password": password}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "登录应成功: {}", username);
    let body: Value = resp.json().await.unwrap();
    body["data"]["token"].as_str().unwrap().to_string()
}

/// 带 Bearer 的 POST,返回状态码。
async fn http_post(server: &TestServer, path: &str, token: &str, body: Value) -> u16 {
    reqwest::Client::new()
        .post(format!("http://{}{}", server.addr, path))
        .bearer_auth(token)
        .json(&body)
        .send()
        .await
        .unwrap()
        .status()
        .as_u16()
}

/// 建立 /ws 连接并读掉 welcome。
async fn connect_ws(
    server: &TestServer,
    token: &str,
) -> tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>> {
    let mut req = format!("ws://{}/ws", server.addr)
        .into_client_request()
        .unwrap();
    req.headers_mut()
        .insert("authorization", format!("Bearer {}", token).parse().unwrap());
    let (mut ws, _) = connect_async(req).await.expect("WS 握手应成功");
    let welcome = next_text(&mut ws).await.expect("应收到 welcome");
    assert_eq!(welcome["type"], "pong");
    assert_eq!(welcome["data"]["message"], "connected");
    ws
}

type Ws =
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

/// 读下一条文本消息(3 秒超时)。Close/出错/超时均返回 None。
async fn next_text(ws: &mut Ws) -> Option<Value> {
    let fut = async {
        while let Some(msg) = ws.next().await {
            match msg {
                Ok(TMessage::Text(t)) => return serde_json::from_str::<Value>(&t).ok(),
                Ok(TMessage::Close(_)) | Err(_) => return None,
                _ => continue,
            }
        }
        None
    };
    tokio::time::timeout(CLOSE_WITHIN, fut).await.ok().flatten()
}

/// 断言连接在 `within` 内被服务端关闭:读到 Close 帧(code 必须为 1008)或流结束。
async fn assert_closed_within(ws: &mut Ws, within: Duration, what: &str) {
    let fut = async {
        loop {
            match ws.next().await {
                Some(Ok(TMessage::Close(frame))) => {
                    let frame = frame.unwrap_or_else(|| panic!("{what}: Close 帧应带 code"));
                    assert_eq!(
                        frame.code,
                        CloseCode::Policy,
                        "{what}: close code 应为 1008(Policy),实际 {:?}",
                        frame.code
                    );
                    return;
                }
                // 流结束或连接被重置也视为已关闭。
                None | Some(Err(_)) => return,
                // 其他帧(Ping/Text 等)忽略,继续等待。
                Some(Ok(_)) => continue,
            }
        }
    };
    tokio::time::timeout(within, fut)
        .await
        .unwrap_or_else(|_| panic!("{what}: {:?} 内应被服务端关闭,但连接仍保持", within));
}

/// 断言连接跨 `HOLD_FOR` 保持,且随后发布的业务事件仍能收到。
async fn assert_stays_open_and_receives_event(server: &TestServer, ws: &mut Ws, what: &str) {
    let hold = async {
        loop {
            match ws.next().await {
                Some(Ok(TMessage::Close(f))) => panic!("{what}: 不应被关闭,收到 Close {:?}", f),
                None => panic!("{what}: 不应被关闭,流已结束"),
                Some(Err(e)) => panic!("{what}: 不应被关闭,流出错 {e:?}"),
                Some(Ok(TMessage::Text(t))) => panic!("{what}: 保持期间不应有文本消息: {t}"),
                Some(Ok(_)) => continue,
            }
        }
    };
    // 超时即表示整个保持窗口内没有关闭,符合预期。
    let _ = tokio::time::timeout(HOLD_FOR, hold).await;

    server
        .state
        .event_bus
        .publish_block_mined(json!({"index": 7, "hash": "keep-open"}));
    let ev = next_text(ws)
        .await
        .unwrap_or_else(|| panic!("{what}: 保持窗口后应仍能收到业务事件"));
    assert_eq!(ev["type"], "block_added", "{what}");
    assert_eq!(ev["data"]["index"], 7, "{what}");
}

// ---------------------------------------------------------------------------
// 用例
// ---------------------------------------------------------------------------

/// 1. 登出后连接被关闭(1008)。
#[tokio::test]
async fn ws_closed_after_logout() {
    let server = start_server().await;
    seed_user(&server.state, "wsuser", USER_PW, Role::User).await;
    let access = login_token(&server, "wsuser", USER_PW).await;
    let mut ws = connect_ws(&server, &access).await;

    assert_eq!(
        http_post(&server, "/api/v1/auth/logout", &access, json!({})).await,
        204,
        "登出应成功(handlers::logout 返回 204 No Content)"
    );
    assert_closed_within(&mut ws, CLOSE_WITHIN, "登出后").await;
}

/// 2. 管理员经 HTTP 停用用户后,其连接被关闭(1008)。
#[tokio::test]
async fn ws_closed_after_admin_deactivates_user() {
    let server = start_server().await;
    seed_user(&server.state, "wsuser", USER_PW, Role::User).await;
    seed_user(&server.state, "wsadmin", ADMIN_PW, Role::Admin).await;
    let user_token = login_token(&server, "wsuser", USER_PW).await;
    let admin_token = login_token(&server, "wsadmin", ADMIN_PW).await;
    let mut ws = connect_ws(&server, &user_token).await;

    let user_id = server.state.auth_service.get_user("wsuser").unwrap().user_id;
    let status = http_post(
        &server,
        &format!("/api/v1/admin/users/{}/deactivate", user_id),
        &admin_token,
        json!({}),
    )
    .await;
    assert_eq!(status, 200, "管理员停用应成功");
    assert_closed_within(&mut ws, CLOSE_WITHIN, "停用后").await;
}

/// 3. 改密:会话 A 改密后,会话 B 的连接被关闭(1008),会话 A 的连接保持并收到事件。
#[tokio::test]
async fn ws_change_password_closes_other_session_keeps_current() {
    let server = start_server().await;
    seed_user(&server.state, "wsuser", USER_PW, Role::User).await;
    let a = login_token(&server, "wsuser", USER_PW).await;
    let b = login_token(&server, "wsuser", USER_PW).await;
    let mut ws_a = connect_ws(&server, &a).await;
    let mut ws_b = connect_ws(&server, &b).await;

    let status = http_post(
        &server,
        "/api/v1/auth/password",
        &a,
        json!({"old_password": USER_PW, "new_password": NEW_PW}),
    )
    .await;
    assert_eq!(status, 204, "改密应成功");

    assert_closed_within(&mut ws_b, CLOSE_WITHIN, "改密后其他会话 B").await;
    assert_stays_open_and_receives_event(&server, &mut ws_a, "改密后当前会话 A").await;
}

/// 4. access 令牌过期后连接被关闭(1008)。
///
/// 构造:真实登录得到带 `sid` 的 access,解码出 Claims,仅把 `exp` 改为 now+2 秒,
/// 用与服务相同的 JWT_SECRET 重新签名(iss/aud/sub/role/sid 全部沿用,会话在库中仍有效)。
/// 握手在 exp 之前完成(登录与握手相隔毫秒级);之后唯一失效原因是令牌过期。
#[tokio::test]
async fn ws_closed_after_access_token_expires() {
    let server = start_server().await;
    seed_user(&server.state, "wsuser", USER_PW, Role::User).await;
    let access = login_token(&server, "wsuser", USER_PW).await;

    let mut claims: Claims = server.state.auth_service.validate_token(&access).unwrap();
    assert!(claims.sid.is_some(), "登录签发的 access 应带 sid");
    claims.exp = chrono::Utc::now().timestamp() + 2;
    let short = encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(JWT_SECRET.as_bytes()),
    )
    .unwrap();

    let mut ws = connect_ws(&server, &short).await;
    assert_closed_within(&mut ws, Duration::from_secs(4), "令牌过期后").await;
}

/// 5. 健康连接(无任何撤销)跨多个复核间隔保持,并仍能收到事件(回归)。
#[tokio::test]
async fn ws_healthy_connection_stays_open_across_revalidations() {
    let server = start_server().await;
    seed_user(&server.state, "wsuser", USER_PW, Role::User).await;
    let access = login_token(&server, "wsuser", USER_PW).await;
    let mut ws = connect_ws(&server, &access).await;

    assert_stays_open_and_receives_event(&server, &mut ws, "健康连接").await;
}
