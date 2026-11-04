//! WebSocket 实时事件集成测试(backlog #4)。
//!
//! 为什么不复用 api_integration.rs 的 tower oneshot:
//! `WebSocketUpgrade` 依赖真实的 HTTP/1.1 Upgrade 握手与底层 I/O 的 on_upgrade,
//! tower `oneshot` 进程内驱动 Router 无法完成真实的协议升级和双向帧收发。
//! 因此本套测试启动真实服务(TcpListener 绑定随机端口)+ tokio-tungstenite 客户端,
//! 对握手鉴权、EventBus 广播收消息、连接数上限、消息大小上限做自动化断言。
//!
//! 频道隔离说明:
//! `/ws` 继续接收全部业务事件；`/ws/chain` 仅接收 `block_added`、`chain_validated`，
//! `/ws/metadata` 仅接收 `metadata_added`，`/ws/aggregation` 仅接收 `aggregation`。
//! `version_tracked` 和未映射的未来业务消息只投递到通用 `/ws`。

use std::sync::Arc;
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use serde_json::Value;
use tokio::net::TcpListener;
use tokio_tungstenite::connect_async;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::http::StatusCode as WsStatus;
use tokio_tungstenite::tungstenite::Message as TMessage;

use datachain::aggregation::{create_aggregation_engine, create_scheduler};
use datachain::api::{self, AppState, Event, EventBus, EventType, NotificationService, WsHub};
use datachain::auth::{create_auth_service, RegisterRequest, Role};
use datachain::core::create_chain;
use datachain::crosschain::AnchorService;
use datachain::metadata::create_metadata_manager;
use datachain::node_signing::NodeIdentity;
use datachain::storage::create_storage;

const JWT_SECRET: &str = "ws-integration-test-secret-key-0123456789-abcdef";

/// 服务端单进程 WebSocket 连接上限(与 src/api/websocket.rs 的 `MAX_WS_CLIENTS` 对齐)。
/// 该常量在 src 里是私有的、未导出,这里在测试侧镜像一份,避免引入对私有项的依赖;
/// 若服务端上限调整,此处需同步更新。
const MAX_WS_CLIENTS: usize = 256;

/// 构建完整 AppState(内存库即可,WS 测试不依赖持久化)。
async fn build_state(dsn: &str) -> AppState {
    let storage = create_storage(dsn).await.unwrap();

    let chain = create_chain(2, 100);
    let blocks = storage.get_all_blocks().await.unwrap();
    if blocks.is_empty() {
        let genesis = chain.init();
        storage.save_block(&genesis).await.unwrap();
    } else {
        chain.load_blocks(blocks);
    }

    let auth_service = create_auth_service(JWT_SECRET.to_string(), 24, storage.clone());
    for user in storage.get_all_users().await.unwrap() {
        auth_service.load_user(user);
    }

    let metadata_manager = create_metadata_manager(chain.clone(), storage.clone());
    let version_tracker = {
        let dir = tempfile::tempdir().unwrap().keep();
        Arc::new(datachain::versioning::VersionTracker::new_with_content_dir(dir).unwrap())
    };
    let aggregation_engine = create_aggregation_engine(chain.clone(), 3600, 100);
    for summary in storage.get_all_aggregations().await.unwrap() {
        aggregation_engine.load_aggregation(summary);
    }

    let ws_hub = WsHub::new();
    let notification = Arc::new(NotificationService::new(ws_hub.clone()));
    let event_bus = Arc::new(EventBus::new(notification));
    let scheduler = create_scheduler(aggregation_engine.clone(), 3600);
    let p2p = datachain::p2p::P2PService::with_node_id("ws-test-node");
    // WS 测试需要在短时间内从同一 IP 发起数百次握手(连接数上限用例要开 256 个连接),
    // 默认限流器(120/60s)会误伤;这里放宽限流,限流本身另有专门用例覆盖。
    let rate_limiter = Arc::new(api::RateLimiter::new(
        1_000_000,
        1_000_000,
        std::time::Duration::from_secs(60),
    ));
    let anchor_service = Arc::new(AnchorService::new(
        Arc::new(NodeIdentity::generate("ws-test-node")),
        "datachain-ws-test",
        storage.clone(),
        None,
    ));

    AppState {
        chain,
        auth_service,
        metadata_manager,
        version_tracker,
        aggregation_engine,
        storage,
        ws_hub,
        event_bus,
        scheduler,
        p2p,
        rate_limiter,
        anchor_service,
        claim_resolver: Arc::new(datachain::catalog::ClaimResolver::new(Default::default())),
    }
}

async fn seed_user(state: &AppState, username: &str, password: &str, role: Role) {
    let req = RegisterRequest {
        username: username.to_string(),
        password: password.to_string(),
        email: format!("{}@ws.local", username),
        role: Some(role),
    };
    let user = state.auth_service.register_with_role(&req, role).unwrap();
    state.storage.save_user(&user).await.unwrap();
}

/// 已启动的测试服务句柄:暴露监听地址和 AppState(便于测试直接 publish 事件)。
struct TestServer {
    addr: std::net::SocketAddr,
    state: AppState,
    _handle: tokio::task::JoinHandle<()>,
}

/// 启动真实 axum 服务,绑定 127.0.0.1 随机端口。
async fn start_server() -> TestServer {
    // tempdir 会在离开作用域时删库;WS 测试运行期间要保留文件,故 keep() 保留目录。
    let dir = tempfile::tempdir().unwrap().keep();
    let dsn = dir.join("ws.db");
    let state = build_state(dsn.to_str().unwrap()).await;

    let app = api::create_router(state.clone());
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    // 给服务器一点时间进入 accept 循环。
    tokio::time::sleep(Duration::from_millis(50)).await;

    TestServer {
        addr,
        state,
        _handle: handle,
    }
}

/// 通过 HTTP login 拿一个合法 access token。
async fn login_token(addr: &std::net::SocketAddr, username: &str, password: &str) -> String {
    let url = format!("http://{}/api/v1/auth/login", addr);
    let client = reqwest::Client::new();
    let resp = client
        .post(&url)
        .json(&serde_json::json!({"username": username, "password": password}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "登录应成功");
    let body: Value = resp.json().await.unwrap();
    body["data"]["token"].as_str().unwrap().to_string()
}

type WsHandshakeRequest = tokio_tungstenite::tungstenite::http::Request<()>;

/// 构造带 Authorization 头的 WS 握手请求。
fn ws_request(addr: &std::net::SocketAddr, path: &str, token: Option<&str>) -> WsHandshakeRequest {
    let url = format!("ws://{}{}", addr, path);
    let mut req = url.into_client_request().unwrap();
    if let Some(t) = token {
        req.headers_mut()
            .insert("authorization", format!("Bearer {}", t).parse().unwrap());
    }
    req
}

/// 从 WS 流读下一条文本消息,带超时。
///
/// 注意:本函数把"超时"、"收到 Close 帧"、"流出错"三种情况**统一归一为 `None`**,
/// 三者无法区分。正向用例里用 `.expect("...")` 把 `None` 变成 panic 是没问题的
/// (收不到期望消息就该失败);但它**不适合直接用于负向断言**——例如想断言"连接被服务端
/// 关闭",`None` 既可能是真的 Close,也可能只是读超时,语义不够精确。需要精确区分
/// Close/超时的负向场景,应直接匹配底层 `TMessage` 帧(见 `channel_oversized_message_closes_without_error`)。
async fn next_text<S>(ws: &mut S) -> Option<Value>
where
    S: StreamExt<Item = Result<TMessage, tokio_tungstenite::tungstenite::Error>> + Unpin,
{
    let fut = async {
        while let Some(msg) = ws.next().await {
            match msg {
                Ok(TMessage::Text(t)) => {
                    return serde_json::from_str::<Value>(&t).ok();
                }
                Ok(TMessage::Close(_)) | Err(_) => return None,
                _ => continue,
            }
        }
        None
    };
    tokio::time::timeout(Duration::from_secs(3), fut)
        .await
        .ok()
        .flatten()
}

/// 在指定窗口内断言连接未收到文本消息。
async fn assert_no_text_within<S>(ws: &mut S, within: Duration, channel: &str)
where
    S: StreamExt<Item = Result<TMessage, tokio_tungstenite::tungstenite::Error>> + Unpin,
{
    let no_text = async {
        while let Some(frame) = ws.next().await {
            match frame {
                Ok(TMessage::Text(text)) => {
                    panic!("{channel} 不应收到文本消息,却收到: {text}");
                }
                Ok(TMessage::Close(_)) | Err(_) => return,
                Ok(_) => continue,
            }
        }
    };
    let _ = tokio::time::timeout(within, no_text).await;
}

// ---------------------------------------------------------------------------
// 验收点 1:WS 握手必须带有效 JWT
// ---------------------------------------------------------------------------

#[tokio::test]
async fn ws_handshake_without_token_is_rejected() {
    let server = start_server().await;
    let req = ws_request(&server.addr, "/ws", None);
    let result = connect_async(req).await;
    match result {
        Ok(_) => panic!("无 token 的 WS 握手不应升级成功"),
        Err(tokio_tungstenite::tungstenite::Error::Http(resp)) => {
            assert_eq!(
                resp.status(),
                WsStatus::UNAUTHORIZED,
                "无 token 应返回 401 而非 101"
            );
        }
        Err(e) => panic!("期望 HTTP 401,实际错误: {e:?}"),
    }
}

#[tokio::test]
async fn ws_handshake_with_invalid_token_is_rejected() {
    let server = start_server().await;
    let req = ws_request(&server.addr, "/ws", Some("not-a-valid-jwt"));
    let result = connect_async(req).await;
    match result {
        Ok(_) => panic!("无效 token 的 WS 握手不应升级成功"),
        Err(tokio_tungstenite::tungstenite::Error::Http(resp)) => {
            assert_eq!(
                resp.status(),
                WsStatus::UNAUTHORIZED,
                "无效 token 应返回 401 而非 101"
            );
        }
        Err(e) => panic!("期望 HTTP 401,实际错误: {e:?}"),
    }
}

#[tokio::test]
async fn ws_handshake_with_valid_token_succeeds() {
    let server = start_server().await;
    seed_user(&server.state, "wsuser", "wspass123456", Role::User).await;
    let token = login_token(&server.addr, "wsuser", "wspass123456").await;

    let req = ws_request(&server.addr, "/ws", Some(&token));
    let (mut ws, resp) = connect_async(req).await.expect("合法 token 的握手应成功");
    assert_eq!(
        resp.status(),
        WsStatus::SWITCHING_PROTOCOLS,
        "合法 token 握手应返回 101"
    );

    // 连接后服务端会先推一条 welcome(Pong + connected)。
    let welcome = next_text(&mut ws).await.expect("应收到 welcome 消息");
    assert_eq!(welcome["type"], "pong");
    assert_eq!(welcome["data"]["message"], "connected");
}

// ---------------------------------------------------------------------------
// 验收点 2:业务事件经 EventBus 发布后,订阅的 WS 客户端能收到对应消息
// ---------------------------------------------------------------------------

#[tokio::test]
async fn event_bus_block_mined_broadcasts_to_ws_clients() {
    let server = start_server().await;
    seed_user(&server.state, "wsuser", "wspass123456", Role::User).await;
    let token = login_token(&server.addr, "wsuser", "wspass123456").await;

    // 同时连 /ws(默认)与 /ws/chain(链频道),两者都订阅同一 WsHub。
    let (mut ws_default, _) = connect_async(ws_request(&server.addr, "/ws", Some(&token)))
        .await
        .unwrap();
    let (mut ws_chain, _) = connect_async(ws_request(&server.addr, "/ws/chain", Some(&token)))
        .await
        .unwrap();

    // 读掉各自的 welcome(/ws 是 pong,/ws/chain 是 subscribe)。
    let w1 = next_text(&mut ws_default).await.expect("默认频道 welcome");
    assert_eq!(w1["type"], "pong");
    let w2 = next_text(&mut ws_chain).await.expect("链频道 welcome");
    assert_eq!(w2["type"], "subscribe");

    // 经 EventBus 发布区块挖掘事件,等价于 handler 挖矿后的广播。
    server
        .state
        .event_bus
        .publish_block_mined(serde_json::json!({
            "index": 42,
            "hash": "abc123"
        }));

    // 两个客户端都应收到 block_added。
    let m1 = next_text(&mut ws_default)
        .await
        .expect("默认频道应收到 block_added");
    assert_eq!(m1["type"], "block_added", "消息类型应为 block_added");
    assert_eq!(m1["data"]["index"], 42);
    assert_eq!(m1["data"]["hash"], "abc123");

    let m2 = next_text(&mut ws_chain)
        .await
        .expect("链频道应收到 block_added");
    assert_eq!(m2["type"], "block_added");
    assert_eq!(m2["data"]["index"], 42);
}

#[tokio::test]
async fn event_bus_metadata_and_aggregation_broadcast() {
    let server = start_server().await;
    seed_user(&server.state, "wsuser", "wspass123456", Role::User).await;
    let token = login_token(&server.addr, "wsuser", "wspass123456").await;

    let (mut ws, _) = connect_async(ws_request(&server.addr, "/ws", Some(&token)))
        .await
        .unwrap();
    let _welcome = next_text(&mut ws).await.expect("welcome");

    // 元数据创建事件 -> metadata_added
    server
        .state
        .event_bus
        .publish_metadata_created(serde_json::json!({"data_id": "d-1"}));
    let m = next_text(&mut ws).await.expect("应收到 metadata_added");
    assert_eq!(m["type"], "metadata_added");
    assert_eq!(m["data"]["data_id"], "d-1");

    // 汇总完成事件 -> aggregation
    server
        .state
        .event_bus
        .publish_aggregation_done(serde_json::json!({"count": 7}));
    let a = next_text(&mut ws).await.expect("应收到 aggregation");
    assert_eq!(a["type"], "aggregation");
    assert_eq!(a["data"]["count"], 7);
}

#[tokio::test]
async fn event_bus_events_are_isolated_to_specialized_ws_channels() {
    let server = start_server().await;
    seed_user(&server.state, "wsuser", "wspass123456", Role::User).await;
    let token = login_token(&server.addr, "wsuser", "wspass123456").await;

    let (mut ws_default, _) = connect_async(ws_request(&server.addr, "/ws", Some(&token)))
        .await
        .unwrap();
    let (mut ws_chain, _) = connect_async(ws_request(&server.addr, "/ws/chain", Some(&token)))
        .await
        .unwrap();
    let (mut ws_metadata, _) =
        connect_async(ws_request(&server.addr, "/ws/metadata", Some(&token)))
            .await
            .unwrap();
    let (mut ws_aggregation, _) =
        connect_async(ws_request(&server.addr, "/ws/aggregation", Some(&token)))
            .await
            .unwrap();

    assert_eq!(next_text(&mut ws_default).await.unwrap()["type"], "pong");
    assert_eq!(next_text(&mut ws_chain).await.unwrap()["type"], "subscribe");
    assert_eq!(
        next_text(&mut ws_metadata).await.unwrap()["type"],
        "subscribe"
    );
    assert_eq!(
        next_text(&mut ws_aggregation).await.unwrap()["type"],
        "subscribe"
    );

    server
        .state
        .event_bus
        .publish_block_mined(serde_json::json!({"event_id": "block-mined"}));
    let message = next_text(&mut ws_default)
        .await
        .expect("通用频道应收到 block_added");
    assert_eq!(message["type"], "block_added");
    assert_eq!(message["data"]["event_id"], "block-mined");
    let message = next_text(&mut ws_chain)
        .await
        .expect("链频道应收到 block_added");
    assert_eq!(message["type"], "block_added");
    assert_eq!(message["data"]["event_id"], "block-mined");
    assert_no_text_within(&mut ws_metadata, Duration::from_millis(200), "/ws/metadata").await;
    assert_no_text_within(
        &mut ws_aggregation,
        Duration::from_millis(200),
        "/ws/aggregation",
    )
    .await;

    server.state.event_bus.publish(Event::new(
        EventType::ChainValidated,
        serde_json::json!({"event_id": "chain-validated"}),
    ));
    let message = next_text(&mut ws_default)
        .await
        .expect("通用频道应收到 chain_validated");
    assert_eq!(message["type"], "chain_validated");
    assert_eq!(message["data"]["event_id"], "chain-validated");
    let message = next_text(&mut ws_chain)
        .await
        .expect("链频道应收到 chain_validated");
    assert_eq!(message["type"], "chain_validated");
    assert_eq!(message["data"]["event_id"], "chain-validated");
    assert_no_text_within(&mut ws_metadata, Duration::from_millis(200), "/ws/metadata").await;
    assert_no_text_within(
        &mut ws_aggregation,
        Duration::from_millis(200),
        "/ws/aggregation",
    )
    .await;

    server
        .state
        .event_bus
        .publish_metadata_created(serde_json::json!({"event_id": "metadata-created"}));
    let message = next_text(&mut ws_default)
        .await
        .expect("通用频道应收到 metadata_added");
    assert_eq!(message["type"], "metadata_added");
    assert_eq!(message["data"]["event_id"], "metadata-created");
    let message = next_text(&mut ws_metadata)
        .await
        .expect("元数据频道应收到 metadata_added");
    assert_eq!(message["type"], "metadata_added");
    assert_eq!(message["data"]["event_id"], "metadata-created");
    assert_no_text_within(&mut ws_chain, Duration::from_millis(200), "/ws/chain").await;
    assert_no_text_within(
        &mut ws_aggregation,
        Duration::from_millis(200),
        "/ws/aggregation",
    )
    .await;

    server
        .state
        .event_bus
        .publish_aggregation_done(serde_json::json!({"event_id": "aggregation-done"}));
    let message = next_text(&mut ws_default)
        .await
        .expect("通用频道应收到 aggregation");
    assert_eq!(message["type"], "aggregation");
    assert_eq!(message["data"]["event_id"], "aggregation-done");
    let message = next_text(&mut ws_aggregation)
        .await
        .expect("汇总频道应收到 aggregation");
    assert_eq!(message["type"], "aggregation");
    assert_eq!(message["data"]["event_id"], "aggregation-done");
    assert_no_text_within(&mut ws_chain, Duration::from_millis(200), "/ws/chain").await;
    assert_no_text_within(&mut ws_metadata, Duration::from_millis(200), "/ws/metadata").await;

    server.state.event_bus.publish(Event::new(
        EventType::VersionTracked,
        serde_json::json!({"event_id": "version-tracked"}),
    ));
    let message = next_text(&mut ws_default)
        .await
        .expect("通用频道应收到 version_tracked");
    assert_eq!(message["type"], "version_tracked");
    assert_eq!(message["data"]["event_id"], "version-tracked");
    assert_no_text_within(&mut ws_chain, Duration::from_millis(200), "/ws/chain").await;
    assert_no_text_within(&mut ws_metadata, Duration::from_millis(200), "/ws/metadata").await;
    assert_no_text_within(
        &mut ws_aggregation,
        Duration::from_millis(200),
        "/ws/aggregation",
    )
    .await;
}

// ---------------------------------------------------------------------------
// 验收点 3a:单条消息大小上限(16 KiB)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn ws_oversized_message_triggers_error_and_close() {
    let server = start_server().await;
    seed_user(&server.state, "wsuser", "wspass123456", Role::User).await;
    let token = login_token(&server.addr, "wsuser", "wspass123456").await;

    let (mut ws, _) = connect_async(ws_request(&server.addr, "/ws", Some(&token)))
        .await
        .unwrap();
    let _welcome = next_text(&mut ws).await.expect("welcome");

    // 发送 > 16 KiB 的文本消息。
    let big = "x".repeat(16 * 1024 + 1);
    ws.send(TMessage::Text(big)).await.unwrap();

    // 服务端应回一条 error 消息(message too large)后断开。
    let err = next_text(&mut ws).await.expect("应收到 error 消息");
    assert_eq!(err["type"], "error", "超限消息应触发 error 响应");
    assert_eq!(err["data"]["error"], "message too large");
}

/// 频道 socket(/ws/chain 等)对超限消息的行为与 /ws 不同:
/// `handle_channel_socket` 只 `break` 断开连接,**不**回 "message too large" 的 error 消息
/// (对比 `handle_socket` 会先回 error 再 break)。这是两条处理路径之间已知的、刻意保留的
/// 设计差异——此用例锁定的正是"频道超限只断开、不回 error"这一行为,而非 /ws 的"先回 error"。
#[tokio::test]
async fn channel_oversized_message_closes_without_error() {
    let server = start_server().await;
    seed_user(&server.state, "wsuser", "wspass123456", Role::User).await;
    let token = login_token(&server.addr, "wsuser", "wspass123456").await;

    let (mut ws, _) = connect_async(ws_request(&server.addr, "/ws/chain", Some(&token)))
        .await
        .unwrap();
    // 频道 welcome 是 subscribe(不是 /ws 的 pong)。
    let welcome = next_text(&mut ws).await.expect("链频道 welcome");
    assert_eq!(welcome["type"], "subscribe");

    // 发送 > 16 KiB 的文本消息。
    let big = "x".repeat(16 * 1024 + 1);
    ws.send(TMessage::Text(big)).await.unwrap();

    // 断言:服务端直接关闭连接,不会先回任何 error 文本消息。
    // 这里不能用 next_text(它把超时/Close/Err 都归一为 None,无法区分),
    // 必须直接匹配底层帧,精确断言"收到 Close 帧或流结束,且期间没有任何 Text 帧"。
    let closed = async {
        while let Some(frame) = ws.next().await {
            match frame {
                // 收到 Close 帧 => 连接被服务端关闭,符合预期。
                Ok(TMessage::Close(_)) => return true,
                // 关键:绝不应该收到 Text(尤其不是 error 消息)。
                Ok(TMessage::Text(t)) => {
                    panic!("频道超限不应回任何文本消息,却收到: {t}");
                }
                // Ping/Pong/Binary 等中间帧忽略,继续等关闭。
                Ok(_) => continue,
                // 底层读错误通常也意味着连接已断,视为已关闭。
                Err(_) => return true,
            }
        }
        // 流自然结束(None)同样表示连接已关闭。
        true
    };
    let was_closed = tokio::time::timeout(Duration::from_secs(3), closed)
        .await
        .expect("服务端应在超时前关闭频道连接");
    assert!(was_closed, "频道超限消息应导致服务端关闭连接");
}

// ---------------------------------------------------------------------------
// 验收点 3b:连接数上限(256)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn ws_connection_limit_rejects_overflow() {
    let server = start_server().await;
    seed_user(&server.state, "wsuser", "wspass123456", Role::User).await;
    let token = login_token(&server.addr, "wsuser", "wspass123456").await;

    // 保持 MAX_WS_CLIENTS 个连接打开(达到上限)。
    let mut conns = Vec::new();
    for i in 0..MAX_WS_CLIENTS {
        let (mut ws, resp) = connect_async(ws_request(&server.addr, "/ws", Some(&token)))
            .await
            .unwrap_or_else(|e| panic!("第 {i} 个连接应成功,实际: {e:?}"));
        assert_eq!(resp.status(), WsStatus::SWITCHING_PROTOCOLS);
        // 读掉 welcome,确保连接已被服务端计数(try_add_client 已执行)。
        let _ = next_text(&mut ws).await;
        conns.push(ws);
    }
    assert_eq!(
        server.state.ws_hub.get_client_count(),
        MAX_WS_CLIENTS,
        "应已有 MAX_WS_CLIENTS 个在线连接"
    );

    // 第 257 个连接应被拒(503,升级前返回)。
    let result = connect_async(ws_request(&server.addr, "/ws", Some(&token))).await;
    match result {
        Ok(_) => panic!("超过上限的连接不应升级成功"),
        Err(tokio_tungstenite::tungstenite::Error::Http(resp)) => {
            assert_eq!(
                resp.status(),
                WsStatus::SERVICE_UNAVAILABLE,
                "超限连接应返回 503"
            );
        }
        Err(e) => panic!("期望 HTTP 503,实际错误: {e:?}"),
    }

    // 主动关闭一个连接,服务端计数应回落,随后允许新连接。
    {
        let mut ws = conns.pop().unwrap();
        ws.close(None).await.unwrap();
    }

    // 不能用固定 sleep:客户端 close() 返回后,服务端的 remove_client() 是在
    // handle_socket 的 loop 退出后才执行的,存在不确定的滞后;固定 sleep(200ms) 偶发不够,
    // 会让紧接着的重连撞上仍是 256 的计数而误收 503(flaky)。
    // 改为轮询等待服务端计数真正回落到 < 256(总超时 2s,每 20ms 查一次),再发起重连。
    let drained = async {
        loop {
            if server.state.ws_hub.get_client_count() < MAX_WS_CLIENTS {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    };
    tokio::time::timeout(Duration::from_secs(2), drained)
        .await
        .expect("关闭一个连接后,服务端计数应在 2s 内回落到上限以下");

    let (_ws, resp) = connect_async(ws_request(&server.addr, "/ws", Some(&token)))
        .await
        .expect("释放一个名额后应允许新连接");
    assert_eq!(resp.status(), WsStatus::SWITCHING_PROTOCOLS);
}
