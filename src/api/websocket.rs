use axum::{
    extract::{
        ws::{close_code, CloseFrame, Message, WebSocket, WebSocketUpgrade},
        Query, State,
    },
    http::StatusCode,
    response::{IntoResponse, Response},
    Extension,
};
use futures_util::{SinkExt, StreamExt};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::{
    collections::{HashMap, HashSet},
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::Duration,
};
use tokio::sync::broadcast;

use super::AppState;
use crate::auth::{AuthService, Claims};

/// WebSocket 消息类型
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MessageType {
    BlockAdded,
    MetadataAdded,
    Aggregation,
    ChainValidated,
    VersionTracked,
    Ping,
    Pong,
    Subscribe,
    Unsubscribe,
    Error,
}

/// WebSocket 消息
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WsMessage {
    #[serde(rename = "type")]
    pub msg_type: MessageType,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub channel: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<serde_json::Value>,
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

impl WsMessage {
    pub fn new(msg_type: MessageType, data: Option<serde_json::Value>) -> Self {
        Self {
            msg_type,
            channel: None,
            data,
            timestamp: chrono::Utc::now(),
        }
    }

    pub fn with_channel(mut self, channel: impl Into<String>) -> Self {
        self.channel = Some(channel.into());
        self
    }
}

/// WebSocket 单条文本消息最大字节数。
const MAX_WS_MESSAGE_BYTES: usize = 16 * 1024;
/// 单进程最大 WebSocket 连接数,防止无界连接耗尽资源。
const MAX_WS_CLIENTS: usize = 256;
/// 默认连接复核间隔(毫秒),与 `auth.ws_revalidate_secs` 默认 30 秒一致。
const DEFAULT_REVALIDATE_MS: u64 = 30_000;
/// 单次连接复核的超时时间;超时按复核失败处理,避免复核挂起使连接长期不被清理。
const REVALIDATE_TIMEOUT: Duration = Duration::from_secs(5);

fn channel_accepts_message(channel: &str, msg_type: &MessageType) -> bool {
    matches!(
        (channel, msg_type),
        (
            "chain",
            MessageType::BlockAdded | MessageType::ChainValidated
        ) | ("metadata", MessageType::MetadataAdded)
            | ("aggregation", MessageType::Aggregation)
    )
}

/// WebSocket Hub - 管理所有连接
pub struct WsHub {
    /// 广播发送器
    tx: broadcast::Sender<WsMessage>,
    /// 频道订阅
    channels: RwLock<HashMap<String, HashSet<String>>>,
    /// 客户端数量
    client_count: RwLock<usize>,
    /// 连接定时复核间隔(毫秒)
    revalidate_ms: AtomicU64,
}

impl WsHub {
    pub fn new() -> Arc<Self> {
        let (tx, _) = broadcast::channel(256);
        Arc::new(Self {
            tx,
            channels: RwLock::new(HashMap::new()),
            client_count: RwLock::new(0),
            revalidate_ms: AtomicU64::new(DEFAULT_REVALIDATE_MS),
        })
    }

    /// 获取广播接收器
    pub fn subscribe(&self) -> broadcast::Receiver<WsMessage> {
        self.tx.subscribe()
    }

    /// 广播消息
    pub fn broadcast(&self, msg: WsMessage) {
        let _ = self.tx.send(msg);
    }

    /// 广播到特定频道
    pub fn broadcast_to_channel(
        &self,
        channel: &str,
        msg_type: MessageType,
        data: serde_json::Value,
    ) {
        let msg = WsMessage::new(msg_type, Some(data)).with_channel(channel);
        self.broadcast(msg);
    }

    /// 订阅频道
    pub fn subscribe_channel(&self, client_id: &str, channel: &str) {
        let mut channels = self.channels.write();
        channels
            .entry(channel.to_string())
            .or_insert_with(HashSet::new)
            .insert(client_id.to_string());
    }

    /// 取消订阅频道
    pub fn unsubscribe_channel(&self, client_id: &str, channel: &str) {
        let mut channels = self.channels.write();
        if let Some(clients) = channels.get_mut(channel) {
            clients.remove(client_id);
        }
    }

    /// 尝试增加客户端,达到上限时拒绝新连接。
    pub fn try_add_client(&self) -> bool {
        let mut count = self.client_count.write();
        if *count >= MAX_WS_CLIENTS {
            return false;
        }
        *count += 1;
        true
    }

    /// 增加客户端计数(兼容内部调用;新握手应优先使用 try_add_client)。
    pub fn add_client(&self) {
        let _ = self.try_add_client();
    }

    /// 减少客户端计数
    pub fn remove_client(&self) {
        let mut count = self.client_count.write();
        if *count > 0 {
            *count -= 1;
        }
    }

    /// 获取客户端数量
    pub fn get_client_count(&self) -> usize {
        *self.client_count.read()
    }

    /// 连接定时复核间隔。
    pub fn revalidate_interval(&self) -> Duration {
        Duration::from_millis(self.revalidate_ms.load(Ordering::Relaxed))
    }

    /// 设置连接定时复核间隔(server 启动按配置设置;亦作测试 seam)。
    /// 毫秒数按 u64 饱和截断,且至少 1ms,避免 `tokio::time::interval` 对 0 间隔 panic。
    pub fn set_revalidate_interval(&self, d: Duration) {
        let ms = u64::try_from(d.as_millis()).unwrap_or(u64::MAX).max(1);
        self.revalidate_ms.store(ms, Ordering::Relaxed);
    }
}

impl Default for WsHub {
    fn default() -> Self {
        let (tx, _) = broadcast::channel(256);
        Self {
            tx,
            channels: RwLock::new(HashMap::new()),
            client_count: RwLock::new(0),
            revalidate_ms: AtomicU64::new(DEFAULT_REVALIDATE_MS),
        }
    }
}

#[derive(Deserialize)]
pub struct WsQuery {
    #[serde(default)]
    pub client_id: Option<String>,
}

/// WebSocket 处理器
pub async fn ws_handler(
    ws: WebSocketUpgrade,
    Query(query): Query<WsQuery>,
    Extension(claims): Extension<Claims>,
    State(state): State<AppState>,
) -> Response {
    if !state.ws_hub.try_add_client() {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            "websocket connection limit reached",
        )
            .into_response();
    }
    let client_id = query
        .client_id
        .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
    let hub = state.ws_hub.clone();
    let auth = state.auth_service.clone();

    ws.on_upgrade(move |socket| handle_socket(socket, client_id, hub, auth, claims))
        .into_response()
}

/// 区块链 WebSocket 处理器
pub async fn chain_ws_handler(
    ws: WebSocketUpgrade,
    Extension(claims): Extension<Claims>,
    State(state): State<AppState>,
) -> Response {
    if !state.ws_hub.try_add_client() {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            "websocket connection limit reached",
        )
            .into_response();
    }
    let client_id = uuid::Uuid::new_v4().to_string();
    let hub = state.ws_hub.clone();
    let auth = state.auth_service.clone();
    ws.on_upgrade(move |socket| {
        handle_channel_socket(socket, client_id, "chain".to_string(), hub, auth, claims)
    })
    .into_response()
}

/// 元数据 WebSocket 处理器
pub async fn metadata_ws_handler(
    ws: WebSocketUpgrade,
    Extension(claims): Extension<Claims>,
    State(state): State<AppState>,
) -> Response {
    if !state.ws_hub.try_add_client() {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            "websocket connection limit reached",
        )
            .into_response();
    }
    let client_id = uuid::Uuid::new_v4().to_string();
    let hub = state.ws_hub.clone();
    let auth = state.auth_service.clone();
    ws.on_upgrade(move |socket| {
        handle_channel_socket(socket, client_id, "metadata".to_string(), hub, auth, claims)
    })
    .into_response()
}

/// 汇总 WebSocket 处理器
pub async fn aggregation_ws_handler(
    ws: WebSocketUpgrade,
    Extension(claims): Extension<Claims>,
    State(state): State<AppState>,
) -> Response {
    if !state.ws_hub.try_add_client() {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            "websocket connection limit reached",
        )
            .into_response();
    }
    let client_id = uuid::Uuid::new_v4().to_string();
    let hub = state.ws_hub.clone();
    let auth = state.auth_service.clone();
    ws.on_upgrade(move |socket| {
        handle_channel_socket(
            socket,
            client_id,
            "aggregation".to_string(),
            hub,
            auth,
            claims,
        )
    })
    .into_response()
}

/// 复核失败时发送的 Close 帧(1008 policy violation)。
fn revalidate_close_frame() -> Message {
    Message::Close(Some(CloseFrame {
        code: close_code::POLICY,
        reason: "session no longer valid".into(),
    }))
}

/// 处理 WebSocket 连接
async fn handle_socket(
    socket: WebSocket,
    client_id: String,
    hub: Arc<WsHub>,
    auth: Arc<AuthService>,
    claims: Claims,
) {
    let (mut sender, mut receiver) = socket.split();
    let mut events = hub.subscribe();
    let mut tick = tokio::time::interval(hub.revalidate_interval());
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    tick.tick().await;

    tracing::info!("WebSocket 客户端连接: {}", client_id);

    let welcome = WsMessage::new(
        MessageType::Pong,
        Some(serde_json::json!({
            "client_id": client_id,
            "message": "connected"
        })),
    );
    if let Ok(json) = serde_json::to_string(&welcome) {
        let _ = sender.send(Message::Text(json)).await;
    }

    loop {
        tokio::select! {
            msg = receiver.next() => {
                match msg {
                    Some(Ok(Message::Text(text))) => {
                        if text.len() > MAX_WS_MESSAGE_BYTES {
                            tracing::warn!("WebSocket message too large: {} bytes", text.len());
                            let error = WsMessage::new(
                                MessageType::Error,
                                Some(serde_json::json!({ "error": "message too large" })),
                            );
                            if let Ok(json) = serde_json::to_string(&error) {
                                let _ = sender.send(Message::Text(json)).await;
                            }
                            break;
                        }
                        if let Ok(ws_msg) = serde_json::from_str::<WsMessage>(&text) {
                            if matches!(ws_msg.msg_type, MessageType::Ping) {
                                let pong = WsMessage::new(MessageType::Pong, None);
                                if let Ok(json) = serde_json::to_string(&pong) {
                                    let _ = sender.send(Message::Text(json)).await;
                                }
                            }
                        }
                    }
                    Some(Ok(Message::Ping(data))) => {
                        let _ = sender.send(Message::Pong(data)).await;
                    }
                    Some(Ok(Message::Close(_))) | None => break,
                    Some(Err(e)) => {
                        tracing::error!("WebSocket 错误: {}", e);
                        break;
                    }
                    _ => {}
                }
            }
            _ = tick.tick() => {
                let result = tokio::time::timeout(REVALIDATE_TIMEOUT, auth.revalidate_claims(&claims)).await;
                match result {
                    Ok(Ok(())) => {}
                    Ok(Err(e)) => {
                        tracing::info!("WebSocket 复核失败,关闭连接 {}: {}", client_id, e);
                        let _ = sender.send(revalidate_close_frame()).await;
                        break;
                    }
                    Err(_) => {
                        tracing::warn!("WebSocket 复核超时,关闭连接 {}", client_id);
                        let _ = sender.send(revalidate_close_frame()).await;
                        break;
                    }
                }
            }
            event = events.recv() => {
                match event {
                    Ok(event) => {
                        if let Ok(json) = serde_json::to_string(&event) {
                            let _ = sender.send(Message::Text(json)).await;
                        }
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(count)) => {
                        tracing::warn!("WebSocket event receiver lagged by {} events", count);
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                }
            }
        }
    }

    hub.remove_client();
    tracing::info!("WebSocket 客户端断开: {}", client_id);
}

/// 处理频道 WebSocket 连接
async fn handle_channel_socket(
    socket: WebSocket,
    client_id: String,
    channel: String,
    hub: Arc<WsHub>,
    auth: Arc<AuthService>,
    claims: Claims,
) {
    let (mut sender, mut receiver) = socket.split();
    let mut events = hub.subscribe();
    let mut tick = tokio::time::interval(hub.revalidate_interval());
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    tick.tick().await;

    tracing::info!("WebSocket 客户端连接到频道 {}: {}", channel, client_id);

    let subscribed = WsMessage::new(
        MessageType::Subscribe,
        Some(serde_json::json!({
            "client_id": client_id,
            "channel": channel
        })),
    );
    if let Ok(json) = serde_json::to_string(&subscribed) {
        let _ = sender.send(Message::Text(json)).await;
    }

    loop {
        tokio::select! {
            msg = receiver.next() => {
                match msg {
                    Some(Ok(Message::Text(text))) => {
                        if text.len() > MAX_WS_MESSAGE_BYTES {
                            tracing::warn!("WebSocket channel message too large: {} bytes", text.len());
                            break;
                        }
                    }
                    Some(Ok(Message::Ping(data))) => {
                        let _ = sender.send(Message::Pong(data)).await;
                    }
                    Some(Ok(Message::Close(_))) | None => break,
                    Some(Err(e)) => {
                        tracing::error!("WebSocket 错误: {}", e);
                        break;
                    }
                    _ => {}
                }
            }
            _ = tick.tick() => {
                let result = tokio::time::timeout(REVALIDATE_TIMEOUT, auth.revalidate_claims(&claims)).await;
                match result {
                    Ok(Ok(())) => {}
                    Ok(Err(e)) => {
                        tracing::info!("WebSocket 复核失败,关闭频道连接 {}: {}", client_id, e);
                        let _ = sender.send(revalidate_close_frame()).await;
                        break;
                    }
                    Err(_) => {
                        tracing::warn!("WebSocket 复核超时,关闭频道连接 {}", client_id);
                        let _ = sender.send(revalidate_close_frame()).await;
                        break;
                    }
                }
            }
            event = events.recv() => {
                match event {
                    Ok(event) => {
                        if channel_accepts_message(&channel, &event.msg_type) {
                            if let Ok(json) = serde_json::to_string(&event) {
                                let _ = sender.send(Message::Text(json)).await;
                            }
                        }
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(count)) => {
                        tracing::warn!("WebSocket channel receiver lagged by {} events", count);
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                }
            }
        }
    }

    hub.remove_client();
    tracing::info!("WebSocket 客户端断开频道 {}: {}", channel, client_id);
}
