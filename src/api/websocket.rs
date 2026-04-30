use axum::{
    extract::{
        ws::{Message, WebSocket, WebSocketUpgrade},
        Query, State,
    },
    response::IntoResponse,
};
use futures_util::{SinkExt, StreamExt};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
};
use tokio::sync::broadcast;

use super::AppState;

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

/// WebSocket Hub - 管理所有连接
pub struct WsHub {
    /// 广播发送器
    tx: broadcast::Sender<WsMessage>,
    /// 频道订阅
    channels: RwLock<HashMap<String, HashSet<String>>>,
    /// 客户端数量
    client_count: RwLock<usize>,
}

impl WsHub {
    pub fn new() -> Arc<Self> {
        let (tx, _) = broadcast::channel(256);
        Arc::new(Self {
            tx,
            channels: RwLock::new(HashMap::new()),
            client_count: RwLock::new(0),
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
    pub fn broadcast_to_channel(&self, channel: &str, msg_type: MessageType, data: serde_json::Value) {
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

    /// 增加客户端计数
    pub fn add_client(&self) {
        let mut count = self.client_count.write();
        *count += 1;
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
}

impl Default for WsHub {
    fn default() -> Self {
        let (tx, _) = broadcast::channel(256);
        Self {
            tx,
            channels: RwLock::new(HashMap::new()),
            client_count: RwLock::new(0),
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
    State(_state): State<AppState>,
) -> impl IntoResponse {
    let client_id = query
        .client_id
        .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());

    ws.on_upgrade(move |socket| handle_socket(socket, client_id))
}

/// 区块链 WebSocket 处理器
pub async fn chain_ws_handler(
    ws: WebSocketUpgrade,
    State(_state): State<AppState>,
) -> impl IntoResponse {
    let client_id = uuid::Uuid::new_v4().to_string();
    ws.on_upgrade(move |socket| handle_channel_socket(socket, client_id, "chain".to_string()))
}

/// 元数据 WebSocket 处理器
pub async fn metadata_ws_handler(
    ws: WebSocketUpgrade,
    State(_state): State<AppState>,
) -> impl IntoResponse {
    let client_id = uuid::Uuid::new_v4().to_string();
    ws.on_upgrade(move |socket| handle_channel_socket(socket, client_id, "metadata".to_string()))
}

/// 汇总 WebSocket 处理器
pub async fn aggregation_ws_handler(
    ws: WebSocketUpgrade,
    State(_state): State<AppState>,
) -> impl IntoResponse {
    let client_id = uuid::Uuid::new_v4().to_string();
    ws.on_upgrade(move |socket| handle_channel_socket(socket, client_id, "aggregation".to_string()))
}

/// 处理 WebSocket 连接
async fn handle_socket(socket: WebSocket, client_id: String) {
    let (mut sender, mut receiver) = socket.split();

    tracing::info!("WebSocket 客户端连接: {}", client_id);

    // 发送欢迎消息
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

    // 处理消息
    while let Some(msg) = receiver.next().await {
        match msg {
            Ok(Message::Text(text)) => {
                if let Ok(ws_msg) = serde_json::from_str::<WsMessage>(&text) {
                    match ws_msg.msg_type {
                        MessageType::Ping => {
                            let pong = WsMessage::new(MessageType::Pong, None);
                            if let Ok(json) = serde_json::to_string(&pong) {
                                let _ = sender.send(Message::Text(json)).await;
                            }
                        }
                        _ => {}
                    }
                }
            }
            Ok(Message::Ping(data)) => {
                let _ = sender.send(Message::Pong(data)).await;
            }
            Ok(Message::Close(_)) => break,
            Err(e) => {
                tracing::error!("WebSocket 错误: {}", e);
                break;
            }
            _ => {}
        }
    }

    tracing::info!("WebSocket 客户端断开: {}", client_id);
}

/// 处理频道 WebSocket 连接
async fn handle_channel_socket(socket: WebSocket, client_id: String, channel: String) {
    let (mut sender, mut receiver) = socket.split();

    tracing::info!("WebSocket 客户端连接到频道 {}: {}", channel, client_id);

    // 发送订阅确认
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

    // 处理消息
    while let Some(msg) = receiver.next().await {
        match msg {
            Ok(Message::Ping(data)) => {
                let _ = sender.send(Message::Pong(data)).await;
            }
            Ok(Message::Close(_)) => break,
            Err(e) => {
                tracing::error!("WebSocket 错误: {}", e);
                break;
            }
            _ => {}
        }
    }

    tracing::info!("WebSocket 客户端断开频道 {}: {}", channel, client_id);
}
