use std::collections::HashMap;
use std::sync::Arc;
use chrono::{DateTime, Utc};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use tokio::sync::broadcast;

use super::websocket::{MessageType, WsHub, WsMessage};

/// 通知服务
pub struct NotificationService {
    hub: Arc<WsHub>,
}

impl NotificationService {
    /// 创建通知服务
    pub fn new(hub: Arc<WsHub>) -> Self {
        Self { hub }
    }

    /// 通知新区块
    pub fn notify_new_block(&self, block_data: serde_json::Value) {
        self.hub.broadcast(WsMessage::new(MessageType::BlockAdded, Some(block_data)));
    }

    /// 通知新元数据
    pub fn notify_new_metadata(&self, metadata: serde_json::Value) {
        self.hub.broadcast(WsMessage::new(MessageType::MetadataAdded, Some(metadata)));
    }

    /// 通知汇总完成
    pub fn notify_aggregation_complete(&self, aggregation: serde_json::Value) {
        self.hub.broadcast(WsMessage::new(MessageType::Aggregation, Some(aggregation)));
    }

    /// 通知链验证完成
    pub fn notify_chain_validated(&self, result: serde_json::Value) {
        self.hub.broadcast(WsMessage::new(MessageType::ChainValidated, Some(result)));
    }

    /// 通知版本追踪
    pub fn notify_version_tracked(&self, version: serde_json::Value) {
        self.hub.broadcast(WsMessage::new(MessageType::VersionTracked, Some(version)));
    }

    /// 发送到特定频道
    pub fn notify_to_channel(&self, channel: &str, msg_type: MessageType, data: serde_json::Value) {
        self.hub.broadcast_to_channel(channel, msg_type, data);
    }

    /// 发送给特定用户
    pub fn notify_user(&self, user_id: &str, msg_type: MessageType, data: serde_json::Value) {
        let channel = format!("user:{}", user_id);
        self.hub.broadcast_to_channel(&channel, msg_type, data);
    }

    /// 获取连接统计
    pub fn get_connection_stats(&self) -> HashMap<String, usize> {
        let mut stats = HashMap::new();
        stats.insert("total_clients".to_string(), self.hub.get_client_count());
        stats
    }
}

/// 事件类型
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventType {
    BlockMined,
    MetadataCreated,
    AggregationDone,
    ChainValidated,
    VersionTracked,
    UserLoggedIn,
    UserRegistered,
}

/// 事件
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Event {
    #[serde(rename = "type")]
    pub event_type: EventType,
    pub data: serde_json::Value,
    pub timestamp: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_id: Option<String>,
}

impl Event {
    pub fn new(event_type: EventType, data: serde_json::Value) -> Self {
        Self {
            event_type,
            data,
            timestamp: Utc::now(),
            user_id: None,
        }
    }

    pub fn with_user(mut self, user_id: impl Into<String>) -> Self {
        self.user_id = Some(user_id.into());
        self
    }
}

/// 事件处理器
pub type EventHandler = Box<dyn Fn(&Event) + Send + Sync>;

/// 事件总线
pub struct EventBus {
    notification: Arc<NotificationService>,
    handlers: RwLock<HashMap<EventType, Vec<Arc<EventHandler>>>>,
    tx: broadcast::Sender<Event>,
}

impl EventBus {
    /// 创建事件总线
    pub fn new(notification: Arc<NotificationService>) -> Self {
        let (tx, _) = broadcast::channel(256);
        Self {
            notification,
            handlers: RwLock::new(HashMap::new()),
            tx,
        }
    }

    /// 订阅事件
    pub fn subscribe(&self, event_type: EventType, handler: EventHandler) {
        let mut handlers = self.handlers.write();
        handlers
            .entry(event_type)
            .or_insert_with(Vec::new)
            .push(Arc::new(handler));
    }

    /// 获取事件接收器
    pub fn receiver(&self) -> broadcast::Receiver<Event> {
        self.tx.subscribe()
    }

    /// 发布事件
    pub fn publish(&self, mut event: Event) {
        event.timestamp = Utc::now();

        // 调用处理器
        let handlers = self.handlers.read();
        if let Some(event_handlers) = handlers.get(&event.event_type) {
            for handler in event_handlers {
                let handler = handler.clone();
                let event = event.clone();
                tokio::spawn(async move {
                    handler(&event);
                });
            }
        }

        // 通过 WebSocket 广播
        match event.event_type {
            EventType::BlockMined => {
                self.notification.notify_new_block(event.data.clone());
            }
            EventType::MetadataCreated => {
                self.notification.notify_new_metadata(event.data.clone());
            }
            EventType::AggregationDone => {
                self.notification.notify_aggregation_complete(event.data.clone());
            }
            EventType::ChainValidated => {
                self.notification.notify_chain_validated(event.data.clone());
            }
            EventType::VersionTracked => {
                self.notification.notify_version_tracked(event.data.clone());
            }
            _ => {}
        }

        // 广播到订阅者
        let _ = self.tx.send(event);
    }

    /// 发布区块挖掘事件
    pub fn publish_block_mined(&self, block_data: serde_json::Value) {
        self.publish(Event::new(EventType::BlockMined, block_data));
    }

    /// 发布元数据创建事件
    pub fn publish_metadata_created(&self, metadata: serde_json::Value) {
        self.publish(Event::new(EventType::MetadataCreated, metadata));
    }

    /// 发布汇总完成事件
    pub fn publish_aggregation_done(&self, aggregation: serde_json::Value) {
        self.publish(Event::new(EventType::AggregationDone, aggregation));
    }
}
