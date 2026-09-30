use std::sync::Arc;

use super::{notification::EventBus, websocket::WsHub};
use crate::aggregation::{AggregationEngine, Scheduler};
use crate::auth::AuthService;
use crate::core::Chain;
use crate::metadata::MetadataManager;
use crate::p2p::P2PService;
use crate::storage::Storage;
use crate::versioning::VersionTracker;

/// 应用状态
#[derive(Clone)]
pub struct AppState {
    pub chain: Arc<Chain>,
    pub auth_service: Arc<AuthService>,
    pub metadata_manager: Arc<MetadataManager>,
    pub version_tracker: Arc<VersionTracker>,
    pub aggregation_engine: Arc<AggregationEngine>,
    pub storage: Arc<Storage>,
    pub ws_hub: Arc<WsHub>,
    pub event_bus: Arc<EventBus>,
    pub scheduler: Arc<Scheduler>,
    pub p2p: Arc<P2PService>,
}

impl AppState {
    /// 创建应用状态
    pub fn new(
        chain: Arc<Chain>,
        auth_service: Arc<AuthService>,
        metadata_manager: Arc<MetadataManager>,
        version_tracker: Arc<VersionTracker>,
        aggregation_engine: Arc<AggregationEngine>,
        storage: Arc<Storage>,
        ws_hub: Arc<WsHub>,
        event_bus: Arc<EventBus>,
        scheduler: Arc<Scheduler>,
        p2p: Arc<P2PService>,
    ) -> Self {
        Self {
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
        }
    }
}
