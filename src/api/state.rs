use std::sync::Arc;

use crate::aggregation::AggregationEngine;
use crate::auth::AuthService;
use crate::core::Chain;
use crate::metadata::MetadataManager;
use crate::storage::Storage;
use crate::versioning::VersionTracker;
use super::websocket::WsHub;

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
    ) -> Self {
        Self {
            chain,
            auth_service,
            metadata_manager,
            version_tracker,
            aggregation_engine,
            storage,
            ws_hub,
        }
    }
}
