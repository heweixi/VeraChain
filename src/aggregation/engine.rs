use chrono::{DateTime, Utc};
use parking_lot::RwLock;
use serde::Serialize;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use super::{AggregationStrategy, CountBasedStrategy, StrategyType, TimeBasedStrategy};
use crate::core::{build_merkle_root, metadata_leaf_hash, Chain, MetadataEntry, TimeRange};

/// 汇总引擎
pub struct AggregationEngine {
    chain: Arc<Chain>,
    strategies: RwLock<Vec<Box<dyn AggregationStrategy>>>,
    aggregations: RwLock<Vec<AggregationSummary>>,
    last_aggregation: RwLock<DateTime<Utc>>,
    aggregated_count: RwLock<usize>,
}

impl AggregationEngine {
    /// 创建汇总引擎
    pub fn new(chain: Arc<Chain>, time_interval_secs: u64, count_threshold: usize) -> Self {
        let mut strategies: Vec<Box<dyn AggregationStrategy>> = Vec::new();
        
        // 添加默认策略
        strategies.push(Box::new(TimeBasedStrategy::new(Duration::from_secs(time_interval_secs))));
        strategies.push(Box::new(CountBasedStrategy::new(count_threshold, Duration::from_secs(86400))));

        Self {
            chain,
            strategies: RwLock::new(strategies),
            aggregations: RwLock::new(Vec::new()),
            last_aggregation: RwLock::new(Utc::now()),
            aggregated_count: RwLock::new(0),
        }
    }

    /// 添加策略
    pub fn add_strategy(&self, strategy: Box<dyn AggregationStrategy>) {
        let mut strategies = self.strategies.write();
        strategies.push(strategy);
    }

    /// 检查是否应该汇总
    pub fn should_aggregate(&self) -> (bool, Option<StrategyType>) {
        let strategies = self.strategies.read();
        let metadata_count = self.get_total_metadata_count();

        for strategy in strategies.iter() {
            if strategy.should_aggregate(metadata_count) {
                let strategy_type = match strategy.strategy_type() {
                    "time_based" => StrategyType::TimeBased,
                    "count_based" => StrategyType::CountBased,
                    "recursive" => StrategyType::Recursive,
                    _ => StrategyType::Manual,
                };
                return (true, Some(strategy_type));
            }
        }

        (false, None)
    }

    /// 执行汇总
    pub fn aggregate(&self, strategy_type: StrategyType) -> Option<AggregationSummary> {
        let blocks = self.chain.get_all_blocks();
        if blocks.is_empty() {
            return None;
        }

        // 收集所有元数据
        let mut all_metadata = Vec::new();
        for block in &blocks {
            all_metadata.extend(block.metadata_list.clone());
        }

        if all_metadata.is_empty() {
            return None;
        }

        // 计算统计信息
        let statistics = self.compute_statistics(&all_metadata);

        // 计算 Merkle 根:基于所聚合的元数据 data_id,叶子 = SHA256(data_id)
        // (与 Python/Go 的元数据聚合及区块 merkle 统一,BLOCK_HASH_SPEC 第10节)
        let hashes: Vec<String> = all_metadata
            .iter()
            .map(|m| metadata_leaf_hash(&m.data_id))
            .collect();
        let merkle_root = build_merkle_root(&hashes);

        // 创建汇总
        let summary = AggregationSummary {
            summary_id: uuid::Uuid::new_v4().to_string(),
            summary_type: strategy_type.to_string(),
            level: 1,
            created_at: Utc::now(),
            time_range: Some(TimeRange {
                start: *self.last_aggregation.read(),
                end: Utc::now(),
            }),
            block_range: Some((blocks.first().unwrap().index, blocks.last().unwrap().index)),
            statistics,
            merkle_root,
            metadata_count: all_metadata.len(),
            parent_summaries: Vec::new(),
        };

        // 更新状态
        *self.last_aggregation.write() = Utc::now();
        *self.aggregated_count.write() = all_metadata.len();

        // 重置策略
        let strategies = self.strategies.read();
        for strategy in strategies.iter() {
            strategy.reset();
        }

        // 保存汇总
        let mut aggregations = self.aggregations.write();
        aggregations.push(summary.clone());

        Some(summary)
    }

    /// 计算统计信息
    fn compute_statistics(&self, metadata_list: &[MetadataEntry]) -> HashMap<String, serde_json::Value> {
        let mut stats = HashMap::new();

        if metadata_list.is_empty() {
            stats.insert("total_metadata".to_string(), serde_json::json!(0));
            stats.insert("total_size".to_string(), serde_json::json!(0));
            stats.insert("unique_owners".to_string(), serde_json::json!(0));
            return stats;
        }

        let total_metadata = metadata_list.len();
        let total_size: i64 = metadata_list.iter().map(|m| m.data_size).sum();

        let mut owners: HashMap<String, usize> = HashMap::new();
        let mut tags: HashMap<String, usize> = HashMap::new();
        let mut size_distribution = HashMap::new();
        size_distribution.insert("0-1KB".to_string(), 0usize);
        size_distribution.insert("1KB-1MB".to_string(), 0usize);
        size_distribution.insert("1MB-100MB".to_string(), 0usize);
        size_distribution.insert("100MB+".to_string(), 0usize);

        for m in metadata_list {
            *owners.entry(m.owner.clone()).or_insert(0) += 1;

            for tag in &m.tags {
                *tags.entry(tag.clone()).or_insert(0) += 1;
            }

            // 大小分布
            let category = if m.data_size < 1024 {
                "0-1KB"
            } else if m.data_size < 1024 * 1024 {
                "1KB-1MB"
            } else if m.data_size < 100 * 1024 * 1024 {
                "1MB-100MB"
            } else {
                "100MB+"
            };
            *size_distribution.get_mut(category).unwrap() += 1;
        }

        // Top owners
        let mut top_owners: Vec<_> = owners.into_iter().collect();
        top_owners.sort_by(|a, b| b.1.cmp(&a.1));
        top_owners.truncate(10);

        // Top tags
        let mut top_tags: Vec<_> = tags.into_iter().collect();
        top_tags.sort_by(|a, b| b.1.cmp(&a.1));
        top_tags.truncate(10);

        stats.insert("total_metadata".to_string(), serde_json::json!(total_metadata));
        stats.insert("total_size".to_string(), serde_json::json!(total_size));
        stats.insert("unique_owners".to_string(), serde_json::json!(top_owners.len()));
        stats.insert("size_distribution".to_string(), serde_json::json!(size_distribution));
        stats.insert("top_owners".to_string(), serde_json::json!(top_owners));
        stats.insert("top_tags".to_string(), serde_json::json!(top_tags));

        stats
    }

    /// 获取总元数据数量
    fn get_total_metadata_count(&self) -> usize {
        let blocks = self.chain.get_all_blocks();
        blocks.iter().map(|b| b.metadata_list.len()).sum()
    }

    /// 获取汇总
    pub fn get_aggregation(&self, summary_id: &str) -> Option<AggregationSummary> {
        let aggregations = self.aggregations.read();
        aggregations.iter().find(|a| a.summary_id == summary_id).cloned()
    }

    /// 获取所有汇总
    pub fn get_all_aggregations(&self) -> Vec<AggregationSummary> {
        self.aggregations.read().clone()
    }

    /// 获取上次汇总时间
    pub fn get_last_aggregation(&self) -> DateTime<Utc> {
        *self.last_aggregation.read()
    }

    /// 获取已汇总的元数据数量
    pub fn get_aggregated_count(&self) -> usize {
        *self.aggregated_count.read()
    }
}

/// 汇总摘要
#[derive(Debug, Clone, Serialize)]
pub struct AggregationSummary {
    pub summary_id: String,
    pub summary_type: String,
    pub level: u32,
    pub created_at: DateTime<Utc>,
    pub time_range: Option<TimeRange>,
    pub block_range: Option<(i64, i64)>,
    pub statistics: HashMap<String, serde_json::Value>,
    pub merkle_root: String,
    pub metadata_count: usize,
    pub parent_summaries: Vec<String>,
}

/// 创建共享的 AggregationEngine 实例
pub fn create_aggregation_engine(
    chain: Arc<Chain>,
    time_interval_secs: u64,
    count_threshold: usize,
) -> Arc<AggregationEngine> {
    Arc::new(AggregationEngine::new(chain, time_interval_secs, count_threshold))
}
