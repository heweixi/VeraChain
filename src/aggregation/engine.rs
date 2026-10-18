use chrono::{DateTime, Utc};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
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
    /// 递归聚合阈值:同一 level 的 summary 数达到该值即合并为上一级父 summary。
    recursive_threshold: usize,
}

impl AggregationEngine {
    /// 创建汇总引擎
    pub fn new(chain: Arc<Chain>, time_interval_secs: u64, count_threshold: usize) -> Self {
        let mut strategies: Vec<Box<dyn AggregationStrategy>> = Vec::new();

        // 添加默认策略
        strategies.push(Box::new(TimeBasedStrategy::new(Duration::from_secs(
            time_interval_secs,
        ))));
        strategies.push(Box::new(CountBasedStrategy::new(
            count_threshold,
            Duration::from_secs(86400),
        )));

        // 递归聚合阈值:同一 level 的 summary 数达到该值即合并为父 summary。
        // 取 count_threshold 与 8 的较小值并下限 2,避免需要海量子 summary 才合并。
        // 递归不进入自动 strategies 列表(其 should_aggregate 以 summary 数而非 metadata 数判断),
        // 改由 should_aggregate() 单独检查未合并 summary 数触发。
        let recursive_threshold = std::cmp::min(count_threshold.max(2), 8);

        Self {
            chain,
            strategies: RwLock::new(strategies),
            aggregations: RwLock::new(Vec::new()),
            last_aggregation: RwLock::new(Utc::now()),
            aggregated_count: RwLock::new(0),
            recursive_threshold,
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
        drop(strategies);

        // 递归聚合:存在任一 level 的未合并 summary 数达到阈值时触发向上合并。
        if self.has_recursive_opportunity() {
            return (true, Some(StrategyType::Recursive));
        }

        (false, None)
    }

    /// 是否存在可向上合并的未合并 summary 批次。
    fn has_recursive_opportunity(&self) -> bool {
        let aggregations = self.aggregations.read();
        let mut per_level: HashMap<u32, usize> = HashMap::new();
        for s in aggregations.iter() {
            if !s.is_merged {
                *per_level.entry(s.level).or_insert(0) += 1;
            }
        }
        per_level.values().any(|&c| c >= self.recursive_threshold)
    }

    /// 执行汇总
    pub fn aggregate(&self, strategy_type: StrategyType) -> Option<AggregationSummary> {
        // 递归策略:把已有 summary 向上合并为父 summary,而非重新扫描区块元数据。
        if strategy_type == StrategyType::Recursive {
            return self.aggregate_recursive();
        }

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
            is_merged: false,
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

    /// 递归聚合:把当前最高层中尚未拥有父 summary 的子 summary 合并为上一级父 summary。
    ///
    /// 选取当前最高 level 且 `is_merged == false` 的 summary 作为候选子集;当其数量达到
    /// `recursive_threshold` 时,合并生成 level+1 父 summary:
    /// - merkle_root = build_merkle_root(子 summary 的 merkle_root 列表)(确定性、可验证)
    /// - metadata_count / total_size 等统计量从子 summary 累加
    /// - parent_summaries 记录子 summary_id,子 summary 标记 is_merged
    pub fn aggregate_recursive(&self) -> Option<AggregationSummary> {
        let mut aggregations = self.aggregations.write();
        if aggregations.is_empty() {
            return None;
        }

        // 从最低 level 开始,找到第一个未合并 summary 数达到阈值的 level 作为合并目标。
        // 先填满低层(level 1→2),低层不足阈值时再考虑更高层(level 2→3),符合自底向上聚合。
        let levels: std::collections::BTreeSet<u32> = aggregations
            .iter()
            .filter(|s| !s.is_merged)
            .map(|s| s.level)
            .collect();

        let mut target_level: Option<u32> = None;
        for level in levels {
            let count = aggregations
                .iter()
                .filter(|s| s.level == level && !s.is_merged)
                .count();
            if count >= self.recursive_threshold {
                target_level = Some(level);
                break;
            }
        }
        let top_level = target_level?;

        // 收集该 level 的未合并子 summary(按创建时间稳定排序,保证 merkle_root 确定)。
        let mut child_indices: Vec<usize> = aggregations
            .iter()
            .enumerate()
            .filter(|(_, s)| s.level == top_level && !s.is_merged)
            .map(|(i, _)| i)
            .collect();
        child_indices.sort_by_key(|&i| {
            (
                aggregations[i].created_at,
                aggregations[i].summary_id.clone(),
            )
        });

        // 仅合并恰好 recursive_threshold 个子 summary,使多批子 summary 分批成多个父。
        child_indices.truncate(self.recursive_threshold);
        if child_indices.len() < self.recursive_threshold {
            return None;
        }

        let children: Vec<AggregationSummary> = child_indices
            .iter()
            .map(|&i| aggregations[i].clone())
            .collect();

        // 聚合子 summary 的 merkle_root 得到父 merkle_root。
        let child_roots: Vec<String> = children.iter().map(|c| c.merkle_root.clone()).collect();
        let parent_root = build_merkle_root(&child_roots);

        // 累加统计量。
        let total_metadata: usize = children.iter().map(|c| c.metadata_count).sum();
        let total_size: i64 = children
            .iter()
            .map(|c| {
                c.statistics
                    .get("total_size")
                    .and_then(|v| v.as_i64())
                    .unwrap_or(0)
            })
            .sum();
        let mut statistics: HashMap<String, serde_json::Value> = HashMap::new();
        statistics.insert(
            "total_metadata".to_string(),
            serde_json::json!(total_metadata),
        );
        statistics.insert("total_size".to_string(), serde_json::json!(total_size));
        statistics.insert("child_count".to_string(), serde_json::json!(children.len()));
        statistics.insert(
            "child_levels".to_string(),
            serde_json::json!(children.iter().map(|c| c.level).collect::<Vec<_>>()),
        );

        // 父 block_range 覆盖所有子的 block_range。
        let block_range = {
            let mut lo: Option<i64> = None;
            let mut hi: Option<i64> = None;
            for c in &children {
                if let Some((s, e)) = c.block_range {
                    lo = Some(lo.map_or(s, |v| v.min(s)));
                    hi = Some(hi.map_or(e, |v| v.max(e)));
                }
            }
            match (lo, hi) {
                (Some(s), Some(e)) => Some((s, e)),
                _ => None,
            }
        };

        // 父 time_range 覆盖所有子的 created_at。
        let time_start = children
            .iter()
            .map(|c| c.created_at)
            .min()
            .unwrap_or_else(Utc::now);
        let time_end = children
            .iter()
            .map(|c| c.created_at)
            .max()
            .unwrap_or_else(Utc::now);

        let parent = AggregationSummary {
            summary_id: uuid::Uuid::new_v4().to_string(),
            summary_type: StrategyType::Recursive.to_string(),
            level: top_level + 1,
            created_at: Utc::now(),
            time_range: Some(TimeRange {
                start: time_start,
                end: time_end,
            }),
            block_range,
            statistics,
            merkle_root: parent_root,
            metadata_count: total_metadata,
            parent_summaries: children.iter().map(|c| c.summary_id.clone()).collect(),
            is_merged: false,
        };

        // 标记子 summary 已被合并,避免重复聚合。
        for &i in &child_indices {
            aggregations[i].is_merged = true;
        }
        aggregations.push(parent.clone());

        Some(parent)
    }

    /// 加载持久化的聚合结果。
    pub fn load_aggregation(&self, summary: AggregationSummary) {
        let latest = {
            let mut aggregations = self.aggregations.write();
            if aggregations
                .iter()
                .any(|item| item.summary_id == summary.summary_id)
            {
                return;
            }
            aggregations.push(summary);
            aggregations
                .iter()
                .max_by_key(|item| item.created_at)
                .cloned()
        };

        if let Some(latest) = latest {
            *self.last_aggregation.write() = latest.created_at;
            *self.aggregated_count.write() = latest.metadata_count;
        }
    }

    /// 移除尚未成功持久化的聚合结果。
    pub fn remove_aggregation(&self, summary_id: &str) -> bool {
        let (removed, latest) = {
            let mut aggregations = self.aggregations.write();
            let before = aggregations.len();
            aggregations.retain(|item| item.summary_id != summary_id);
            let removed = aggregations.len() != before;
            let latest = aggregations
                .iter()
                .max_by_key(|item| item.created_at)
                .cloned();
            (removed, latest)
        };

        if removed {
            if let Some(latest) = latest {
                *self.last_aggregation.write() = latest.created_at;
                *self.aggregated_count.write() = latest.metadata_count;
            } else {
                *self.last_aggregation.write() = Utc::now();
                *self.aggregated_count.write() = 0;
            }
        }
        removed
    }

    /// 计算统计信息
    fn compute_statistics(
        &self,
        metadata_list: &[MetadataEntry],
    ) -> HashMap<String, serde_json::Value> {
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

        stats.insert(
            "total_metadata".to_string(),
            serde_json::json!(total_metadata),
        );
        stats.insert("total_size".to_string(), serde_json::json!(total_size));
        stats.insert(
            "unique_owners".to_string(),
            serde_json::json!(top_owners.len()),
        );
        stats.insert(
            "size_distribution".to_string(),
            serde_json::json!(size_distribution),
        );
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
        aggregations
            .iter()
            .find(|a| a.summary_id == summary_id)
            .cloned()
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
#[derive(Debug, Clone, Serialize, Deserialize)]
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
    /// 是否已被更高层父 summary 合并(递归聚合用)。旧数据反序列化默认 false。
    #[serde(default)]
    pub is_merged: bool,
}

/// 创建共享的 AggregationEngine 实例
pub fn create_aggregation_engine(
    chain: Arc<Chain>,
    time_interval_secs: u64,
    count_threshold: usize,
) -> Arc<AggregationEngine> {
    Arc::new(AggregationEngine::new(
        chain,
        time_interval_secs,
        count_threshold,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::{build_merkle_root, create_chain};

    fn leaf_summary(id: &str, root: &str, count: usize, size: i64) -> AggregationSummary {
        let mut statistics = HashMap::new();
        statistics.insert("total_size".to_string(), serde_json::json!(size));
        AggregationSummary {
            summary_id: id.to_string(),
            summary_type: StrategyType::CountBased.to_string(),
            level: 1,
            created_at: Utc::now(),
            time_range: None,
            block_range: Some((0, 1)),
            statistics,
            merkle_root: root.to_string(),
            metadata_count: count,
            parent_summaries: Vec::new(),
            is_merged: false,
        }
    }

    #[test]
    fn recursive_merges_children_into_parent() {
        // count_threshold=2 → recursive_threshold=2
        let engine = AggregationEngine::new(create_chain(1, 10), 3600, 2);
        engine.load_aggregation(leaf_summary("c1", "root1", 3, 100));
        engine.load_aggregation(leaf_summary("c2", "root2", 5, 200));

        let parent = engine
            .aggregate(StrategyType::Recursive)
            .expect("应生成父 summary");
        assert_eq!(parent.level, 2);
        assert_eq!(parent.metadata_count, 8);
        assert_eq!(parent.parent_summaries.len(), 2);
        assert!(parent.parent_summaries.contains(&"c1".to_string()));
        assert!(parent.parent_summaries.contains(&"c2".to_string()));
        // 父 merkle_root 由子 root 按稳定顺序聚合得到。
        let expected = build_merkle_root(&["root1".to_string(), "root2".to_string()]);
        assert_eq!(parent.merkle_root, expected);
        assert_eq!(
            parent.statistics.get("total_size").and_then(|v| v.as_i64()),
            Some(300)
        );

        // 子 summary 已标记 merged,再次递归不应重复合并同一批。
        let all = engine.get_all_aggregations();
        let merged_children = all.iter().filter(|s| s.level == 1 && s.is_merged).count();
        assert_eq!(merged_children, 2);
    }

    #[test]
    fn recursive_needs_threshold_children() {
        let engine = AggregationEngine::new(create_chain(1, 10), 3600, 2);
        engine.load_aggregation(leaf_summary("c1", "root1", 3, 100));
        // 只有 1 个子 summary,未达阈值 2。
        assert!(engine.aggregate(StrategyType::Recursive).is_none());
    }

    #[test]
    fn recursive_builds_multi_level() {
        let engine = AggregationEngine::new(create_chain(1, 10), 3600, 2);
        // 4 个 level-1 → 合并 2 次得到 2 个 level-2 → 再合并得到 1 个 level-3。
        for i in 0..4 {
            engine.load_aggregation(leaf_summary(
                &format!("c{}", i),
                &format!("root{}", i),
                1,
                10,
            ));
        }
        // 第一次合并前 2 个未合并 level-1。
        let p1 = engine.aggregate(StrategyType::Recursive).unwrap();
        assert_eq!(p1.level, 2);
        let p2 = engine.aggregate(StrategyType::Recursive).unwrap();
        assert_eq!(p2.level, 2);
        // 现在有 2 个未合并 level-2 → 合并为 level-3。
        let p3 = engine.aggregate(StrategyType::Recursive).unwrap();
        assert_eq!(p3.level, 3);
        assert_eq!(p3.parent_summaries.len(), 2);
    }
}
