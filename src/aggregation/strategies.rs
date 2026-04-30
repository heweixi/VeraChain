use chrono::{DateTime, Utc};
use parking_lot::Mutex;
use std::time::Duration;

/// 汇总策略 trait
pub trait AggregationStrategy: Send + Sync {
    /// 检查是否应该汇总
    fn should_aggregate(&self, metadata_count: usize) -> bool;
    
    /// 获取策略类型
    fn strategy_type(&self) -> &str;
    
    /// 重置状态
    fn reset(&self);
}

/// 定时汇总策略
pub struct TimeBasedStrategy {
    interval: Duration,
    last_aggregation: Mutex<DateTime<Utc>>,
}

impl TimeBasedStrategy {
    /// 创建定时汇总策略
    pub fn new(interval: Duration) -> Self {
        Self {
            interval,
            last_aggregation: Mutex::new(Utc::now()),
        }
    }

    /// 获取时间范围
    pub fn get_time_range(&self) -> (DateTime<Utc>, DateTime<Utc>) {
        let last = *self.last_aggregation.lock();
        (last, Utc::now())
    }
}

impl AggregationStrategy for TimeBasedStrategy {
    fn should_aggregate(&self, _metadata_count: usize) -> bool {
        let last = *self.last_aggregation.lock();
        let elapsed = Utc::now().signed_duration_since(last);
        elapsed >= chrono::Duration::from_std(self.interval).unwrap_or_default()
    }

    fn strategy_type(&self) -> &str {
        "time_based"
    }

    fn reset(&self) {
        *self.last_aggregation.lock() = Utc::now();
    }
}

/// 定量汇总策略
pub struct CountBasedStrategy {
    threshold: usize,
    max_wait_time: Duration,
    last_aggregation: Mutex<DateTime<Utc>>,
}

impl CountBasedStrategy {
    /// 创建定量汇总策略
    pub fn new(threshold: usize, max_wait_time: Duration) -> Self {
        Self {
            threshold,
            max_wait_time,
            last_aggregation: Mutex::new(Utc::now()),
        }
    }

    /// 获取阈值
    pub fn threshold(&self) -> usize {
        self.threshold
    }
}

impl AggregationStrategy for CountBasedStrategy {
    fn should_aggregate(&self, metadata_count: usize) -> bool {
        // 检查数量阈值
        if metadata_count >= self.threshold {
            return true;
        }

        // 检查最大等待时间
        let last = *self.last_aggregation.lock();
        let elapsed = Utc::now().signed_duration_since(last);
        if elapsed >= chrono::Duration::from_std(self.max_wait_time).unwrap_or_default() && metadata_count > 0 {
            return true;
        }

        false
    }

    fn strategy_type(&self) -> &str {
        "count_based"
    }

    fn reset(&self) {
        *self.last_aggregation.lock() = Utc::now();
    }
}

/// 递归汇总策略
pub struct RecursiveStrategy {
    level: u32,
    threshold: usize,
}

impl RecursiveStrategy {
    /// 创建递归汇总策略
    pub fn new(level: u32, threshold: usize) -> Self {
        Self { level, threshold }
    }

    /// 获取汇总级别
    pub fn level(&self) -> u32 {
        self.level
    }
}

impl AggregationStrategy for RecursiveStrategy {
    fn should_aggregate(&self, aggregation_count: usize) -> bool {
        aggregation_count >= self.threshold
    }

    fn strategy_type(&self) -> &str {
        "recursive"
    }

    fn reset(&self) {
        // 递归策略不需要重置
    }
}

/// 策略类型枚举
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StrategyType {
    TimeBased,
    CountBased,
    Recursive,
    Manual,
}

impl std::fmt::Display for StrategyType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StrategyType::TimeBased => write!(f, "time_based"),
            StrategyType::CountBased => write!(f, "count_based"),
            StrategyType::Recursive => write!(f, "recursive"),
            StrategyType::Manual => write!(f, "manual"),
        }
    }
}

impl std::str::FromStr for StrategyType {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "time_based" => Ok(StrategyType::TimeBased),
            "count_based" => Ok(StrategyType::CountBased),
            "recursive" => Ok(StrategyType::Recursive),
            "manual" => Ok(StrategyType::Manual),
            _ => Err(format!("Unknown strategy type: {}", s)),
        }
    }
}
