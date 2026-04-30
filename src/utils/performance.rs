use std::time::{Duration, Instant};
use tracing::{info, warn};

/// 性能计时器
pub struct Timer {
    name: String,
    start: Instant,
    threshold: Option<Duration>,
}

impl Timer {
    /// 创建计时器
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            start: Instant::now(),
            threshold: None,
        }
    }

    /// 设置警告阈值
    pub fn with_threshold(mut self, threshold: Duration) -> Self {
        self.threshold = Some(threshold);
        self
    }

    /// 获取已用时间
    pub fn elapsed(&self) -> Duration {
        self.start.elapsed()
    }

    /// 获取已用时间（毫秒）
    pub fn elapsed_ms(&self) -> u128 {
        self.elapsed().as_millis()
    }

    /// 停止并记录
    pub fn stop(self) -> Duration {
        let elapsed = self.elapsed();

        if let Some(threshold) = self.threshold {
            if elapsed > threshold {
                warn!(
                    "{} 耗时 {:?}，超过阈值 {:?}",
                    self.name, elapsed, threshold
                );
            } else {
                info!("{} 耗时 {:?}", self.name, elapsed);
            }
        } else {
            info!("{} 耗时 {:?}", self.name, elapsed);
        }

        elapsed
    }
}

impl Drop for Timer {
    fn drop(&mut self) {
        // 如果没有显式调用 stop，在 drop 时记录
    }
}

/// 性能统计
#[derive(Debug, Clone, Default)]
pub struct PerformanceStats {
    pub count: u64,
    pub total_time: Duration,
    pub min_time: Option<Duration>,
    pub max_time: Option<Duration>,
}

impl PerformanceStats {
    /// 创建统计
    pub fn new() -> Self {
        Self::default()
    }

    /// 记录一次执行
    pub fn record(&mut self, duration: Duration) {
        self.count += 1;
        self.total_time += duration;

        self.min_time = Some(match self.min_time {
            Some(min) => min.min(duration),
            None => duration,
        });

        self.max_time = Some(match self.max_time {
            Some(max) => max.max(duration),
            None => duration,
        });
    }

    /// 获取平均时间
    pub fn average(&self) -> Option<Duration> {
        if self.count == 0 {
            return None;
        }
        Some(self.total_time / self.count as u32)
    }

    /// 获取统计摘要
    pub fn summary(&self) -> String {
        format!(
            "count={}, total={:?}, avg={:?}, min={:?}, max={:?}",
            self.count,
            self.total_time,
            self.average(),
            self.min_time,
            self.max_time
        )
    }
}

/// 性能监控器
pub struct PerformanceMonitor {
    stats: parking_lot::RwLock<std::collections::HashMap<String, PerformanceStats>>,
}

impl PerformanceMonitor {
    /// 创建监控器
    pub fn new() -> Self {
        Self {
            stats: parking_lot::RwLock::new(std::collections::HashMap::new()),
        }
    }

    /// 记录执行时间
    pub fn record(&self, name: &str, duration: Duration) {
        let mut stats = self.stats.write();
        stats
            .entry(name.to_string())
            .or_insert_with(PerformanceStats::new)
            .record(duration);
    }

    /// 获取统计
    pub fn get_stats(&self, name: &str) -> Option<PerformanceStats> {
        let stats = self.stats.read();
        stats.get(name).cloned()
    }

    /// 获取所有统计
    pub fn get_all_stats(&self) -> std::collections::HashMap<String, PerformanceStats> {
        self.stats.read().clone()
    }

    /// 清空统计
    pub fn clear(&self) {
        let mut stats = self.stats.write();
        stats.clear();
    }

    /// 计时执行
    pub fn time<F, R>(&self, name: &str, f: F) -> R
    where
        F: FnOnce() -> R,
    {
        let start = Instant::now();
        let result = f();
        self.record(name, start.elapsed());
        result
    }

    /// 异步计时执行
    pub async fn time_async<F, R>(&self, name: &str, f: F) -> R
    where
        F: std::future::Future<Output = R>,
    {
        let start = Instant::now();
        let result = f.await;
        self.record(name, start.elapsed());
        result
    }
}

impl Default for PerformanceMonitor {
    fn default() -> Self {
        Self::new()
    }
}

/// 全局性能监控器
lazy_static::lazy_static! {
    pub static ref GLOBAL_MONITOR: PerformanceMonitor = PerformanceMonitor::new();
}

/// 计时宏
#[macro_export]
macro_rules! timed {
    ($name:expr, $body:expr) => {{
        let _timer = $crate::utils::Timer::new($name);
        let result = $body;
        _timer.stop();
        result
    }};
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread::sleep;

    #[test]
    fn test_timer() {
        let timer = Timer::new("test");
        sleep(Duration::from_millis(10));
        let elapsed = timer.stop();
        assert!(elapsed >= Duration::from_millis(10));
    }

    #[test]
    fn test_performance_stats() {
        let mut stats = PerformanceStats::new();

        stats.record(Duration::from_millis(10));
        stats.record(Duration::from_millis(20));
        stats.record(Duration::from_millis(30));

        assert_eq!(stats.count, 3);
        assert_eq!(stats.min_time, Some(Duration::from_millis(10)));
        assert_eq!(stats.max_time, Some(Duration::from_millis(30)));
    }

    #[test]
    fn test_performance_monitor() {
        let monitor = PerformanceMonitor::new();

        monitor.time("test_op", || {
            sleep(Duration::from_millis(5));
        });

        let stats = monitor.get_stats("test_op").unwrap();
        assert_eq!(stats.count, 1);
    }
}
