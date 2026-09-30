use chrono::{DateTime, Utc};
use parking_lot::Mutex;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::time::interval;

use super::{AggregationEngine, AggregationSummary, StrategyType};

/// 汇总回调函数
pub type AggregationCallback = Box<dyn Fn(&AggregationSummary) + Send + Sync>;

/// 汇总调度器
pub struct Scheduler {
    engine: Arc<AggregationEngine>,
    check_interval: Duration,
    running: Mutex<bool>,
    stop_tx: Mutex<Option<mpsc::Sender<()>>>,
    callback: Mutex<Option<Arc<AggregationCallback>>>,
}

impl Scheduler {
    /// 创建调度器
    pub fn new(engine: Arc<AggregationEngine>, check_interval: Duration) -> Self {
        Self {
            engine,
            check_interval,
            running: Mutex::new(false),
            stop_tx: Mutex::new(None),
            callback: Mutex::new(None),
        }
    }

    /// 设置回调函数
    pub fn set_callback(&self, callback: AggregationCallback) {
        let mut cb = self.callback.lock();
        *cb = Some(Arc::new(callback));
    }

    /// 启动调度器
    pub fn start(&self) {
        let mut running = self.running.lock();
        if *running {
            return;
        }
        *running = true;

        let (stop_tx, mut stop_rx) = mpsc::channel::<()>(1);
        *self.stop_tx.lock() = Some(stop_tx);

        let engine = self.engine.clone();
        let check_interval = self.check_interval;
        let callback = self.callback.lock().clone();

        tokio::spawn(async move {
            let mut ticker = interval(check_interval);

            loop {
                tokio::select! {
                    _ = stop_rx.recv() => {
                        break;
                    }
                    _ = ticker.tick() => {
                        Self::check_and_aggregate(&engine, callback.as_ref());
                    }
                }
            }
        });
    }

    /// 停止调度器
    pub fn stop(&self) {
        let mut running = self.running.lock();
        if !*running {
            return;
        }
        *running = false;

        if let Some(tx) = self.stop_tx.lock().take() {
            let _ = tx.try_send(());
        }
    }

    /// 检查是否运行中
    pub fn is_running(&self) -> bool {
        *self.running.lock()
    }

    /// 检查并执行汇总
    fn check_and_aggregate(
        engine: &AggregationEngine,
        callback: Option<&Arc<AggregationCallback>>,
    ) {
        let (should_agg, strategy) = engine.should_aggregate();
        if !should_agg {
            return;
        }

        if let Some(strategy_type) = strategy {
            if let Some(agg) = engine.aggregate(strategy_type) {
                if let Some(cb) = callback {
                    cb(&agg);
                }
            }
        }
    }

    /// 立即触发汇总
    pub fn trigger_now(&self, strategy: StrategyType) -> Option<AggregationSummary> {
        self.engine.aggregate(strategy)
    }

    /// 获取调度器状态
    pub fn get_status(&self) -> SchedulerStatus {
        SchedulerStatus {
            running: *self.running.lock(),
            check_interval_secs: self.check_interval.as_secs(),
            last_aggregation: self.engine.get_last_aggregation(),
            aggregated_count: self.engine.get_aggregated_count(),
        }
    }
}

/// 调度器状态
#[derive(Debug, Clone, serde::Serialize)]
pub struct SchedulerStatus {
    pub running: bool,
    pub check_interval_secs: u64,
    pub last_aggregation: DateTime<Utc>,
    pub aggregated_count: usize,
}

/// 创建共享的 Scheduler 实例
pub fn create_scheduler(
    engine: Arc<AggregationEngine>,
    check_interval_secs: u64,
) -> Arc<Scheduler> {
    Arc::new(Scheduler::new(
        engine,
        Duration::from_secs(check_interval_secs),
    ))
}
