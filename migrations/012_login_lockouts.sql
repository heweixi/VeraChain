-- 用户名维度指数退避锁定状态,与 login_rate_counters 的窗口计数分离
CREATE TABLE IF NOT EXISTS login_lockouts (
    key TEXT PRIMARY KEY NOT NULL,
    level INTEGER NOT NULL,
    locked_until INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_login_lockouts_until ON login_lockouts(locked_until)
