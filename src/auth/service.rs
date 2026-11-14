use parking_lot::RwLock;
use std::collections::HashMap;
use std::sync::Arc;

use super::{
    validate_new_password, ChangePasswordRequest, JwtHandler, LoginRequest, LoginResponse,
    RegisterRequest, Role, User,
};
use crate::crypto::{hash_password, verify_password};
use crate::error::{DataChainError, Result};
use crate::storage::{AuditEvent, SessionRecord, Storage, UnlockOutcome};

/// 登录请求的客户端上下文,用于会话审计字段。
#[derive(Debug, Clone, Default)]
pub struct LoginContext {
    /// 对端 IP(来自连接信息,不信任 XFF)。仅用于计算 HMAC 摘要,不落盘、不进日志。
    pub client_ip: Option<String>,
    /// 原始 User-Agent,入库前会去控制字符并截断。
    pub user_agent: Option<String>,
}

/// 登录限速参数(固定窗口)。
#[derive(Debug, Clone, Copy)]
pub struct LoginLimits {
    /// 单个用户名在一个窗口内允许的尝试次数。
    pub user_max_attempts: i64,
    /// 单个客户端 IP 在一个窗口内允许的尝试次数。
    pub ip_max_attempts: i64,
    /// 窗口长度(秒)。
    pub window_secs: i64,
}

impl Default for LoginLimits {
    fn default() -> Self {
        Self {
            user_max_attempts: 5,
            ip_max_attempts: 20,
            window_secs: 15 * 60,
        }
    }
}

/// 用户名维度的指数退避锁定策略(秒)。
#[derive(Debug, Clone, Copy)]
pub struct LockoutPolicy {
    /// 首次锁定时长。
    pub base_secs: i64,
    /// 锁定时长上限。
    pub max_secs: i64,
    /// 距上次锁定结束超过该时长后,退避级别归零。
    pub reset_secs: i64,
}

impl Default for LockoutPolicy {
    fn default() -> Self {
        Self {
            base_secs: 900,
            max_secs: 3600,
            reset_secs: 86400,
        }
    }
}

/// 认证服务的可配置参数;`Default` 等于此前的硬编码行为。
#[derive(Debug, Clone, Copy)]
pub struct AuthSettings {
    /// access token 有效期(小时)。
    pub access_expire_hours: u64,
    /// refresh token 有效期(天)。
    pub refresh_expire_days: u64,
    pub login_limits: LoginLimits,
    pub lockout: LockoutPolicy,
    /// 注册、CLI 创建、改密与 CLI 重置密码时新密码的最小字符数。
    pub password_min_length: usize,
}

impl Default for AuthSettings {
    fn default() -> Self {
        Self {
            access_expire_hours: 24,
            refresh_expire_days: 7,
            login_limits: LoginLimits::default(),
            lockout: LockoutPolicy::default(),
            password_min_length: 8,
        }
    }
}

/// 无法取得对端地址时(如进程内 oneshot 测试)IP 维度使用的占位值。
const UNKNOWN_CLIENT_IP: &str = "unknown";

/// 用户名限速 key 的最大字符数,防止超长用户名撑大计数器表。
const USERNAME_KEY_MAX_CHARS: usize = 128;

fn normalize_username_key(username: &str) -> String {
    username
        .chars()
        .filter(|c| !c.is_control())
        .flat_map(char::to_lowercase)
        .take(USERNAME_KEY_MAX_CHARS)
        .collect()
}

/// 登录限速的用户名维度 key;login 与 unlock 共用,保证两处一致。
fn login_user_key(username: &str) -> String {
    format!("user:{}", normalize_username_key(username))
}

/// 改密限速的用户维度 key;change_password 与 unlock 共用。
fn pwchg_key(user_id: &str) -> String {
    format!("pwchg:{}", user_id)
}

/// 限速门拒绝信息:建议的 Retry-After(秒)与审计 reason。
struct RateDenial {
    retry_after_secs: u64,
    reason: &'static str,
}

/// 不存在用户时用于抹平耗时的 bcrypt 哈希,cost 与真实密码一致(同为 `hash_password`)。
fn dummy_password_hash() -> &'static str {
    static DUMMY: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    // hash 失败不能退化为空串(会让时序保护无声失效),直接 panic 暴露问题。
    DUMMY.get_or_init(|| {
        hash_password("datachain-dummy-password-for-timing")
            .expect("生成 dummy bcrypt 哈希失败,无法保证登录时序保护")
    })
}

/// 在 blocking 线程池中哈希密码,避免 bcrypt 占用 tokio 工作线程。
/// 错误文本固定,不含密码或哈希。
async fn hash_password_blocking(password: String) -> Result<String> {
    tokio::task::spawn_blocking(move || hash_password(&password))
        .await
        .map_err(|_| DataChainError::Internal("password hashing task failed".to_string()))?
        .map_err(|_| DataChainError::Internal("password hashing failed".to_string()))
}

/// 在 blocking 线程池中验证密码。`hash` 为 `None` 时对 dummy 哈希验证(结果恒为 false),
/// 用于抹平不存在用户的耗时;dummy 的 OnceLock 首次初始化也在闭包内完成。
async fn verify_password_blocking(password: String, hash: Option<String>) -> Result<bool> {
    tokio::task::spawn_blocking(move || match hash {
        Some(h) => verify_password(&password, &h),
        None => {
            let _ = verify_password(&password, dummy_password_hash());
            false
        }
    })
    .await
    .map_err(|_| DataChainError::Internal("password verification task failed".to_string()))
}

/// user_agent 入库长度上限(字符数)。
const USER_AGENT_MAX_CHARS: usize = 200;

/// 去控制字符并截断,防止日志注入与超长写入。
fn sanitize_user_agent(raw: &str) -> String {
    raw.chars()
        .filter(|c| !c.is_control())
        .take(USER_AGENT_MAX_CHARS)
        .collect()
}

/// 会话列表对外展示的视图:不含 ip_hash、refresh family、token 或 jti。
#[derive(Debug, Clone, serde::Serialize)]
pub struct SessionView {
    pub id: String,
    pub created_at: i64,
    pub last_seen_at: i64,
    pub expires_at: i64,
    pub user_agent: Option<String>,
    /// 脱敏 IP 提示,如 `203.0.x.x`。
    pub ip_hint: Option<String>,
    /// 是否为发起本次请求的会话。
    pub current: bool,
}

/// 管理员视角的会话视图:只含 id、时间戳与脱敏 IP 提示,
/// 不含 ip_hash、refresh family、token、jti、user_agent、撤销信息。
#[derive(Debug, Clone, serde::Serialize)]
pub struct AdminSessionView {
    pub id: String,
    pub created_at: i64,
    pub last_seen_at: i64,
    pub expires_at: i64,
    /// 脱敏 IP 提示,如 `203.0.x.x`。
    pub ip_hint: Option<String>,
    /// 管理员视角下恒为 false。
    pub current: bool,
}

/// IP 脱敏:IPv4 保留前两段,IPv6 保留前两组;无法解析(如占位值)返回 `None`。
fn mask_ip(ip: &str) -> Option<String> {
    match ip.parse::<std::net::IpAddr>().ok()? {
        std::net::IpAddr::V4(v4) => {
            let o = v4.octets();
            Some(format!("{}.{}.x.x", o[0], o[1]))
        }
        std::net::IpAddr::V6(v6) => {
            let seg = v6.segments();
            Some(format!("{:x}:{:x}:x:x:x:x:x:x", seg[0], seg[1]))
        }
    }
}

/// refresh 复用/双花导致整族撤销的原因前缀;其他撤销原因(登出、停用等)不算复用。
const REUSE_REASON: &str = "refresh token reuse detected";
const DOUBLE_SPEND_REASON: &str = "refresh token double-spend detected";

/// refresh 流程中逐步填充的失败审计线索(不含 token/jti/family)。
#[derive(Debug, Default)]
struct RefreshTrace {
    user_id: Option<String>,
    session_id: Option<String>,
    /// 流程内显式指定的 reason;未指定时按错误类型推断。
    reason: Option<&'static str>,
}

impl RefreshTrace {
    /// 返回应审计的 reason;复用与 5xx 类(数据库/存储/数据损坏)返回 `None`,不写 `refresh_failure`。
    fn failure_reason(&self, err: &DataChainError) -> Option<&'static str> {
        match err {
            DataChainError::TokenReuseDetected
            | DataChainError::DatabaseError(_)
            | DataChainError::StorageError(_)
            | DataChainError::DataCorruption { .. } => None,
            DataChainError::TokenExpired => Some("token_expired"),
            DataChainError::UserNotFound(_) => Some("user_inactive"),
            DataChainError::InvalidToken => Some(self.reason.unwrap_or("invalid_token")),
            _ => None,
        }
    }
}

/// HMAC-SHA256(RFC 2104)。仅用于派生 IP 摘要,避免引入额外依赖。
fn hmac_sha256(key: &[u8], message: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    const BLOCK: usize = 64;
    let mut k = [0u8; BLOCK];
    if key.len() > BLOCK {
        k[..32].copy_from_slice(&Sha256::digest(key));
    } else {
        k[..key.len()].copy_from_slice(key);
    }
    let mut ipad = [0x36u8; BLOCK];
    let mut opad = [0x5cu8; BLOCK];
    for ((inner_byte, outer_byte), key_byte) in ipad.iter_mut().zip(opad.iter_mut()).zip(k.iter()) {
        *inner_byte ^= key_byte;
        *outer_byte ^= key_byte;
    }
    let mut inner = Sha256::new();
    inner.update(ipad);
    inner.update(message);
    let inner = inner.finalize();
    let mut outer = Sha256::new();
    outer.update(opad);
    outer.update(inner);
    outer.finalize().into()
}

/// 认证服务
pub struct AuthService {
    users: RwLock<HashMap<String, User>>, // user_id -> User
    username_index: RwLock<HashMap<String, String>>, // username -> user_id
    email_index: RwLock<HashMap<String, String>>, // email -> user_id
    jwt_handler: JwtHandler,
    storage: Arc<Storage>,
    /// 由 JWT 密钥派生的 IP 摘要密钥(与签名用途域分离)。
    ip_hash_key: Vec<u8>,
    login_limits: LoginLimits,
    lockout: LockoutPolicy,
    password_min_length: usize,
}

impl AuthService {
    /// 创建认证服务(其余参数取默认值)
    pub fn new(jwt_secret: String, jwt_expire_hours: u64, storage: Arc<Storage>) -> Self {
        Self::with_settings(
            jwt_secret,
            storage,
            AuthSettings {
                access_expire_hours: jwt_expire_hours,
                ..AuthSettings::default()
            },
        )
    }

    /// 按完整参数创建认证服务。
    pub fn with_settings(
        jwt_secret: String,
        storage: Arc<Storage>,
        settings: AuthSettings,
    ) -> Self {
        Self {
            users: RwLock::new(HashMap::new()),
            username_index: RwLock::new(HashMap::new()),
            email_index: RwLock::new(HashMap::new()),
            login_limits: settings.login_limits,
            lockout: settings.lockout,
            password_min_length: settings.password_min_length,
            ip_hash_key: format!("datachain-ip-hash:{}", jwt_secret).into_bytes(),
            jwt_handler: JwtHandler::new(jwt_secret, settings.access_expire_hours)
                .with_refresh_expire_days(settings.refresh_expire_days),
            storage,
        }
    }

    /// 当前生效的用户名维度指数退避锁定策略(登录流程已使用)。
    pub fn lockout_policy(&self) -> LockoutPolicy {
        self.lockout
    }

    /// 当前生效的改密最小密码长度(改密接口已使用)。
    pub fn password_min_length(&self) -> usize {
        self.password_min_length
    }

    /// 覆盖登录限速参数(默认 5 次/用户名、20 次/IP、15 分钟窗口)。
    pub fn with_login_limits(mut self, limits: LoginLimits) -> Self {
        self.login_limits = limits;
        self
    }

    /// 客户端 IP 的 HMAC 摘要:取前 16 字节的十六进制(32 字符)。
    pub fn hash_client_ip(&self, ip: &str) -> String {
        hex::encode(&hmac_sha256(&self.ip_hash_key, ip.as_bytes())[..16])
    }

    /// 写入认证审计日志。失败只记 error 日志,绝不阻塞或改变认证结果。
    async fn audit(&self, event: AuditEvent) {
        if let Err(e) = self.storage.append_audit_event(&event).await {
            tracing::error!("写入认证审计日志失败: {}", e);
        }
    }

    /// 记录一次被锁定/限速拒绝的登录尝试(`login_locked`,result `denied`)。
    async fn audit_login_locked(&self, req: &LoginRequest, ctx: &LoginContext, reason: &str) {
        self.audit(
            AuditEvent::new("login_locked", "denied")
                .username(&req.username)
                .client(self.ctx_ip_hash(ctx).as_deref(), ctx.user_agent.as_deref())
                .reason(reason),
        )
        .await;
    }

    /// 限速门(登录与改密共用,key 由调用方决定):
    /// 1. `user_key` 处于指数退避锁定期 => 直接拒绝,不计数;
    /// 2. 对 `ip_key`、`user_key` 原子递增固定窗口计数;
    /// 3. `user_key` 超限 => 落指数退避锁;`ip_key` 超限 => 固定窗口 Retry-After;同时超限取较大值。
    ///
    /// 通过返回 `Ok(Ok(()))`(名额已占用,成功后应调用 [`Self::release_rate_gate`] 归还);
    /// 被拒返回 `Ok(Err(denial))`;存储故障返回 `Err`。
    async fn enter_rate_gate(
        &self,
        user_key: &str,
        ip_key: &str,
        now: i64,
    ) -> Result<std::result::Result<(), RateDenial>> {
        let limits = self.login_limits;
        if let Some(locked_until) = self.storage.get_login_lock(user_key, now).await? {
            return Ok(Err(RateDenial {
                retry_after_secs: (locked_until - now).max(1) as u64,
                reason: "account locked",
            }));
        }

        let (ip_count, window_start) = self
            .storage
            .incr_login_counter(ip_key, now, limits.window_secs)
            .await?;
        let (user_count, _) = self
            .storage
            .incr_login_counter(user_key, now, limits.window_secs)
            .await?;
        let ip_exceeded = ip_count > limits.ip_max_attempts;
        let user_exceeded = user_count > limits.user_max_attempts;
        if !(ip_exceeded || user_exceeded) {
            return Ok(Ok(()));
        }

        let mut retry_after = 0i64;
        if user_exceeded {
            let locked_until = self
                .storage
                .lock_login_key(
                    user_key,
                    now,
                    self.lockout.base_secs,
                    self.lockout.max_secs,
                    self.lockout.reset_secs,
                )
                .await?;
            retry_after = retry_after.max(locked_until - now);
        }
        if ip_exceeded {
            retry_after = retry_after.max(window_start + limits.window_secs - now);
        }
        Ok(Err(RateDenial {
            retry_after_secs: retry_after.max(1) as u64,
            reason: if user_exceeded {
                "account locked"
            } else {
                "rate limit exceeded"
            },
        }))
    }

    /// 归还 [`Self::enter_rate_gate`] 本次占用的两个名额(不会低于 0,也不清零他人累积的失败)。
    async fn release_rate_gate(&self, user_key: &str, ip_key: &str, now: i64) -> Result<()> {
        let window_secs = self.login_limits.window_secs;
        self.storage
            .decr_login_counter(user_key, now, window_secs)
            .await?;
        self.storage
            .decr_login_counter(ip_key, now, window_secs)
            .await?;
        Ok(())
    }

    /// 改密:顺序为 策略校验 → 限速门(`pwchg:<user_id>` + `ip:<hash>`)→ 验旧密码
    /// → 新旧相同检查 → 哈希新密码并归还名额 → 单事务更新哈希并撤销其他会话
    /// → 同步内存哈希 → 审计。
    ///
    /// `claims.sid` 为 `None`(旧 token)时无法确定当前会话,撤销全部会话。
    pub async fn change_password(
        &self,
        claims: &super::Claims,
        req: &ChangePasswordRequest,
        ctx: &LoginContext,
    ) -> Result<()> {
        // 1. 策略校验:失败不消耗配额。
        validate_new_password(&req.new_password, self.password_min_length)
            .map_err(DataChainError::PasswordRejected)?;

        let user_id = claims.sub.as_str();
        let ip_hash = self.ctx_ip_hash(ctx);
        let audit_event = |event_type: &str, result: &str, reason: &str| {
            let mut event = AuditEvent::new(event_type, result)
                .user(user_id)
                .client(ip_hash.as_deref(), ctx.user_agent.as_deref())
                .reason(reason);
            if let Some(sid) = claims.sid.as_deref() {
                event = event.session(sid);
            }
            event
        };

        // 2. 限速门:独立 key,锁定不影响登录。
        let now = self.storage.now_secs();
        let user_key = pwchg_key(user_id);
        let ip_key = format!(
            "ip:{}",
            self.hash_client_ip(ctx.client_ip.as_deref().unwrap_or(UNKNOWN_CLIENT_IP))
        );
        if let Err(denial) = self.enter_rate_gate(&user_key, &ip_key, now).await? {
            self.audit(audit_event(
                "password_change_locked",
                "denied",
                denial.reason,
            ))
            .await;
            return Err(DataChainError::TooManyAttempts {
                retry_after_secs: denial.retry_after_secs,
            });
        }

        // 3. 以 SQLite 中的哈希验证旧密码;用户行缺失也走同 cost 的 bcrypt 抹平耗时。
        let stored_hash = self.storage.get_user_password_hash(user_id).await?;
        let old_ok =
            verify_password_blocking(req.old_password.clone(), stored_hash.clone()).await?;
        let old_hash = match stored_hash {
            Some(hash) if old_ok => hash,
            _ => {
                // 配额不归还:失败计入 pwchg 锁定。
                self.audit(audit_event(
                    "password_change_failure",
                    "failure",
                    "bad old password",
                ))
                .await;
                return Err(DataChainError::InvalidCredentials);
            }
        };

        // 4. 旧密码通过后才比较新旧是否相同,避免探测。
        if req.new_password == req.old_password {
            return Err(DataChainError::PasswordRejected(
                "new password must differ from old password",
            ));
        }

        // 5. 哈希新密码,归还两个名额。
        let new_hash = hash_password_blocking(req.new_password.clone()).await?;
        self.release_rate_gate(&user_key, &ip_key, now).await?;

        // 6. 单事务:乐观更新哈希(旧哈希已被并发改密替换则 0 行)+ 撤销其他会话。
        let revoked = self
            .storage
            .update_user_password_and_revoke_other_sessions(
                user_id,
                &old_hash,
                &new_hash,
                claims.sid.as_deref(),
                "password changed",
                self.jwt_handler.refresh_expire_secs(),
            )
            .await?;
        let Some(revoked) = revoked else {
            self.audit(audit_event(
                "password_change_failure",
                "failure",
                "concurrent change",
            ))
            .await;
            return Err(DataChainError::InvalidCredentials);
        };

        // 7. 提交后同步内存哈希(login 校验用内存副本)。
        if let Some(user) = self.users.write().get_mut(user_id) {
            user.password_hash = new_hash;
        }

        // 8. 审计(不含任何密码内容)。
        self.audit(audit_event(
            "password_changed",
            "success",
            &format!("revoked {} other sessions", revoked.len()),
        ))
        .await;
        Ok(())
    }

    /// 运维重置密码(CLI `user passwd`):不验旧密码、不走限速门。
    ///
    /// 顺序:策略校验 → blocking 池哈希 → 单事务改哈希并撤销全部会话 → 同步内存哈希
    /// → 审计 `password_reset`(无 actor,不含任何密码内容)。返回被撤销的会话数。
    /// 用户不存在返回 `UserNotFound`。
    pub async fn reset_password(
        &self,
        target_user_id: &str,
        new_password: &str,
        ctx: &LoginContext,
    ) -> Result<u64> {
        validate_new_password(new_password, self.password_min_length)
            .map_err(DataChainError::PasswordRejected)?;
        let new_hash = hash_password_blocking(new_password.to_string()).await?;
        let revoked = self
            .storage
            .set_user_password_and_revoke_all_sessions(
                target_user_id,
                &new_hash,
                "password reset",
                self.jwt_handler.refresh_expire_secs(),
            )
            .await?
            .ok_or_else(|| DataChainError::UserNotFound(target_user_id.to_string()))?;

        if let Some(user) = self.users.write().get_mut(target_user_id) {
            user.password_hash = new_hash;
        }

        self.audit(
            AuditEvent::new("password_reset", "success")
                .user(target_user_id)
                .client(self.ctx_ip_hash(ctx).as_deref(), ctx.user_agent.as_deref())
                .reason(&format!("cli reset, revoked {} sessions", revoked)),
        )
        .await;
        Ok(revoked)
    }

    /// 解锁用户:清除其登录(`user:<规范化用户名>`)与改密(`pwchg:<user_id>`)两个 key 的
    /// 锁与窗口计数(退避级别随锁行一并归零)。不清 IP 维度。
    ///
    /// key 由目标用户的存储用户名经与 login 相同的函数得出。目标不在内存用户表返回
    /// `UserNotFound`。无锁时也写审计 `login_unlocked`(不含密码内容)。
    pub async fn unlock_user(
        &self,
        actor: Option<&str>,
        target_user_id: &str,
        ctx: &LoginContext,
    ) -> Result<UnlockOutcome> {
        let user = self.get_user_by_id(target_user_id)?;
        let keys = [login_user_key(&user.username), pwchg_key(target_user_id)];
        let outcome = self.storage.clear_login_keys(&keys).await?;

        let mut event = AuditEvent::new("login_unlocked", "success")
            .user(target_user_id)
            .client(self.ctx_ip_hash(ctx).as_deref(), ctx.user_agent.as_deref())
            .reason(&format!(
                "cleared locks={} counters={}",
                outcome.locks_cleared, outcome.counters_cleared
            ));
        if let Some(actor) = actor {
            event = event.actor(actor);
        }
        self.audit(event).await;
        Ok(outcome)
    }

    /// 请求上下文里的客户端 IP 摘要(无对端地址时为 `None`)。
    fn ctx_ip_hash(&self, ctx: &LoginContext) -> Option<String> {
        ctx.client_ip.as_deref().map(|ip| self.hash_client_ip(ip))
    }

    /// 公开注册:始终创建普通用户,不接受客户端指定高权限角色。
    ///
    /// 同步方法,bcrypt 会阻塞当前线程且不校验密码策略;请求路径请用 [`Self::register_validated`]。
    pub fn register(&self, req: &RegisterRequest) -> Result<User> {
        self.register_with_role(req, Role::User)
    }

    /// 带密码策略校验的异步注册:策略校验 → blocking 池哈希 → 同时持有三把写锁
    /// (users/username_index/email_index,顺序与 `register_with_role`、`remove_user` 一致)
    /// 复检用户名与邮箱唯一性并插入。并发同名只有一个成功,其余返回 `UserExists`。
    pub async fn register_validated(&self, req: &RegisterRequest, role: Role) -> Result<User> {
        validate_new_password(&req.password, self.password_min_length)
            .map_err(DataChainError::PasswordRejected)?;
        let password_hash = hash_password_blocking(req.password.clone()).await?;
        let user = User::new(req.username.clone(), password_hash, req.email.clone(), role);

        // 持锁区内无 await。
        let mut users = self.users.write();
        let mut username_index = self.username_index.write();
        let mut email_index = self.email_index.write();
        if username_index.contains_key(&req.username) {
            return Err(DataChainError::UserExists(req.username.clone()));
        }
        if email_index.contains_key(&req.email) {
            return Err(DataChainError::UserExists(req.email.clone()));
        }
        username_index.insert(user.username.clone(), user.user_id.clone());
        email_index.insert(user.email.clone(), user.user_id.clone());
        users.insert(user.user_id.clone(), user.clone());
        Ok(user)
    }

    /// 管理/CLI 注册:由受信调用方显式指定角色。
    ///
    /// 同步方法,会阻塞(bcrypt)且不校验密码策略,请求路径请用 [`Self::register_validated`]。
    pub fn register_with_role(&self, req: &RegisterRequest, role: Role) -> Result<User> {
        // 检查用户名唯一性
        {
            let username_index = self.username_index.read();
            if username_index.contains_key(&req.username) {
                return Err(DataChainError::UserExists(req.username.clone()));
            }
        }

        // 检查邮箱唯一性
        {
            let email_index = self.email_index.read();
            if email_index.contains_key(&req.email) {
                return Err(DataChainError::UserExists(req.email.clone()));
            }
        }

        // 哈希密码
        let password_hash =
            hash_password(&req.password).map_err(|e| DataChainError::Internal(e.to_string()))?;

        // 创建用户
        let user = User::new(req.username.clone(), password_hash, req.email.clone(), role);

        // 存储用户
        {
            let mut users = self.users.write();
            let mut username_index = self.username_index.write();
            let mut email_index = self.email_index.write();

            username_index.insert(user.username.clone(), user.user_id.clone());
            email_index.insert(user.email.clone(), user.user_id.clone());
            users.insert(user.user_id.clone(), user.clone());
        }

        Ok(user)
    }

    /// 用户登录。成功时在同一流程内创建会话,access token 携带 `sid`。
    pub async fn login(&self, req: &LoginRequest, ctx: &LoginContext) -> Result<LoginResponse> {
        // 限速:先在事务外对 IP 与用户名两个维度原子递增(不先读后写),超限直接 429。
        // 失败/成功都先计数,成功后再归还名额,避免并发请求绕过阈值。
        let now = self.storage.now_secs();
        let ip_key = format!(
            "ip:{}",
            self.hash_client_ip(ctx.client_ip.as_deref().unwrap_or(UNKNOWN_CLIENT_IP))
        );
        let user_key = login_user_key(&req.username);

        // 限速门(锁定检查 + 计数 + 落锁),登录与改密共用。
        if let Err(denial) = self.enter_rate_gate(&user_key, &ip_key, now).await? {
            self.audit_login_locked(req, ctx, denial.reason).await;
            return Err(DataChainError::TooManyAttempts {
                retry_after_secs: denial.retry_after_secs,
            });
        }

        // 取用户;不存在时也对固定 dummy hash 做一次同 cost 的 bcrypt,抹平耗时差异。
        // 两把读锁不嵌套持有,避免与 register 的写锁顺序形成死锁。
        let found = {
            let id = self.username_index.read().get(&req.username).cloned();
            id.and_then(|id| self.users.read().get(&id).cloned())
        };
        // 密码哈希以 SQLite 为权威(CLI 可能在别的进程里改密/删用户,内存哈希会陈旧)。
        // 内存无该用户或库里无该行,都按未知用户处理(对 dummy 哈希验证,恰好一次 bcrypt)。
        let db_hash = match found.as_ref() {
            Some(user) => self.storage.get_user_password_hash(&user.user_id).await?,
            None => None,
        };
        let found = found.filter(|_| db_hash.is_some());
        let password_ok = verify_password_blocking(req.password.clone(), db_hash).await?;
        // 用户不存在 / 密码错误 / 账户已禁用 统一返回同一错误(禁用账户也先验证密码)。
        // 启用状态以 SQLite 为权威(CLI 可能在别的进程里停用/启用,内存副本会陈旧)。
        // 失败原因只写入审计日志,对外始终是同一个 InvalidCredentials。
        let verdict: std::result::Result<User, (Option<String>, &'static str)> = match found {
            None => Err((None, "unknown user")),
            Some(user) if !password_ok => Err((Some(user.user_id), "bad password")),
            Some(user) => {
                if self.storage.is_user_active(&user.user_id).await? {
                    Ok(user)
                } else {
                    Err((Some(user.user_id), "account inactive"))
                }
            }
        };
        let mut user = match verdict {
            Ok(user) => user,
            Err((user_id, reason)) => {
                let mut event = AuditEvent::new("login_failure", "failure")
                    .username(&req.username)
                    .client(self.ctx_ip_hash(ctx).as_deref(), ctx.user_agent.as_deref())
                    .reason(reason);
                if let Some(user_id) = user_id {
                    event = event.user(&user_id);
                }
                self.audit(event).await;
                return Err(DataChainError::InvalidCredentials);
            }
        };

        // 成功:对两个维度都只归还本次自己占用的名额(净效果为 0),
        // 绝不清零用户名计数——否则能登录大小写变体账户("BOB" 与 "bob" 归一化后同 key)
        // 的攻击者可抵消对受害者累积的失败计数,绕过限速。
        // 归还不会低于 0,也不会让他人累积的失败减少:本次名额是本请求刚递增的那一份。
        self.release_rate_gate(&user_key, &ip_key, now).await?;

        // 更新最后登录时间:只原地改内存里的 last_login,不整条覆盖用户
        // (整条覆盖会把并发改密刚写入的新哈希换回旧哈希)。
        {
            let mut users = self.users.write();
            if let Some(stored) = users.get_mut(&user.user_id) {
                stored.update_last_login();
            }
        }
        user.update_last_login();

        // 生成令牌；登录新建 token-family。
        // 注意：login 不向撤销表写入任何记录，新 family 的令牌默认有效，
        // 进程重启后仍有效直至过期——设计上可接受。
        let family_id = uuid::Uuid::new_v4().to_string();
        let session = SessionRecord {
            id: uuid::Uuid::new_v4().to_string(),
            user_id: user.user_id.clone(),
            refresh_family: family_id.clone(),
            created_at: now,
            last_seen_at: now,
            expires_at: now + self.jwt_handler.refresh_expire_secs(),
            revoked_at: None,
            revoke_reason: None,
            ip_hash: ctx.client_ip.as_deref().map(|ip| self.hash_client_ip(ip)),
            ip_hint: ctx.client_ip.as_deref().and_then(mask_ip),
            user_agent: ctx.user_agent.as_deref().map(sanitize_user_agent),
        };
        self.purge_expired_sessions_lazily(&user.user_id, now).await;
        self.storage.create_session(&session).await?;

        let token_pair = self.jwt_handler.generate_token_pair(
            &user.user_id,
            &user.username,
            user.role,
            &family_id,
            Some(session.id.as_str()),
        )?;

        self.audit(
            AuditEvent::new("login_success", "success")
                .user(&user.user_id)
                .username(&req.username)
                .session(&session.id)
                .client(session.ip_hash.as_deref(), ctx.user_agent.as_deref()),
        )
        .await;

        Ok(LoginResponse {
            token: token_pair.access_token,
            refresh_token: token_pair.refresh_token,
            token_type: token_pair.token_type,
            expires_at: token_pair.expires_at,
            user: user.to_public(),
        })
    }

    /// 验证令牌
    pub fn validate_token(&self, token: &str) -> Result<super::Claims> {
        self.jwt_handler.verify_access_token(token)
    }

    /// 统一的 access token 鉴权:供 HTTP 鉴权中间件、可选鉴权中间件与 WS 握手共用。
    ///
    /// 依次校验:JWT 签名/过期 → (有 `sid` 时)会话存在、属于该用户、未撤销、未过期
    /// → 用户 is_active(SQLite 权威,带短 TTL 缓存;启用状态只信 SQLite)
    /// → 内存用户存在且角色与 claims 一致。
    /// 无 `sid` 的旧 token 跳过会话检查,只查 is_active。
    /// 任一步失败(含查库失败)都返回 `Err`,调用方一律按 401 处理(fail-closed)。
    pub async fn authenticate_access_token(&self, token: &str) -> Result<super::Claims> {
        let claims = self.validate_token(token)?;

        if let Some(sid) = claims.sid.as_deref() {
            let now = chrono::Utc::now().timestamp();
            match self.storage.get_session(sid).await? {
                Some(s)
                    if s.user_id == claims.sub && s.revoked_at.is_none() && s.expires_at > now => {}
                _ => return Err(DataChainError::InvalidToken),
            }
        }

        if !self.storage.is_user_active_cached(&claims.sub).await? {
            return Err(DataChainError::InvalidToken);
        }

        // 角色必须与当前用户一致(角色被修改后旧 token 失效)。
        // 启用状态只信 SQLite(上面已查):内存副本在 CLI 启用后会陈旧,不能再用它拒绝。
        let user = self
            .get_user_by_id(&claims.sub)
            .map_err(|_| DataChainError::InvalidToken)?;
        if user.role.to_string() != claims.role {
            return Err(DataChainError::InvalidToken);
        }
        Ok(claims)
    }

    /// 刷新令牌。
    ///
    /// 采用 token-family 复用检测 + 抢占式撤销收口并发双花：
    /// 1. 解码校验签名/iss/aud/token_type；
    /// 2. 若该 jti 已被撤销，或其所属 family 已被整体撤销 => 判定为复用攻击，
    ///    撤销整个 family 与对应会话并返回 TokenReuseDetected
    ///    (family 因登出/停用等非复用原因被撤销时,返回 InvalidToken,不算复用)；
    /// 3. 校验用户 is_active(SQLite 权威)与会话(family 对应会话存在、属于该用户、
    ///    未撤销、未过期;空 family 的存量旧令牌跳过,轮换时补建会话)；
    /// 4. 对旧 jti 做抢占式撤销（数据库主键唯一性）：
    ///    - 抢占成功 => 本请求独占该旧 token，更新会话 last_seen_at 并签发带 sid 的新令牌对；
    ///    - 抢占失败（jti 已存在）=> 说明被并发请求/之前的轮换先消费，属并发双花，
    ///      撤销整个 family 与会话并返回 TokenReuseDetected。
    ///
    /// 第 2 步的 is_jti_revoked / is_family_revoked 与第 4 步的 revoke_refresh 之间
    /// 本身存在 TOCTOU 窗口，但最终以第 4 步的主键抢占为准绳：即便两个并发请求
    /// 都通过了第 2 步检查，也只有一个能在第 4 步抢占成功，另一个必然失败并触发整族撤销。
    /// 与登出并发时:登出同事务撤销会话并写 family 哨兵行;refresh 在抢占 jti 后以
    /// `touch_session`(仅作用于未撤销会话)收口,会话已被撤销则不签发令牌。
    ///
    /// 存量退化说明：存量旧令牌（family_id 为空串）命中复用时，因无 family 标识，
    /// 只能退化为「单 jti 失效」而非整族失效。这是升级过渡期的已知弱化（旧令牌签发时
    /// 尚无 family 概念），并非安全绕过——过渡期结束、旧令牌全部过期后自然消失。
    pub async fn refresh_token(&self, refresh_token: &str) -> Result<LoginResponse> {
        self.refresh_token_with_context(refresh_token, &LoginContext::default())
            .await
    }

    /// 带客户端上下文的刷新:流程与 [`Self::refresh_token`] 相同,
    /// 失败时(复用与 5xx 类除外)额外写入 `refresh_failure` 审计行。
    /// 审计只含 reason 词表、user_id、session_id、ip_hash、user_agent,不含 token/jti/family。
    pub async fn refresh_token_with_context(
        &self,
        refresh_token: &str,
        ctx: &LoginContext,
    ) -> Result<LoginResponse> {
        let mut trace = RefreshTrace::default();
        let result = self.refresh_token_inner(refresh_token, &mut trace).await;
        if let Err(err) = &result {
            if let Some(reason) = trace.failure_reason(err) {
                let mut event = AuditEvent::new("refresh_failure", "failure")
                    .client(self.ctx_ip_hash(ctx).as_deref(), ctx.user_agent.as_deref())
                    .reason(reason);
                if let Some(user_id) = trace.user_id.as_deref() {
                    event = event.user(user_id);
                }
                if let Some(sid) = trace.session_id.as_deref() {
                    event = event.session(sid);
                }
                self.audit(event).await;
            }
        }
        result
    }

    async fn refresh_token_inner(
        &self,
        refresh_token: &str,
        trace: &mut RefreshTrace,
    ) -> Result<LoginResponse> {
        let claims = self.jwt_handler.parse_refresh_claims(refresh_token)?;
        let user_id = claims.sub.clone();
        trace.user_id = Some(user_id.clone());
        let family_id = claims.family_id.clone();
        // 哨兵行 TTL 取自刷新令牌有效期，避免魔法数（见 Storage::revoke_family）。
        let ttl_secs = self.jwt_handler.refresh_expire_secs();
        let now = chrono::Utc::now().timestamp();

        // 复用检测：jti 已撤销 或 family 已整体撤销。
        // family_id 可能为空（存量旧令牌），此时跳过 family 级判定。
        let jti_revoked = self.storage.is_jti_revoked(&claims.jti).await?;
        let family_revoked = if family_id.is_empty() {
            false
        } else {
            self.storage.is_family_revoked(&user_id, &family_id).await?
        };
        if jti_revoked || family_revoked {
            if family_revoked && !jti_revoked {
                // family 因登出/停用等原因被撤销:不是复用攻击,只拒绝。
                if let Some(session) = self.storage.get_session_by_family(&family_id).await? {
                    let by_reuse = session
                        .revoke_reason
                        .as_deref()
                        .is_some_and(|r| r.starts_with("refresh token"));
                    if session.revoked_at.is_some() && !by_reuse {
                        trace.session_id = Some(session.id.clone());
                        trace.reason = Some("session_revoked");
                        return Err(DataChainError::InvalidToken);
                    }
                }
            }
            let sid = self
                .revoke_family_and_session(&user_id, &family_id, REUSE_REASON, ttl_secs)
                .await?;
            self.audit_reuse(&user_id, sid.as_deref(), REUSE_REASON)
                .await;
            return Err(DataChainError::TokenReuseDetected);
        }

        // 用户状态以 SQLite 为权威(CLI 可能在别的进程里停用)。
        if !self.storage.is_user_active(&user_id).await? {
            trace.reason = Some("user_inactive");
            return Err(DataChainError::InvalidToken);
        }
        let user = {
            let users = self.users.read();
            users
                .get(&user_id)
                .cloned()
                .ok_or(DataChainError::UserNotFound(user_id.clone()))?
        };

        // 会话校验:非空 family 必须对应一个有效会话。
        let session = if family_id.is_empty() {
            None
        } else {
            match self.storage.get_session_by_family(&family_id).await? {
                Some(s) if s.user_id == user_id && s.revoked_at.is_none() && s.expires_at > now => {
                    trace.session_id = Some(s.id.clone());
                    Some(s)
                }
                Some(s) if s.user_id == user_id && s.revoked_at.is_some() => {
                    trace.session_id = Some(s.id.clone());
                    trace.reason = Some("session_revoked");
                    return Err(DataChainError::InvalidToken);
                }
                _ => {
                    trace.reason = Some("session_invalid");
                    return Err(DataChainError::InvalidToken);
                }
            }
        };

        // 抢占式撤销旧 jti：以主键唯一性收口并发双花。
        // 返回 false => 该 jti 已被另一并发请求/之前的轮换消费 => 复用/并发双花。
        let claimed = self
            .storage
            .revoke_refresh(
                &claims.jti,
                &user_id,
                &family_id,
                Some("rotated"),
                claims.exp,
            )
            .await?;
        if !claimed {
            // 抢占失败：旧 token 已被消费。整族撤销并判定复用。
            // 存量 token（family_id 为空）无族可撤，退化为单 jti 失效（上面已落库）。
            let sid = self
                .revoke_family_and_session(&user_id, &family_id, DOUBLE_SPEND_REASON, ttl_secs)
                .await?;
            self.audit_reuse(&user_id, sid.as_deref(), DOUBLE_SPEND_REASON)
                .await;
            return Err(DataChainError::TokenReuseDetected);
        }

        // 已有会话:更新 last_seen_at 并顺延过期;会话已被并发登出则拒绝签发。
        // 存量旧令牌无 family_id:补发新 family 并补建会话,令后续轮换可被追踪。
        let (sid, next_family_id) = match session {
            Some(session) => {
                if !self
                    .storage
                    .touch_session(&session.id, now, now + ttl_secs)
                    .await?
                {
                    // 会话在检查后被并发撤销:登出/停用 => 拒绝签发(InvalidToken);
                    // 并发双花/复用触发的整族撤销 => 同样不签发,返回 TokenReuseDetected。
                    let by_reuse = self
                        .storage
                        .get_session(&session.id)
                        .await?
                        .and_then(|s| s.revoke_reason)
                        .is_some_and(|r| r.starts_with("refresh token"));
                    if !by_reuse {
                        trace.reason = Some("session_invalid");
                    }
                    return Err(if by_reuse {
                        DataChainError::TokenReuseDetected
                    } else {
                        DataChainError::InvalidToken
                    });
                }
                (session.id, family_id)
            }
            None => {
                let next_family_id = uuid::Uuid::new_v4().to_string();
                let backfilled = SessionRecord {
                    id: uuid::Uuid::new_v4().to_string(),
                    user_id: user.user_id.clone(),
                    refresh_family: next_family_id.clone(),
                    created_at: now,
                    last_seen_at: now,
                    expires_at: now + ttl_secs,
                    revoked_at: None,
                    revoke_reason: None,
                    ip_hash: None,
                    ip_hint: None,
                    user_agent: None,
                };
                self.storage.create_session(&backfilled).await?;
                (backfilled.id, next_family_id)
            }
        };
        self.purge_expired_sessions_lazily(&user.user_id, now).await;

        let token_pair = self.jwt_handler.generate_token_pair(
            &user.user_id,
            &user.username,
            user.role,
            &next_family_id,
            Some(sid.as_str()),
        )?;

        self.audit(
            AuditEvent::new("refresh_success", "success")
                .user(&user.user_id)
                .session(&sid),
        )
        .await;

        Ok(LoginResponse {
            token: token_pair.access_token,
            refresh_token: token_pair.refresh_token,
            token_type: token_pair.token_type,
            expires_at: token_pair.expires_at,
            user: user.to_public(),
        })
    }

    /// 撤销整个 refresh family,并同步撤销其对应会话(若有),返回该会话 id。
    async fn revoke_family_and_session(
        &self,
        user_id: &str,
        family_id: &str,
        reason: &str,
        ttl_secs: i64,
    ) -> Result<Option<String>> {
        if family_id.is_empty() {
            return Ok(None);
        }
        self.storage
            .revoke_family(user_id, family_id, Some(reason), ttl_secs)
            .await?;
        let Some(session) = self.storage.get_session_by_family(family_id).await? else {
            return Ok(None);
        };
        self.storage
            .revoke_session(&session.id, reason, ttl_secs)
            .await?;
        Ok(Some(session.id))
    }

    /// 记录 refresh 复用/双花事件。
    async fn audit_reuse(&self, user_id: &str, session_id: Option<&str>, reason: &str) {
        let mut event = AuditEvent::new("refresh_reuse_detected", "denied")
            .user(user_id)
            .reason(reason);
        if let Some(sid) = session_id {
            event = event.session(sid);
        }
        self.audit(event).await;
    }

    /// 惰性清理该用户已过期的会话;失败只记日志,不影响登录/刷新。
    async fn purge_expired_sessions_lazily(&self, user_id: &str, now: i64) {
        if let Err(e) = self
            .storage
            .purge_expired_sessions_for_user(user_id, now)
            .await
        {
            tracing::warn!("清理过期会话失败: {}", e);
        }
    }

    /// 登出当前会话(幂等):撤销 `claims.sid` 对应会话并联动 refresh family。
    /// 无 `sid` 的存量 access token 没有可撤销的会话,视为成功。
    pub async fn logout(&self, claims: &super::Claims, ctx: &LoginContext) -> Result<()> {
        if let Some(sid) = claims.sid.as_deref() {
            self.storage
                .revoke_session(sid, "logout", self.jwt_handler.refresh_expire_secs())
                .await?;
        }
        let mut event = AuditEvent::new("logout", "success")
            .user(&claims.sub)
            .client(self.ctx_ip_hash(ctx).as_deref(), ctx.user_agent.as_deref());
        if let Some(sid) = claims.sid.as_deref() {
            event = event.session(sid);
        }
        self.audit(event).await;
        Ok(())
    }

    /// 撤销该用户的全部会话(幂等),返回本次被撤销的会话数。
    pub async fn logout_all(&self, user_id: &str, ctx: &LoginContext) -> Result<u64> {
        let ids = self
            .storage
            .revoke_user_sessions(
                user_id,
                "logout-all",
                self.jwt_handler.refresh_expire_secs(),
            )
            .await?;
        self.audit(
            AuditEvent::new("logout_all", "success")
                .user(user_id)
                .client(self.ctx_ip_hash(ctx).as_deref(), ctx.user_agent.as_deref())
                .reason(&format!("revoked {} sessions", ids.len())),
        )
        .await;
        Ok(ids.len() as u64)
    }

    /// 列出该用户未撤销、未过期的会话。`current_sid` 用于标记发起请求的会话。
    pub async fn list_sessions(
        &self,
        user_id: &str,
        current_sid: Option<&str>,
    ) -> Result<Vec<SessionView>> {
        let now = chrono::Utc::now().timestamp();
        self.purge_expired_sessions_lazily(user_id, now).await;
        let sessions = self.storage.list_active_sessions(user_id, now).await?;
        Ok(sessions
            .into_iter()
            .map(|s| SessionView {
                current: current_sid == Some(s.id.as_str()),
                id: s.id,
                created_at: s.created_at,
                last_seen_at: s.last_seen_at,
                expires_at: s.expires_at,
                user_agent: s.user_agent,
                ip_hint: s.ip_hint,
            })
            .collect())
    }

    /// 撤销该用户名下的指定会话。会话不存在、不属于该用户或已不再有效时返回 `false`
    /// (调用方统一按 404 处理,避免枚举他人会话 id)。
    pub async fn revoke_user_session(
        &self,
        user_id: &str,
        session_id: &str,
        ctx: &LoginContext,
    ) -> Result<bool> {
        let now = chrono::Utc::now().timestamp();
        let revoked = match self.storage.get_session(session_id).await? {
            Some(s) if s.user_id == user_id && s.revoked_at.is_none() && s.expires_at > now => {
                self.storage
                    .revoke_session(
                        session_id,
                        "session revoked by user",
                        self.jwt_handler.refresh_expire_secs(),
                    )
                    .await?
            }
            _ => false,
        };
        if revoked {
            self.audit(
                AuditEvent::new("session_revoked", "success")
                    .user(user_id)
                    .session(session_id)
                    .client(self.ctx_ip_hash(ctx).as_deref(), ctx.user_agent.as_deref()),
            )
            .await;
        }
        Ok(revoked)
    }

    /// 获取用户
    pub fn get_user(&self, username: &str) -> Result<User> {
        let user_id = {
            let username_index = self.username_index.read();
            username_index
                .get(username)
                .cloned()
                .ok_or(DataChainError::UserNotFound(username.to_string()))?
        };

        let users = self.users.read();
        users
            .get(&user_id)
            .cloned()
            .ok_or(DataChainError::UserNotFound(username.to_string()))
    }

    /// 根据 ID 获取用户
    pub fn get_user_by_id(&self, user_id: &str) -> Result<User> {
        let users = self.users.read();
        users
            .get(user_id)
            .cloned()
            .ok_or(DataChainError::UserNotFound(user_id.to_string()))
    }

    /// 获取所有用户
    pub fn get_all_users(&self) -> Vec<User> {
        let users = self.users.read();
        users.values().cloned().collect()
    }

    /// 加载用户（从存储恢复）
    pub fn load_user(&self, user: User) {
        let mut users = self.users.write();
        let mut username_index = self.username_index.write();
        let mut email_index = self.email_index.write();

        username_index.insert(user.username.clone(), user.user_id.clone());
        email_index.insert(user.email.clone(), user.user_id.clone());
        users.insert(user.user_id.clone(), user);
    }

    /// 回滚尚未成功写入存储的用户。
    pub fn remove_user(&self, user_id: &str) -> bool {
        let mut users = self.users.write();
        let mut username_index = self.username_index.write();
        let mut email_index = self.email_index.write();
        if let Some(user) = users.remove(user_id) {
            username_index.remove(&user.username);
            email_index.remove(&user.email);
            true
        } else {
            false
        }
    }

    /// 停用用户:同事务写 SQLite(is_active=0)并撤销其全部会话与 refresh family,
    /// 随后清本进程缓存并同步内存副本、写审计。返回被撤销的会话数。
    /// 用户在 SQLite 中不存在时返回 `UserNotFound`。
    pub async fn deactivate_user(&self, user_id: &str) -> Result<u64> {
        self.deactivate_user_by(None, user_id, &LoginContext::default())
            .await
    }

    /// 带操作者的停用:`actor` 为 `Some` 且等于 `target` 时返回 `SelfDeactivation`
    /// (不落库、不审计)。其余行为同 [`Self::deactivate_user`],审计事件带 `actor_user_id`。
    pub async fn deactivate_user_by(
        &self,
        actor: Option<&str>,
        target: &str,
        ctx: &LoginContext,
    ) -> Result<u64> {
        if actor == Some(target) {
            return Err(DataChainError::SelfDeactivation);
        }
        let result = self
            .storage
            .deactivate_user_and_revoke_sessions(
                target,
                "user deactivated",
                self.jwt_handler.refresh_expire_secs(),
            )
            .await;
        let revoked = match result {
            Ok(v) => v.ok_or_else(|| DataChainError::UserNotFound(target.to_string()))?,
            Err(DataChainError::LastAdminProtected) => {
                let mut event = AuditEvent::new("user_deactivate_denied", "denied")
                    .user(target)
                    .client(self.ctx_ip_hash(ctx).as_deref(), ctx.user_agent.as_deref())
                    .reason("last active admin");
                if let Some(actor) = actor {
                    event = event.actor(actor);
                }
                self.audit(event).await;
                return Err(DataChainError::LastAdminProtected);
            }
            Err(e) => return Err(e),
        };
        if let Some(user) = self.users.write().get_mut(target) {
            user.deactivate();
        }
        let mut event = AuditEvent::new("user_deactivated", "success")
            .user(target)
            .client(self.ctx_ip_hash(ctx).as_deref(), ctx.user_agent.as_deref())
            .reason(&format!("revoked {} sessions", revoked));
        if let Some(actor) = actor {
            event = event.actor(actor);
        }
        self.audit(event).await;
        Ok(revoked)
    }

    /// 激活用户:只写 SQLite(is_active=1)并清缓存,**不**恢复任何已撤销的会话。
    /// 用户在 SQLite 中不存在时返回 `UserNotFound`。
    pub async fn activate_user(&self, user_id: &str) -> Result<()> {
        self.activate_user_by(None, user_id, &LoginContext::default())
            .await
    }

    /// 带操作者的激活,审计事件带 `actor_user_id`。
    pub async fn activate_user_by(
        &self,
        actor: Option<&str>,
        target: &str,
        ctx: &LoginContext,
    ) -> Result<()> {
        if !self.storage.set_user_active(target, true).await? {
            return Err(DataChainError::UserNotFound(target.to_string()));
        }
        if let Some(user) = self.users.write().get_mut(target) {
            user.activate();
        }
        let mut event = AuditEvent::new("user_activated", "success")
            .user(target)
            .client(self.ctx_ip_hash(ctx).as_deref(), ctx.user_agent.as_deref());
        if let Some(actor) = actor {
            event = event.actor(actor);
        }
        self.audit(event).await;
        Ok(())
    }

    /// 管理员列出目标用户未撤销、未过期的会话(`current` 恒为 false)。
    /// 目标不存在返回 `UserNotFound`;成功后写审计 `admin_sessions_listed`。
    pub async fn admin_list_sessions(
        &self,
        actor: &str,
        target: &str,
        ctx: &LoginContext,
    ) -> Result<Vec<AdminSessionView>> {
        if !self.storage.user_exists(target).await? {
            return Err(DataChainError::UserNotFound(target.to_string()));
        }
        let now = chrono::Utc::now().timestamp();
        self.purge_expired_sessions_lazily(target, now).await;
        let sessions = self.storage.list_active_sessions(target, now).await?;
        self.audit(
            AuditEvent::new("admin_sessions_listed", "success")
                .user(target)
                .actor(actor)
                .client(self.ctx_ip_hash(ctx).as_deref(), ctx.user_agent.as_deref()),
        )
        .await;
        Ok(sessions
            .into_iter()
            .map(|s| AdminSessionView {
                id: s.id,
                created_at: s.created_at,
                last_seen_at: s.last_seen_at,
                expires_at: s.expires_at,
                ip_hint: s.ip_hint,
                current: false,
            })
            .collect())
    }

    /// 管理员撤销目标用户全部会话(幂等),返回本次撤销数。
    /// 目标不存在返回 `UserNotFound`;成功后写审计 `admin_sessions_revoked`。
    pub async fn admin_revoke_sessions(
        &self,
        actor: &str,
        target: &str,
        ctx: &LoginContext,
    ) -> Result<u64> {
        if !self.storage.user_exists(target).await? {
            return Err(DataChainError::UserNotFound(target.to_string()));
        }
        let ids = self
            .storage
            .revoke_user_sessions(
                target,
                "sessions revoked by admin",
                self.jwt_handler.refresh_expire_secs(),
            )
            .await?;
        self.audit(
            AuditEvent::new("admin_sessions_revoked", "success")
                .user(target)
                .actor(actor)
                .client(self.ctx_ip_hash(ctx).as_deref(), ctx.user_agent.as_deref())
                .reason(&format!("revoked {} sessions", ids.len())),
        )
        .await;
        Ok(ids.len() as u64)
    }
}

/// 创建共享的 AuthService 实例
pub fn create_auth_service(
    jwt_secret: String,
    jwt_expire_hours: u64,
    storage: Arc<Storage>,
) -> Arc<AuthService> {
    Arc::new(AuthService::new(jwt_secret, jwt_expire_hours, storage))
}

/// 按完整参数创建共享的 AuthService 实例。
pub fn create_auth_service_with_settings(
    jwt_secret: String,
    storage: Arc<Storage>,
    settings: AuthSettings,
) -> Arc<AuthService> {
    Arc::new(AuthService::with_settings(jwt_secret, storage, settings))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::LoginRequest;

    async fn build_service() -> Arc<AuthService> {
        let dir = tempfile::tempdir().unwrap().keep();
        let path = dir.join("auth.sqlite");
        let storage = crate::storage::create_storage(path.to_str().unwrap())
            .await
            .unwrap();
        create_auth_service("test-secret".to_string(), 24, storage)
    }

    async fn register_login(service: &AuthService) -> LoginResponse {
        let req = RegisterRequest {
            username: "alice".to_string(),
            password: "password123".to_string(),
            email: "alice@example.com".to_string(),
            role: None,
        };
        // 用户状态以 SQLite 为权威,测试用户需同时落库。
        let user = service.register(&req).unwrap();
        service.storage.save_user(&user).await.unwrap();
        service
            .login(
                &LoginRequest {
                    username: "alice".to_string(),
                    password: "password123".to_string(),
                },
                &LoginContext::default(),
            )
            .await
            .unwrap()
    }

    #[test]
    fn hmac_sha256_matches_rfc4231_case_2() {
        let mac = hmac_sha256(b"Jefe", b"what do ya want for nothing?");
        assert_eq!(
            hex::encode(mac),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
    }

    #[test]
    fn sanitize_user_agent_strips_controls_and_truncates() {
        let cleaned = sanitize_user_agent(&format!("a\u{1b}[0m\n{}", "b".repeat(500)));
        assert!(!cleaned.chars().any(|c| c.is_control()));
        assert_eq!(cleaned.chars().count(), 200);
    }

    #[tokio::test]
    async fn refresh_rotates_and_invalidates_old_token() {
        let service = build_service().await;
        let login = register_login(&service).await;

        // 正常轮换成功，拿到新刷新令牌。
        let rotated = service.refresh_token(&login.refresh_token).await.unwrap();
        assert_ne!(rotated.refresh_token, login.refresh_token);

        // 用轮换后的新令牌可继续刷新。
        let rotated2 = service.refresh_token(&rotated.refresh_token).await.unwrap();
        assert_ne!(rotated2.refresh_token, rotated.refresh_token);
    }

    #[tokio::test]
    async fn reusing_old_refresh_token_triggers_family_revocation() {
        let service = build_service().await;
        let login = register_login(&service).await;

        // 第一次轮换：旧 token 被撤销。
        let rotated = service.refresh_token(&login.refresh_token).await.unwrap();

        // 复用已被撤销的旧 token => 判定为复用攻击。
        let reuse = service.refresh_token(&login.refresh_token).await;
        assert!(matches!(reuse, Err(DataChainError::TokenReuseDetected)));

        // 复用检测会整族撤销：此前合法的 rotated token 也随之失效。
        let after = service.refresh_token(&rotated.refresh_token).await;
        assert!(matches!(after, Err(DataChainError::TokenReuseDetected)));
    }

    /// 并发双花回归测试：同一 refresh token 被两个请求同时消费。
    ///
    /// 证明 revoke_refresh 的抢占语义收口了 TOCTOU：即便两个并发请求都可能
    /// 通过 is_jti_revoked 检查，数据库主键唯一性也只允许其中一个抢占成功并
    /// 签发新令牌对，另一个必然得到 TokenReuseDetected，且触发整族撤销。
    /// 一个旧 token 绝不可能兑换出两对有效新令牌。
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_double_spend_yields_single_success() {
        let service = build_service().await;
        let login = register_login(&service).await;

        let token_a = login.refresh_token.clone();
        let token_b = login.refresh_token.clone();
        let svc_a = service.clone();
        let svc_b = service.clone();

        // 两个任务并发用同一个旧 refresh token 轮换。
        let (ra, rb) = tokio::join!(
            tokio::spawn(async move { svc_a.refresh_token(&token_a).await }),
            tokio::spawn(async move { svc_b.refresh_token(&token_b).await }),
        );
        let ra = ra.unwrap();
        let rb = rb.unwrap();

        // 恰好一个成功、一个被判定为复用/双花。
        let ok_count = [&ra, &rb].iter().filter(|r| r.is_ok()).count();
        let reuse_count = [&ra, &rb]
            .iter()
            .filter(|r| matches!(r, Err(DataChainError::TokenReuseDetected)))
            .count();
        assert_eq!(ok_count, 1, "并发双花必须恰好只有一个请求成功");
        assert_eq!(reuse_count, 1, "另一个请求必须被判定为 TokenReuseDetected");

        // 抢占失败一侧已触发整族撤销：成功一侧拿到的新 token 也应随之失效，
        // 证明旧 token 的并发双花不会留下任何可继续使用的有效令牌。
        let winner = match (ra, rb) {
            (Ok(w), _) | (_, Ok(w)) => w,
            _ => panic!("并发双花应恰有一方成功"),
        };
        let after = service.refresh_token(&winner.refresh_token).await;
        assert!(
            matches!(after, Err(DataChainError::TokenReuseDetected)),
            "双花触发整族撤销后，胜出方的新 token 也应失效"
        );
    }

    #[tokio::test]
    async fn revocation_survives_service_restart() {
        // 同一 Storage 支撑两个 AuthService 实例，模拟进程重启后撤销状态仍在。
        let dir = tempfile::tempdir().unwrap().keep();
        let path = dir.join("auth.sqlite");
        let storage = crate::storage::create_storage(path.to_str().unwrap())
            .await
            .unwrap();

        let service1 = create_auth_service("s".to_string(), 24, storage.clone());
        let login = register_login(&service1).await;
        let rotated = service1.refresh_token(&login.refresh_token).await.unwrap();

        // 新建一个 AuthService（不共享内存撤销状态，仅共享 Storage）。
        let service2 = create_auth_service("s".to_string(), 24, storage.clone());
        // service2 需要有该用户才能走到用户查找；从存储无用户，这里直接复用 service1 验证撤销表持久化。
        // 对 service2 复用旧 token 应被撤销表拦截。
        let reuse = service2.refresh_token(&login.refresh_token).await;
        assert!(matches!(reuse, Err(DataChainError::TokenReuseDetected)));
        // rotated 仍是该 family 的有效 token，但 family 已因复用被撤销。
        let after = service2.refresh_token(&rotated.refresh_token).await;
        assert!(matches!(after, Err(DataChainError::TokenReuseDetected)));
    }
}
