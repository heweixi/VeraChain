use parking_lot::RwLock;
use std::collections::HashMap;
use std::sync::Arc;

use super::{JwtHandler, LoginRequest, LoginResponse, RegisterRequest, Role, User};
use crate::crypto::{hash_password, verify_password};
use crate::error::{DataChainError, Result};
use crate::storage::{SessionRecord, Storage};

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

/// 不存在用户时用于抹平耗时的 bcrypt 哈希,cost 与真实密码一致(同为 `hash_password`)。
fn dummy_password_hash() -> &'static str {
    static DUMMY: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    DUMMY.get_or_init(|| hash_password("datachain-dummy-password-for-timing").unwrap_or_default())
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
}

impl AuthService {
    /// 创建认证服务
    pub fn new(jwt_secret: String, jwt_expire_hours: u64, storage: Arc<Storage>) -> Self {
        Self {
            users: RwLock::new(HashMap::new()),
            username_index: RwLock::new(HashMap::new()),
            email_index: RwLock::new(HashMap::new()),
            login_limits: LoginLimits::default(),
            ip_hash_key: format!("datachain-ip-hash:{}", jwt_secret).into_bytes(),
            jwt_handler: JwtHandler::new(jwt_secret, jwt_expire_hours),
            storage,
        }
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

    /// 公开注册:始终创建普通用户,不接受客户端指定高权限角色。
    pub fn register(&self, req: &RegisterRequest) -> Result<User> {
        self.register_with_role(req, Role::User)
    }

    /// 管理/CLI 注册:由受信调用方显式指定角色。
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
        let now = chrono::Utc::now().timestamp();
        let limits = self.login_limits;
        let ip_key = format!(
            "ip:{}",
            self.hash_client_ip(ctx.client_ip.as_deref().unwrap_or(UNKNOWN_CLIENT_IP))
        );
        let user_key = format!("user:{}", normalize_username_key(&req.username));
        let (ip_count, window_start) = self
            .storage
            .incr_login_counter(&ip_key, now, limits.window_secs)
            .await?;
        let (user_count, _) = self
            .storage
            .incr_login_counter(&user_key, now, limits.window_secs)
            .await?;
        if ip_count > limits.ip_max_attempts || user_count > limits.user_max_attempts {
            let retry_after_secs = (window_start + limits.window_secs - now).max(1) as u64;
            return Err(DataChainError::TooManyAttempts { retry_after_secs });
        }

        // 取用户;不存在时也对固定 dummy hash 做一次同 cost 的 bcrypt,抹平耗时差异。
        // 两把读锁不嵌套持有,避免与 register 的写锁顺序形成死锁。
        let found = {
            let id = self.username_index.read().get(&req.username).cloned();
            id.and_then(|id| self.users.read().get(&id).cloned())
        };
        let password_ok = match &found {
            Some(user) => verify_password(&req.password, &user.password_hash),
            None => {
                let _ = verify_password(&req.password, dummy_password_hash());
                false
            }
        };
        // 用户不存在 / 密码错误 / 账户已禁用 统一返回同一错误(禁用账户也先验证密码)。
        let mut user = match found {
            Some(user) if password_ok && user.is_active => user,
            _ => return Err(DataChainError::InvalidCredentials),
        };

        // 成功:重置用户名维度计数,归还 IP 维度的本次名额。
        self.storage.reset_login_counter(&user_key).await?;
        self.storage
            .decr_login_counter(&ip_key, now, limits.window_secs)
            .await?;

        // 更新最后登录时间
        user.update_last_login();
        {
            let mut users = self.users.write();
            users.insert(user.user_id.clone(), user.clone());
        }

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
    /// → 用户 is_active(SQLite 权威,带短 TTL 缓存)→ 内存用户存在、启用且角色与 claims 一致。
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

        // 角色必须与当前用户一致(角色被修改后旧 token 失效);内存侧禁用同样拒绝。
        let user = self
            .get_user_by_id(&claims.sub)
            .map_err(|_| DataChainError::InvalidToken)?;
        if !user.is_active || user.role.to_string() != claims.role {
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
        let claims = self.jwt_handler.parse_refresh_claims(refresh_token)?;
        let user_id = claims.sub.clone();
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
                        return Err(DataChainError::InvalidToken);
                    }
                }
            }
            self.revoke_family_and_session(&user_id, &family_id, REUSE_REASON, ttl_secs)
                .await?;
            return Err(DataChainError::TokenReuseDetected);
        }

        // 用户状态以 SQLite 为权威(CLI 可能在别的进程里停用)。
        if !self.storage.is_user_active(&user_id).await? {
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
                    Some(s)
                }
                _ => return Err(DataChainError::InvalidToken),
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
            self.revoke_family_and_session(&user_id, &family_id, DOUBLE_SPEND_REASON, ttl_secs)
                .await?;
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
                    // 会话在检查后被并发撤销:登出/停用 => 拒绝签发;
                    // 若是并发双花触发的整族撤销,沿用既有语义(胜出方拿到的令牌随整族失效)。
                    let by_reuse = self
                        .storage
                        .get_session(&session.id)
                        .await?
                        .and_then(|s| s.revoke_reason)
                        .is_some_and(|r| r.starts_with("refresh token"));
                    if !by_reuse {
                        return Err(DataChainError::InvalidToken);
                    }
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

        Ok(LoginResponse {
            token: token_pair.access_token,
            refresh_token: token_pair.refresh_token,
            token_type: token_pair.token_type,
            expires_at: token_pair.expires_at,
            user: user.to_public(),
        })
    }

    /// 撤销整个 refresh family,并同步撤销其对应会话(若有)。
    async fn revoke_family_and_session(
        &self,
        user_id: &str,
        family_id: &str,
        reason: &str,
        ttl_secs: i64,
    ) -> Result<()> {
        if family_id.is_empty() {
            return Ok(());
        }
        self.storage
            .revoke_family(user_id, family_id, Some(reason), ttl_secs)
            .await?;
        if let Some(session) = self.storage.get_session_by_family(family_id).await? {
            self.storage
                .revoke_session(&session.id, reason, ttl_secs)
                .await?;
        }
        Ok(())
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
    pub async fn logout(&self, claims: &super::Claims) -> Result<()> {
        if let Some(sid) = claims.sid.as_deref() {
            self.storage
                .revoke_session(sid, "logout", self.jwt_handler.refresh_expire_secs())
                .await?;
        }
        Ok(())
    }

    /// 撤销该用户的全部会话(幂等),返回本次被撤销的会话数。
    pub async fn logout_all(&self, user_id: &str) -> Result<u64> {
        let ids = self
            .storage
            .revoke_user_sessions(
                user_id,
                "logout-all",
                self.jwt_handler.refresh_expire_secs(),
            )
            .await?;
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
    pub async fn revoke_user_session(&self, user_id: &str, session_id: &str) -> Result<bool> {
        let now = chrono::Utc::now().timestamp();
        match self.storage.get_session(session_id).await? {
            Some(s) if s.user_id == user_id && s.revoked_at.is_none() && s.expires_at > now => {
                self.storage
                    .revoke_session(
                        session_id,
                        "session revoked by user",
                        self.jwt_handler.refresh_expire_secs(),
                    )
                    .await
            }
            _ => Ok(false),
        }
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

    /// 停用用户
    pub fn deactivate_user(&self, user_id: &str) -> Result<()> {
        let mut users = self.users.write();
        let user = users
            .get_mut(user_id)
            .ok_or(DataChainError::UserNotFound(user_id.to_string()))?;
        user.deactivate();
        Ok(())
    }

    /// 激活用户
    pub fn activate_user(&self, user_id: &str) -> Result<()> {
        let mut users = self.users.write();
        let user = users
            .get_mut(user_id)
            .ok_or(DataChainError::UserNotFound(user_id.to_string()))?;
        user.activate();
        Ok(())
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
