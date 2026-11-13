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
            user_agent: ctx.user_agent.as_deref().map(sanitize_user_agent),
        };
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
    ///    撤销整个 family 并返回 TokenReuseDetected；
    /// 3. 否则对旧 jti 做抢占式撤销（数据库主键唯一性）：
    ///    - 抢占成功 => 本请求独占该旧 token，签发同一 family 的新令牌对；
    ///    - 抢占失败（jti 已存在）=> 说明被并发请求/之前的轮换先消费，属并发双花，
    ///      撤销整个 family 并返回 TokenReuseDetected。
    ///
    /// 第 2 步的 is_jti_revoked / is_family_revoked 与第 3 步的 revoke_refresh 之间
    /// 本身存在 TOCTOU 窗口，但最终以第 3 步的主键抢占为准绳：即便两个并发请求
    /// 都通过了第 2 步检查，也只有一个能在第 3 步抢占成功，另一个必然失败并触发整族撤销。
    ///
    /// 存量退化说明：存量旧 token（family_id 为空串）命中复用时，因无 family 标识，
    /// 只能退化为「单 jti 失效」而非整族失效。这是升级过渡期的已知弱化（旧 token 签发时
    /// 尚无 family 概念），并非安全绕过——过渡期结束、旧 token 全部过期后自然消失。
    pub async fn refresh_token(&self, refresh_token: &str) -> Result<LoginResponse> {
        let claims = self.jwt_handler.parse_refresh_claims(refresh_token)?;
        let user_id = claims.sub.clone();
        let family_id = claims.family_id.clone();
        // 哨兵行 TTL 取自刷新令牌有效期，避免魔法数（见 Storage::revoke_family）。
        let ttl_secs = self.jwt_handler.refresh_expire_secs();

        // 复用检测：jti 已撤销 或 family 已整体撤销。
        // family_id 可能为空（存量旧令牌），此时跳过 family 级判定。
        let jti_revoked = self.storage.is_jti_revoked(&claims.jti).await?;
        let family_revoked = if family_id.is_empty() {
            false
        } else {
            self.storage.is_family_revoked(&user_id, &family_id).await?
        };
        if jti_revoked || family_revoked {
            if !family_id.is_empty() {
                self.storage
                    .revoke_family(
                        &user_id,
                        &family_id,
                        Some("refresh token reuse detected"),
                        ttl_secs,
                    )
                    .await?;
            }
            return Err(DataChainError::TokenReuseDetected);
        }

        let user = {
            let users = self.users.read();
            users
                .get(&user_id)
                .cloned()
                .ok_or(DataChainError::UserNotFound(user_id.clone()))?
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
            if !family_id.is_empty() {
                self.storage
                    .revoke_family(
                        &user_id,
                        &family_id,
                        Some("refresh token double-spend detected"),
                        ttl_secs,
                    )
                    .await?;
            }
            return Err(DataChainError::TokenReuseDetected);
        }

        // 存量旧令牌无 family_id，轮换时补发一个新 family，令后续轮换可被追踪。
        let next_family_id = if family_id.is_empty() {
            uuid::Uuid::new_v4().to_string()
        } else {
            family_id
        };
        let token_pair = self.jwt_handler.generate_token_pair(
            &user.user_id,
            &user.username,
            user.role,
            &next_family_id,
            // 刷新尚未接入会话(后续切片处理),暂不携带 sid。
            None,
        )?;

        Ok(LoginResponse {
            token: token_pair.access_token,
            refresh_token: token_pair.refresh_token,
            token_type: token_pair.token_type,
            expires_at: token_pair.expires_at,
            user: user.to_public(),
        })
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
        service.register(&req).unwrap();
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
