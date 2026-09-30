use parking_lot::RwLock;
use std::collections::HashMap;
use std::sync::Arc;

use super::{JwtHandler, LoginRequest, LoginResponse, RegisterRequest, Role, User};
use crate::crypto::{hash_password, verify_password};
use crate::error::{DataChainError, Result};

/// 认证服务
pub struct AuthService {
    users: RwLock<HashMap<String, User>>, // user_id -> User
    username_index: RwLock<HashMap<String, String>>, // username -> user_id
    email_index: RwLock<HashMap<String, String>>, // email -> user_id
    jwt_handler: JwtHandler,
}

impl AuthService {
    /// 创建认证服务
    pub fn new(jwt_secret: String, jwt_expire_hours: u64) -> Self {
        Self {
            users: RwLock::new(HashMap::new()),
            username_index: RwLock::new(HashMap::new()),
            email_index: RwLock::new(HashMap::new()),
            jwt_handler: JwtHandler::new(jwt_secret, jwt_expire_hours),
        }
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

    /// 用户登录
    pub fn login(&self, req: &LoginRequest) -> Result<LoginResponse> {
        // 获取用户
        let user_id = {
            let username_index = self.username_index.read();
            username_index
                .get(&req.username)
                .cloned()
                .ok_or(DataChainError::UserNotFound(req.username.clone()))?
        };

        let mut user = {
            let users = self.users.read();
            users
                .get(&user_id)
                .cloned()
                .ok_or(DataChainError::UserNotFound(req.username.clone()))?
        };

        // 检查账户状态
        if !user.is_active {
            return Err(DataChainError::UserNotFound(req.username.clone()));
        }

        // 验证密码
        if !verify_password(&req.password, &user.password_hash) {
            return Err(DataChainError::InvalidPassword);
        }

        // 更新最后登录时间
        user.update_last_login();
        {
            let mut users = self.users.write();
            users.insert(user.user_id.clone(), user.clone());
        }

        // 生成令牌
        let token_pair =
            self.jwt_handler
                .generate_token_pair(&user.user_id, &user.username, user.role)?;

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

    /// 刷新令牌
    pub fn refresh_token(&self, refresh_token: &str) -> Result<LoginResponse> {
        let user_id = self.jwt_handler.verify_refresh_token(refresh_token)?;

        let user = {
            let users = self.users.read();
            users
                .get(&user_id)
                .cloned()
                .ok_or(DataChainError::UserNotFound(user_id.clone()))?
        };

        let token_pair =
            self.jwt_handler
                .generate_token_pair(&user.user_id, &user.username, user.role)?;

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
pub fn create_auth_service(jwt_secret: String, jwt_expire_hours: u64) -> Arc<AuthService> {
    Arc::new(AuthService::new(jwt_secret, jwt_expire_hours))
}
