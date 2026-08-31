use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// 用户角色
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    Admin,
    User,
    Auditor,
    Guest,
}

impl Default for Role {
    fn default() -> Self {
        Self::User
    }
}

impl std::fmt::Display for Role {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Role::Admin => write!(f, "admin"),
            Role::User => write!(f, "user"),
            Role::Auditor => write!(f, "auditor"),
            Role::Guest => write!(f, "guest"),
        }
    }
}

impl std::str::FromStr for Role {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "admin" => Ok(Role::Admin),
            "user" => Ok(Role::User),
            "auditor" => Ok(Role::Auditor),
            "guest" => Ok(Role::Guest),
            _ => Err(format!("Unknown role: {}", s)),
        }
    }
}

/// 用户模型
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub id: i64,
    pub user_id: String,
    pub username: String,
    #[serde(skip_serializing)]
    pub password_hash: String,
    pub email: String,
    pub role: Role,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_key: Option<String>,
    pub created_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_login: Option<DateTime<Utc>>,
    pub is_active: bool,
    #[serde(default)]
    pub metadata: HashMap<String, serde_json::Value>,
}

impl User {
    /// 创建新用户
    pub fn new(username: String, password_hash: String, email: String, role: Role) -> Self {
        Self {
            id: 0,
            user_id: uuid::Uuid::new_v4().to_string(),
            username,
            password_hash,
            email,
            role,
            public_key: None,
            created_at: Utc::now(),
            last_login: None,
            is_active: true,
            metadata: HashMap::new(),
        }
    }

    /// 更新最后登录时间
    pub fn update_last_login(&mut self) {
        self.last_login = Some(Utc::now());
    }

    /// 停用账户
    pub fn deactivate(&mut self) {
        self.is_active = false;
    }

    /// 激活账户
    pub fn activate(&mut self) {
        self.is_active = true;
    }

    /// 转换为公开信息（不包含密码）
    pub fn to_public(&self) -> UserPublic {
        UserPublic {
            user_id: self.user_id.clone(),
            username: self.username.clone(),
            email: self.email.clone(),
            role: self.role,
            created_at: self.created_at,
            last_login: self.last_login,
            is_active: self.is_active,
        }
    }
}

/// 用户公开信息
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserPublic {
    pub user_id: String,
    pub username: String,
    pub email: String,
    pub role: Role,
    pub created_at: DateTime<Utc>,
    pub last_login: Option<DateTime<Utc>>,
    pub is_active: bool,
}

/// 注册请求
#[derive(Debug, Clone, Deserialize)]
pub struct RegisterRequest {
    pub username: String,
    pub password: String,
    pub email: String,
    #[serde(default)]
    pub role: Option<Role>,
}

/// 登录请求
#[derive(Debug, Clone, Deserialize)]
pub struct LoginRequest {
    pub username: String,
    pub password: String,
}

/// 登录响应
#[derive(Debug, Clone, Serialize)]
pub struct LoginResponse {
    pub token: String,
    pub refresh_token: String,
    pub token_type: String,
    pub expires_at: DateTime<Utc>,
    pub user: UserPublic,
}
