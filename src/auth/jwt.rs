use chrono::{Duration, Utc};
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};

use super::Role;
use crate::error::{DataChainError, Result};

/// JWT 声明
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String, // user_id
    pub username: String,
    pub role: String,
    pub exp: i64,    // 过期时间
    pub iat: i64,    // 签发时间
    pub iss: String, // 签发者
    pub aud: String, // 受众
    /// 会话标识(sessions.id)。#[serde(default)] 软兼容无该字段的存量 access token。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sid: Option<String>,
}

impl Claims {
    /// 获取用户 ID
    pub fn user_id(&self) -> &str {
        &self.sub
    }
}

/// 刷新令牌声明
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RefreshClaims {
    pub sub: String, // user_id
    pub token_type: String,
    pub jti: String,
    /// token-family 标识：同一登录链路轮换出的刷新令牌共享同一 family_id，
    /// 用于复用检测时整族撤销。#[serde(default)] 软兼容无该字段的存量令牌
    /// （旧令牌反序列化为空串）。
    #[serde(default)]
    pub family_id: String,
    pub exp: i64,
    pub iat: i64,
    pub iss: String,
    pub aud: String,
}

/// JWT 处理器（纯编解码，不持有撤销状态；撤销信息落库于 Storage）。
pub struct JwtHandler {
    secret: String,
    access_expire_hours: u64,
    refresh_expire_days: u64,
}

impl JwtHandler {
    /// 创建 JWT 处理器
    pub fn new(secret: String, access_expire_hours: u64) -> Self {
        Self {
            secret,
            access_expire_hours,
            refresh_expire_days: 7,
        }
    }

    /// 覆盖刷新令牌有效期(天,默认 7)。
    pub fn with_refresh_expire_days(mut self, days: u64) -> Self {
        self.refresh_expire_days = days;
        self
    }

    /// 刷新令牌有效期（秒）。供撤销表哨兵行推导 TTL，避免魔法数。
    pub fn refresh_expire_secs(&self) -> i64 {
        self.refresh_expire_days as i64 * 24 * 3600
    }

    fn validation(&self) -> Validation {
        let mut validation = Validation::new(Algorithm::HS256);
        validation.set_issuer(&["datachain"]);
        validation.set_audience(&["datachain-api"]);
        validation
    }

    /// 生成访问令牌。`sid` 为会话标识,旧调用方(无会话)传 `None`。
    pub fn generate_access_token(
        &self,
        user_id: &str,
        username: &str,
        role: Role,
        sid: Option<&str>,
    ) -> Result<String> {
        let now = Utc::now();
        let exp = now + Duration::hours(self.access_expire_hours as i64);

        let claims = Claims {
            sub: user_id.to_string(),
            username: username.to_string(),
            role: role.to_string(),
            exp: exp.timestamp(),
            iat: now.timestamp(),
            iss: "datachain".to_string(),
            aud: "datachain-api".to_string(),
            sid: sid.map(str::to_string),
        };

        encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(self.secret.as_bytes()),
        )
        .map_err(|_| DataChainError::Internal("Failed to generate token".to_string()))
    }

    /// 生成刷新令牌。family_id 由调用方指定：登录时新建，轮换时沿用原族。
    pub fn generate_refresh_token(&self, user_id: &str, family_id: &str) -> Result<String> {
        let now = Utc::now();
        let exp = now + Duration::days(self.refresh_expire_days as i64);

        let claims = RefreshClaims {
            sub: user_id.to_string(),
            token_type: "refresh".to_string(),
            jti: uuid::Uuid::new_v4().to_string(),
            family_id: family_id.to_string(),
            exp: exp.timestamp(),
            iat: now.timestamp(),
            iss: "datachain".to_string(),
            aud: "datachain-api".to_string(),
        };

        encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(self.secret.as_bytes()),
        )
        .map_err(|_| DataChainError::Internal("Failed to generate refresh token".to_string()))
    }

    /// 验证访问令牌
    pub fn verify_access_token(&self, token: &str) -> Result<Claims> {
        let token_data = decode::<Claims>(
            token,
            &DecodingKey::from_secret(self.secret.as_bytes()),
            &self.validation(),
        )
        .map_err(|e| match e.kind() {
            jsonwebtoken::errors::ErrorKind::ExpiredSignature => DataChainError::TokenExpired,
            _ => DataChainError::InvalidToken,
        })?;

        Ok(token_data.claims)
    }

    /// 解码并校验刷新令牌（签名、iss、aud、token_type），返回完整 claims。
    /// 不查撤销状态——撤销判定由调用方结合 Storage 完成。
    pub fn parse_refresh_claims(&self, token: &str) -> Result<RefreshClaims> {
        let token_data = decode::<RefreshClaims>(
            token,
            &DecodingKey::from_secret(self.secret.as_bytes()),
            &self.validation(),
        )
        .map_err(|e| match e.kind() {
            jsonwebtoken::errors::ErrorKind::ExpiredSignature => DataChainError::TokenExpired,
            _ => DataChainError::InvalidToken,
        })?;

        if token_data.claims.token_type != "refresh" {
            return Err(DataChainError::InvalidToken);
        }

        Ok(token_data.claims)
    }

    /// 生成令牌对。family_id 由调用方指定（登录新建 / 轮换沿用）；sid 为会话标识。
    pub fn generate_token_pair(
        &self,
        user_id: &str,
        username: &str,
        role: Role,
        family_id: &str,
        sid: Option<&str>,
    ) -> Result<TokenPair> {
        let access_token = self.generate_access_token(user_id, username, role, sid)?;
        let refresh_token = self.generate_refresh_token(user_id, family_id)?;
        let expires_at = Utc::now() + Duration::hours(self.access_expire_hours as i64);

        Ok(TokenPair {
            access_token,
            refresh_token,
            token_type: "bearer".to_string(),
            expires_at,
        })
    }
}

/// 令牌对
#[derive(Debug, Clone, Serialize)]
pub struct TokenPair {
    pub access_token: String,
    pub refresh_token: String,
    pub token_type: String,
    pub expires_at: chrono::DateTime<Utc>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_jwt_generation() {
        let handler = JwtHandler::new("test-secret".to_string(), 24);

        let token = handler
            .generate_access_token("user-123", "testuser", Role::User, None)
            .unwrap();
        assert!(!token.is_empty());

        let claims = handler.verify_access_token(&token).unwrap();
        assert_eq!(claims.sub, "user-123");
        assert_eq!(claims.username, "testuser");
        assert!(claims.sid.is_none());
    }

    #[test]
    fn test_access_token_carries_sid() {
        let handler = JwtHandler::new("test-secret".to_string(), 24);
        let token = handler
            .generate_access_token("user-123", "testuser", Role::User, Some("sid-1"))
            .unwrap();
        let claims = handler.verify_access_token(&token).unwrap();
        assert_eq!(claims.sid.as_deref(), Some("sid-1"));
    }
}
