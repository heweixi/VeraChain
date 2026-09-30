use chrono::{Duration, Utc};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
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
    pub exp: i64,
    pub iat: i64,
}

/// JWT 处理器
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

    /// 生成访问令牌
    pub fn generate_access_token(
        &self,
        user_id: &str,
        username: &str,
        role: Role,
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
        };

        encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(self.secret.as_bytes()),
        )
        .map_err(|_| DataChainError::Internal("Failed to generate token".to_string()))
    }

    /// 生成刷新令牌
    pub fn generate_refresh_token(&self, user_id: &str) -> Result<String> {
        let now = Utc::now();
        let exp = now + Duration::days(self.refresh_expire_days as i64);

        let claims = RefreshClaims {
            sub: user_id.to_string(),
            token_type: "refresh".to_string(),
            exp: exp.timestamp(),
            iat: now.timestamp(),
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
            &Validation::default(),
        )
        .map_err(|e| match e.kind() {
            jsonwebtoken::errors::ErrorKind::ExpiredSignature => DataChainError::TokenExpired,
            _ => DataChainError::InvalidToken,
        })?;

        Ok(token_data.claims)
    }

    /// 验证刷新令牌
    pub fn verify_refresh_token(&self, token: &str) -> Result<String> {
        let token_data = decode::<RefreshClaims>(
            token,
            &DecodingKey::from_secret(self.secret.as_bytes()),
            &Validation::default(),
        )
        .map_err(|e| match e.kind() {
            jsonwebtoken::errors::ErrorKind::ExpiredSignature => DataChainError::TokenExpired,
            _ => DataChainError::InvalidToken,
        })?;

        if token_data.claims.token_type != "refresh" {
            return Err(DataChainError::InvalidToken);
        }

        Ok(token_data.claims.sub)
    }

    /// 生成令牌对
    pub fn generate_token_pair(
        &self,
        user_id: &str,
        username: &str,
        role: Role,
    ) -> Result<TokenPair> {
        let access_token = self.generate_access_token(user_id, username, role)?;
        let refresh_token = self.generate_refresh_token(user_id)?;
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
            .generate_access_token("user-123", "testuser", Role::User)
            .unwrap();
        assert!(!token.is_empty());

        let claims = handler.verify_access_token(&token).unwrap();
        assert_eq!(claims.sub, "user-123");
        assert_eq!(claims.username, "testuser");
    }
}
