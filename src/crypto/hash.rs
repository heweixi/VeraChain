use md5::Md5;
use sha2::{Digest, Sha256, Sha512};
use sha3::{Sha3_256, Sha3_512};
use std::collections::HashMap;

/// 哈希引擎
pub struct HashEngine {
    salt: Vec<u8>,
}

impl HashEngine {
    /// 创建哈希引擎
    pub fn new(salt: Option<&[u8]>) -> Self {
        Self {
            salt: salt.unwrap_or(b"datachain-default-salt").to_vec(),
        }
    }

    /// 计算 MD5 哈希
    pub fn compute_md5(&self, data: &[u8]) -> String {
        let mut hasher = Md5::new();
        hasher.update(data);
        hex::encode(hasher.finalize())
    }

    /// 计算 SHA-256 哈希
    pub fn compute_sha256(&self, data: &[u8]) -> String {
        let mut hasher = Sha256::new();
        hasher.update(data);
        hex::encode(hasher.finalize())
    }

    /// 计算 SHA-512 哈希
    pub fn compute_sha512(&self, data: &[u8]) -> String {
        let mut hasher = Sha512::new();
        hasher.update(data);
        hex::encode(hasher.finalize())
    }

    /// 计算 SHA3-256 哈希
    pub fn compute_sha3_256(&self, data: &[u8]) -> String {
        let mut hasher = Sha3_256::new();
        hasher.update(data);
        hex::encode(hasher.finalize())
    }

    /// 计算 SHA3-512 哈希
    pub fn compute_sha3_512(&self, data: &[u8]) -> String {
        let mut hasher = Sha3_512::new();
        hasher.update(data);
        hex::encode(hasher.finalize())
    }

    /// 计算 bcrypt 哈希
    pub fn compute_bcrypt(&self, data: &[u8]) -> Result<String, bcrypt::BcryptError> {
        // bcrypt 有长度限制，使用 SHA256 预处理
        let sha = self.compute_sha256(data);
        bcrypt::hash(sha, bcrypt::DEFAULT_COST)
    }

    /// 验证 bcrypt 哈希
    pub fn verify_bcrypt(&self, data: &[u8], hash: &str) -> bool {
        let sha = self.compute_sha256(data);
        bcrypt::verify(sha, hash).unwrap_or(false)
    }

    /// 计算 Argon2 哈希
    pub fn compute_argon2(&self, data: &[u8]) -> String {
        use argon2::password_hash::SaltString;
        use argon2::{Argon2, PasswordHasher};

        let salt = SaltString::encode_b64(&self.salt).unwrap();
        let argon2 = Argon2::default();

        match argon2.hash_password(data, &salt) {
            Ok(hash) => hash.to_string(),
            Err(_) => String::new(),
        }
    }

    /// 验证 Argon2 哈希
    pub fn verify_argon2(&self, data: &[u8], hash: &str) -> bool {
        use argon2::password_hash::PasswordHash;
        use argon2::{Argon2, PasswordVerifier};

        let argon2 = Argon2::default();
        match PasswordHash::new(hash) {
            Ok(parsed_hash) => argon2.verify_password(data, &parsed_hash).is_ok(),
            Err(_) => false,
        }
    }

    /// 计算 PBKDF2 哈希
    pub fn compute_pbkdf2(&self, data: &[u8]) -> String {
        use pbkdf2::pbkdf2_hmac_array;
        use sha2::Sha256;

        let result = pbkdf2_hmac_array::<Sha256, 32>(data, &self.salt, 100_000);
        hex::encode(result)
    }

    /// 计算 scrypt 哈希
    pub fn compute_scrypt(&self, data: &[u8]) -> Result<String, scrypt::errors::InvalidParams> {
        use scrypt::{scrypt, Params};

        let params = Params::new(14, 8, 1, 32)?;
        let mut output = [0u8; 32];
        scrypt(data, &self.salt, &params, &mut output).ok();
        Ok(hex::encode(output))
    }

    /// 根据算法计算哈希
    pub fn compute_hash(&self, data: &[u8], algorithm: &str) -> String {
        match algorithm {
            "md5" => self.compute_md5(data),
            "sha256" => self.compute_sha256(data),
            "sha512" => self.compute_sha512(data),
            "sha3_256" => self.compute_sha3_256(data),
            "sha3_512" => self.compute_sha3_512(data),
            "argon2" => self.compute_argon2(data),
            "pbkdf2" => self.compute_pbkdf2(data),
            _ => self.compute_sha256(data),
        }
    }

    /// 计算所有支持的哈希值
    pub fn compute_all_hashes(&self, data: &[u8]) -> HashMap<String, String> {
        let mut hashes = HashMap::new();

        hashes.insert("md5".to_string(), self.compute_md5(data));
        hashes.insert("sha256".to_string(), self.compute_sha256(data));
        hashes.insert("sha512".to_string(), self.compute_sha512(data));
        hashes.insert("sha3_256".to_string(), self.compute_sha3_256(data));
        hashes.insert("sha3_512".to_string(), self.compute_sha3_512(data));
        hashes.insert("argon2".to_string(), self.compute_argon2(data));
        hashes.insert("pbkdf2".to_string(), self.compute_pbkdf2(data));

        if let Ok(bcrypt_hash) = self.compute_bcrypt(data) {
            hashes.insert("bcrypt".to_string(), bcrypt_hash);
        }

        if let Ok(scrypt_hash) = self.compute_scrypt(data) {
            hashes.insert("scrypt".to_string(), scrypt_hash);
        }

        hashes
    }

    /// 计算快速哈希（不包含密码哈希）
    pub fn compute_fast_hashes(&self, data: &[u8]) -> HashMap<String, String> {
        let mut hashes = HashMap::new();
        hashes.insert("md5".to_string(), self.compute_md5(data));
        hashes.insert("sha256".to_string(), self.compute_sha256(data));
        hashes.insert("sha3_256".to_string(), self.compute_sha3_256(data));
        hashes
    }

    /// 验证哈希
    pub fn verify_hash(&self, data: &[u8], algorithm: &str, expected: &str) -> bool {
        self.compute_hash(data, algorithm) == expected
    }
}

/// 哈希密码（用于用户认证）
pub fn hash_password(password: &str) -> Result<String, bcrypt::BcryptError> {
    bcrypt::hash(password, bcrypt::DEFAULT_COST)
}

/// 验证密码
pub fn verify_password(password: &str, hash: &str) -> bool {
    bcrypt::verify(password, hash).unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_engine() {
        let engine = HashEngine::new(None);
        let data = b"hello world";

        let md5 = engine.compute_md5(data);
        assert!(!md5.is_empty());

        let sha256 = engine.compute_sha256(data);
        assert!(!sha256.is_empty());
    }

    #[test]
    fn test_password_hash() {
        let password = "secret123";
        let hash = hash_password(password).unwrap();
        assert!(verify_password(password, &hash));
        assert!(!verify_password("wrong", &hash));
    }
}
