//! 新密码策略(仅用于改密)。

/// bcrypt 只使用前 72 字节,超过会被静默截断,策略层先拒绝。
const MAX_PASSWORD_BYTES: usize = 72;

/// 校验新密码:字符数 >= `min_len`、UTF-8 字节数 <= 72、不含 NUL。
///
/// 错误为固定词表,可直接回给客户端:
/// `password too short` / `password too long` / `password contains invalid characters`。
pub fn validate_new_password(pw: &str, min_len: usize) -> Result<(), &'static str> {
    if pw.contains('\0') {
        return Err("password contains invalid characters");
    }
    if pw.len() > MAX_PASSWORD_BYTES {
        return Err("password too long");
    }
    if pw.chars().count() < min_len {
        return Err("password too short");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_boundaries() {
        assert!(validate_new_password("12345678", 8).is_ok());
        assert!(validate_new_password(&"a".repeat(72), 8).is_ok());
    }

    #[test]
    fn rejects_short_by_chars_not_bytes() {
        assert_eq!(
            validate_new_password("short1", 8),
            Err("password too short")
        );
        // 4 个汉字 = 12 字节,但只有 4 个字符。
        assert_eq!(
            validate_new_password("密码密码", 8),
            Err("password too short")
        );
        assert!(validate_new_password("密码密码密码密码", 8).is_ok());
    }

    #[test]
    fn rejects_too_long_by_bytes() {
        assert_eq!(
            validate_new_password(&"a".repeat(73), 8),
            Err("password too long")
        );
        // 25 个汉字 = 75 字节。
        assert_eq!(
            validate_new_password(&"密".repeat(25), 8),
            Err("password too long")
        );
    }

    #[test]
    fn rejects_nul() {
        assert_eq!(
            validate_new_password("valid\0password1", 8),
            Err("password contains invalid characters")
        );
    }
}
