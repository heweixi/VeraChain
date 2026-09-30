//! 统一区块哈希算法 (Block Hash Spec v1)，详见仓库根 BLOCK_HASH_SPEC.md。
//! 三语言实现必须产出字节级一致的哈希。
//!
//! canonical string:
//!   v1|{index}|{timestamp_unix}|{previous_hash}|{merkle_root}|{nonce}|{difficulty}
//! block_hash = lower_hex(SHA256(utf8(canonical string)))
//!
//! - timestamp 统一为 Unix 秒(整数)
//! - 整数十进制、无前导零、无正号（Rust `{}` 满足）
//! - previous_hash / merkle_root 原样(hex 或 "0" / 空串)

use sha2::{Digest, Sha256};

pub const SPEC_VERSION: &str = "v1";

/// 构造规范字符串(见 BLOCK_HASH_SPEC.md 第 3 节)。
pub fn canonical_block_string(
    index: i64,
    timestamp_unix: i64,
    previous_hash: &str,
    merkle_root: &str,
    nonce: u64,
    difficulty: u32,
) -> String {
    format!(
        "{}|{}|{}|{}|{}|{}|{}",
        SPEC_VERSION, index, timestamp_unix, previous_hash, merkle_root, nonce, difficulty
    )
}

/// 按规范计算区块哈希,返回小写 hex。
pub fn canonical_block_hash(
    index: i64,
    timestamp_unix: i64,
    previous_hash: &str,
    merkle_root: &str,
    nonce: u64,
    difficulty: u32,
) -> String {
    let s = canonical_block_string(
        index,
        timestamp_unix,
        previous_hash,
        merkle_root,
        nonce,
        difficulty,
    );
    let mut hasher = Sha256::new();
    hasher.update(s.as_bytes());
    hex::encode(hasher.finalize())
}

/// 元数据条目的 Merkle 叶子哈希(BLOCK_HASH_SPEC.md 第 10 节 v1)。
/// 叶子 = SHA256(data_id) 小写 hex,以 data_id 为条目身份,跨语言绝对一致。
pub fn metadata_leaf_hash(data_id: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data_id.as_bytes());
    hex::encode(hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    // 与 BLOCK_HASH_SPEC.md 第 6 节一致的黄金向量
    const GOLDEN_A: &str = "00c70da3ef00282af337628b29198c5168478082a97396a255346c30a0a45e93";
    const GOLDEN_B: &str = "48ecfe3fa4bbcaeccc3923314be8169e9311c714ccc84eae59e639c50b8fee46";

    #[test]
    fn test_canonical_string_vectors() {
        assert_eq!(
            canonical_block_string(0, 1735689600, "0", "", 0, 0),
            "v1|0|1735689600|0||0|0"
        );
        assert_eq!(
            canonical_block_string(42, 1767225600, "abc123", "def456", 7, 3),
            "v1|42|1767225600|abc123|def456|7|3"
        );
    }

    #[test]
    fn test_golden_a() {
        assert_eq!(canonical_block_hash(0, 1735689600, "0", "", 0, 0), GOLDEN_A);
    }

    #[test]
    fn test_golden_b() {
        assert_eq!(
            canonical_block_hash(42, 1767225600, "abc123", "def456", 7, 3),
            GOLDEN_B
        );
    }

    #[test]
    fn test_deterministic() {
        let h1 = canonical_block_hash(5, 123, "aa", "bb", 1, 1);
        let h2 = canonical_block_hash(5, 123, "aa", "bb", 1, 1);
        assert_eq!(h1, h2);
        assert_eq!(h1.len(), 64);
    }

    // 元数据叶子(SHA256(data_id)) + merkle 黄金向量(BLOCK_HASH_SPEC 第10节 v1)
    #[test]
    fn test_metadata_leaf_merkle_golden() {
        const LEAF_M1: &str = "ca0df2c95aa144c1d0ff2ff3c8f967fdc1de9ef0c4120b3726416701b519d619";
        assert_eq!(metadata_leaf_hash("m1"), LEAF_M1);

        let root = |ids: &[&str]| -> String {
            let leaves: Vec<String> = ids.iter().map(|id| metadata_leaf_hash(id)).collect();
            crate::core::build_merkle_root(&leaves)
        };
        assert_eq!(root(&["m1"]), LEAF_M1);
        assert_eq!(
            root(&["m1", "m2"]),
            "51d9c2e35a60bdab27c3861e044b7bd5b352eaa01ac6deec719f338f8283e637"
        );
        assert_eq!(
            root(&["m1", "m2", "m3"]),
            "0aeb61df09972a07a9928365ff0b6f0d03c4a60ee0999ea2e12eabbebf7db4f1"
        );
    }
}
