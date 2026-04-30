use sha2::{Sha256, Digest};

/// 构建 Merkle 根
pub fn build_merkle_root(hashes: &[String]) -> String {
    if hashes.is_empty() {
        return String::new();
    }

    if hashes.len() == 1 {
        return hashes[0].clone();
    }

    let mut current_level: Vec<String> = hashes.to_vec();

    while current_level.len() > 1 {
        let mut next_level = Vec::new();

        for chunk in current_level.chunks(2) {
            let combined = if chunk.len() == 2 {
                format!("{}{}", chunk[0], chunk[1])
            } else {
                format!("{}{}", chunk[0], chunk[0])
            };

            let mut hasher = Sha256::new();
            hasher.update(combined.as_bytes());
            next_level.push(hex::encode(hasher.finalize()));
        }

        current_level = next_level;
    }

    current_level.into_iter().next().unwrap_or_default()
}

/// Merkle 树
pub struct MerkleTree {
    root: String,
    leaves: Vec<String>,
    levels: Vec<Vec<String>>,
}

impl MerkleTree {
    /// 从数据列表构建 Merkle 树
    pub fn from_data(data: &[&str]) -> Self {
        let leaves: Vec<String> = data
            .iter()
            .map(|d| {
                let mut hasher = Sha256::new();
                hasher.update(d.as_bytes());
                hex::encode(hasher.finalize())
            })
            .collect();

        Self::from_hashes(leaves)
    }

    /// 从哈希列表构建 Merkle 树
    pub fn from_hashes(hashes: Vec<String>) -> Self {
        if hashes.is_empty() {
            return Self {
                root: String::new(),
                leaves: Vec::new(),
                levels: Vec::new(),
            };
        }

        let mut levels = vec![hashes.clone()];
        let mut current_level = hashes.clone();

        while current_level.len() > 1 {
            let mut next_level = Vec::new();

            for chunk in current_level.chunks(2) {
                let combined = if chunk.len() == 2 {
                    format!("{}{}", chunk[0], chunk[1])
                } else {
                    format!("{}{}", chunk[0], chunk[0])
                };

                let mut hasher = Sha256::new();
                hasher.update(combined.as_bytes());
                next_level.push(hex::encode(hasher.finalize()));
            }

            levels.push(next_level.clone());
            current_level = next_level;
        }

        let root = current_level.into_iter().next().unwrap_or_default();

        Self {
            root,
            leaves: hashes,
            levels,
        }
    }

    /// 获取根哈希
    pub fn root(&self) -> &str {
        &self.root
    }

    /// 获取叶子节点
    pub fn leaves(&self) -> &[String] {
        &self.leaves
    }

    /// 获取证明路径
    pub fn get_proof(&self, index: usize) -> Vec<(String, bool)> {
        if index >= self.leaves.len() {
            return Vec::new();
        }

        let mut proof = Vec::new();
        let mut current_index = index;

        for level in &self.levels[..self.levels.len().saturating_sub(1)] {
            let sibling_index = if current_index % 2 == 0 {
                current_index + 1
            } else {
                current_index - 1
            };

            if sibling_index < level.len() {
                let is_left = current_index % 2 == 1;
                proof.push((level[sibling_index].clone(), is_left));
            }

            current_index /= 2;
        }

        proof
    }

    /// 验证证明
    pub fn verify_proof(leaf_hash: &str, proof: &[(String, bool)], root: &str) -> bool {
        let mut current_hash = leaf_hash.to_string();

        for (sibling, is_left) in proof {
            let combined = if *is_left {
                format!("{}{}", sibling, current_hash)
            } else {
                format!("{}{}", current_hash, sibling)
            };

            let mut hasher = Sha256::new();
            hasher.update(combined.as_bytes());
            current_hash = hex::encode(hasher.finalize());
        }

        current_hash == root
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_merkle_root() {
        let hashes = vec![
            "a".to_string(),
            "b".to_string(),
            "c".to_string(),
            "d".to_string(),
        ];
        let root = build_merkle_root(&hashes);
        assert!(!root.is_empty());
    }

    #[test]
    fn test_merkle_tree() {
        let data = vec!["a", "b", "c", "d"];
        let tree = MerkleTree::from_data(&data);
        assert!(!tree.root().is_empty());
        assert_eq!(tree.leaves().len(), 4);
    }

    #[test]
    fn test_merkle_proof() {
        let data = vec!["a", "b", "c", "d"];
        let tree = MerkleTree::from_data(&data);
        
        let proof = tree.get_proof(0);
        let leaf_hash = &tree.leaves()[0];
        
        assert!(MerkleTree::verify_proof(leaf_hash, &proof, tree.root()));
    }
}
