use sha2::{Digest, Sha256};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use super::{Version, VersionTracker};

/// 默认版本内容快照目录。
pub const DEFAULT_CONTENT_STORAGE_DIR: &str = "./data/version-content";

/// 内容寻址存储
pub struct ContentStorage {
    storage_dir: PathBuf,
}

impl ContentStorage {
    /// 创建内容存储
    pub fn new(storage_dir: impl AsRef<Path>) -> io::Result<Self> {
        let storage_dir = storage_dir.as_ref().to_path_buf();
        fs::create_dir_all(&storage_dir)?;

        Ok(Self { storage_dir })
    }

    /// 从 DATACHAIN_VERSION_CONTENT_DIR 创建内容存储，未配置时使用默认目录。
    pub fn from_env() -> io::Result<Self> {
        let storage_dir = std::env::var_os("DATACHAIN_VERSION_CONTENT_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(DEFAULT_CONTENT_STORAGE_DIR));
        Self::new(storage_dir)
    }

    /// 获取内容存储路径（使用前2个字符作为子目录）。
    fn get_content_path(&self, content_hash: &str) -> io::Result<PathBuf> {
        if content_hash.len() != 64 || !content_hash.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "content hash must be a 64-character hexadecimal SHA-256 value",
            ));
        }

        let subdir = &content_hash[..2];
        let filename = &content_hash[2..];
        Ok(self.storage_dir.join(subdir).join(filename))
    }

    /// 存储内容
    pub fn store_content(&self, content: &[u8]) -> io::Result<String> {
        let mut hasher = Sha256::new();
        hasher.update(content);
        let content_hash = hex::encode(hasher.finalize());
        let path = self.get_content_path(&content_hash)?;

        if let Some(dir) = path.parent() {
            fs::create_dir_all(dir)?;
        }

        // 内容按哈希寻址；已存在的快照可以直接复用。
        if !path.exists() {
            fs::write(&path, content)?;
        }

        Ok(content_hash)
    }

    /// 获取内容
    pub fn retrieve_content(&self, content_hash: &str) -> io::Result<Vec<u8>> {
        let path = self.get_content_path(content_hash)?;
        fs::read(&path)
    }

    /// 检查内容是否存在
    pub fn has_content(&self, content_hash: &str) -> bool {
        self.get_content_path(content_hash)
            .map(|path| path.is_file())
            .unwrap_or(false)
    }

    /// 删除内容
    pub fn delete_content(&self, content_hash: &str) -> io::Result<()> {
        let path = self.get_content_path(content_hash)?;
        fs::remove_file(&path)?;

        if let Some(dir) = path.parent() {
            if let Ok(entries) = fs::read_dir(dir) {
                if entries.count() == 0 {
                    let _ = fs::remove_dir(dir);
                }
            }
        }

        Ok(())
    }

    /// 获取存储统计
    pub fn get_storage_stats(&self) -> StorageStats {
        let mut total_files = 0;
        let mut total_size = 0u64;

        if let Ok(entries) = self.walk_dir(&self.storage_dir) {
            for entry in entries {
                if let Ok(metadata) = entry.metadata() {
                    if metadata.is_file() {
                        total_files += 1;
                        total_size += metadata.len();
                    }
                }
            }
        }

        StorageStats {
            total_files,
            total_size,
            storage_dir: self.storage_dir.to_string_lossy().to_string(),
        }
    }

    /// 遍历目录
    fn walk_dir(&self, dir: &Path) -> io::Result<Vec<fs::DirEntry>> {
        let mut entries = Vec::new();

        for entry in fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();

            if path.is_dir() {
                entries.extend(self.walk_dir(&path)?);
            } else {
                entries.push(entry);
            }
        }

        Ok(entries)
    }

    /// 验证内容完整性
    pub fn verify_content(&self, content_hash: &str) -> io::Result<bool> {
        let content = self.retrieve_content(content_hash)?;

        let mut hasher = Sha256::new();
        hasher.update(&content);
        let computed_hash = hex::encode(hasher.finalize());

        Ok(computed_hash == content_hash)
    }

    /// 列出所有内容哈希
    pub fn list_contents(&self) -> io::Result<Vec<String>> {
        let mut hashes = Vec::new();

        for entry in self.walk_dir(&self.storage_dir)? {
            let path = entry.path();
            if let Ok(rel) = path.strip_prefix(&self.storage_dir) {
                let components: Vec<_> = rel.components().collect();
                if components.len() == 2 {
                    let dir = components[0].as_os_str().to_string_lossy();
                    let file = components[1].as_os_str().to_string_lossy();
                    let hash = format!("{}{}", dir, file);
                    if hash.len() == 64 && hash.bytes().all(|byte| byte.is_ascii_hexdigit()) {
                        hashes.push(hash);
                    }
                }
            }
        }

        Ok(hashes)
    }

    /// 清理孤立内容
    pub fn cleanup(&self, valid_hashes: &std::collections::HashSet<String>) -> io::Result<usize> {
        let mut deleted = 0;

        for hash in self.list_contents()? {
            if !valid_hashes.contains(&hash) && self.delete_content(&hash).is_ok() {
                deleted += 1;
            }
        }

        Ok(deleted)
    }
}

/// 存储统计
#[derive(Debug, Clone, serde::Serialize)]
pub struct StorageStats {
    pub total_files: usize,
    pub total_size: u64,
    pub storage_dir: String,
}

/// 带版本的存储
pub struct VersionedStorage {
    content: ContentStorage,
    tracker: std::sync::Arc<VersionTracker>,
}

impl VersionedStorage {
    /// 创建带版本的存储
    pub fn new(
        storage_dir: impl AsRef<Path>,
        tracker: std::sync::Arc<VersionTracker>,
    ) -> io::Result<Self> {
        let content = ContentStorage::new(storage_dir)?;

        Ok(Self { content, tracker })
    }

    /// 存储文件并追踪版本
    pub fn store_file(&self, file_path: &str, author: &str, message: &str) -> io::Result<Version> {
        let content = fs::read(file_path)?;
        let content_hash = self.content.store_content(&content)?;

        let mut version = self
            .tracker
            .track_file(file_path, author, message)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
        version.content_hash = content_hash;

        Ok(version)
    }

    /// 获取版本内容
    pub fn retrieve_version(&self, version_id: &str) -> io::Result<Vec<u8>> {
        let version = self
            .tracker
            .get_version(version_id)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "version not found"))?;

        self.content.retrieve_content(&version.content_hash)
    }

    /// 获取统计信息
    pub fn get_stats(&self) -> VersionedStorageStats {
        VersionedStorageStats {
            content: self.content.get_storage_stats(),
            version: self.tracker.get_statistics(),
        }
    }
}

/// 带版本的存储统计
#[derive(Debug, Clone, serde::Serialize)]
pub struct VersionedStorageStats {
    pub content: StorageStats,
    pub version: super::VersionStatistics,
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_content_storage() {
        let dir = tempdir().unwrap();
        let storage = ContentStorage::new(dir.path()).unwrap();

        let content = b"hello world";
        let hash = storage.store_content(content).unwrap();

        assert!(storage.has_content(&hash));

        let retrieved = storage.retrieve_content(&hash).unwrap();
        assert_eq!(retrieved, content);

        assert!(storage.verify_content(&hash).unwrap());
    }

    #[test]
    fn test_storage_stats() {
        let dir = tempdir().unwrap();
        let storage = ContentStorage::new(dir.path()).unwrap();

        storage.store_content(b"content1").unwrap();
        storage.store_content(b"content2").unwrap();

        let stats = storage.get_storage_stats();
        assert_eq!(stats.total_files, 2);
    }

    #[test]
    fn rejects_invalid_content_hash() {
        let dir = tempdir().unwrap();
        let storage = ContentStorage::new(dir.path()).unwrap();

        assert!(storage.retrieve_content("../outside").is_err());
        assert!(!storage.has_content("../outside"));
    }
}
