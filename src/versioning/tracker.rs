use chrono::{DateTime, Utc};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use crate::error::{DataChainError, Result};

use super::{ContentStorage, DiffCalculator, DiffResult};

/// 版本记录
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Version {
    pub id: i64,
    pub version_id: String,
    pub timestamp: DateTime<Utc>,
    pub file_path: String,
    pub content_hash: String,
    pub size: i64,
    pub author: String,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_version: Option<String>,
}

impl Version {
    /// 创建新版本
    pub fn new(
        file_path: String,
        content_hash: String,
        size: i64,
        author: String,
        message: String,
    ) -> Self {
        Self {
            id: 0,
            version_id: uuid::Uuid::new_v4().to_string(),
            timestamp: Utc::now(),
            file_path,
            content_hash,
            size,
            author,
            message,
            parent_version: None,
        }
    }
}

/// 版本追踪器
pub struct VersionTracker {
    versions: RwLock<HashMap<String, Vec<Version>>>, // file_path -> versions
    content_storage: Arc<ContentStorage>,
}

impl VersionTracker {
    /// 创建版本追踪器，快照目录由 DATACHAIN_VERSION_CONTENT_DIR 配置。
    pub fn new() -> Self {
        Self::try_new().expect("无法初始化版本内容快照存储，请检查 DATACHAIN_VERSION_CONTENT_DIR")
    }

    /// 创建版本追踪器；用于需要显式处理快照目录初始化错误的调用方。
    pub fn try_new() -> Result<Self> {
        let content_storage = ContentStorage::from_env()?;
        Ok(Self::with_content_storage(Arc::new(content_storage)))
    }

    /// 使用指定目录创建版本追踪器。
    pub fn new_with_content_dir(storage_dir: impl AsRef<Path>) -> std::io::Result<Self> {
        let content_storage = ContentStorage::new(storage_dir)?;
        Ok(Self::with_content_storage(Arc::new(content_storage)))
    }

    /// 使用已有内容存储创建版本追踪器。
    pub fn with_content_storage(content_storage: Arc<ContentStorage>) -> Self {
        Self {
            versions: RwLock::new(HashMap::new()),
            content_storage,
        }
    }

    /// 返回快照存储目录路径。
    pub fn content_storage_dir(&self) -> PathBuf {
        PathBuf::from(self.content_storage.get_storage_stats().storage_dir)
    }

    /// 追踪文件变更，同时保存该版本的不可变内容快照。
    pub fn track_file(&self, file_path: &str, author: &str, message: &str) -> Result<Version> {
        let path = Path::new(file_path);

        let mut file = File::open(path)?;
        let mut content = Vec::new();
        file.read_to_end(&mut content)?;

        let size = content.len() as i64;
        let mut hasher = Sha256::new();
        hasher.update(&content);
        let content_hash = hex::encode(hasher.finalize());

        // 无论是否新建元数据，都确保已有版本的内容快照存在。
        // 这也允许为从旧数据库恢复、但尚未有快照的版本补齐内容。
        let stored_hash = self.content_storage.store_content(&content)?;
        if stored_hash != content_hash {
            return Err(DataChainError::StorageError(
                "内容快照哈希与版本内容哈希不一致".to_string(),
            ));
        }

        let versions = self.versions.read();
        if let Some(file_versions) = versions.get(file_path) {
            if let Some(last) = file_versions.last() {
                if last.content_hash == content_hash {
                    return Ok(last.clone());
                }
            }
        }
        drop(versions);

        let mut version = Version::new(
            file_path.to_string(),
            content_hash,
            size,
            author.to_string(),
            message.to_string(),
        );

        let mut versions = self.versions.write();
        if let Some(file_versions) = versions.get(file_path) {
            if let Some(last) = file_versions.last() {
                version.parent_version = Some(last.version_id.clone());
            }
        }

        versions
            .entry(file_path.to_string())
            .or_insert_with(Vec::new)
            .push(version.clone());

        Ok(version)
    }

    /// 追踪目录下所有文件
    pub fn track_directory(
        &self,
        dir_path: &str,
        patterns: &[String],
        author: &str,
    ) -> Result<Vec<Version>> {
        let mut versions = Vec::new();

        let path = Path::new(dir_path);
        if !path.is_dir() {
            return Err(DataChainError::IoError(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "Directory not found",
            )));
        }

        for entry in std::fs::read_dir(path)? {
            let entry = entry?;
            let file_path = entry.path();

            if file_path.is_file() {
                if !patterns.is_empty() {
                    let file_name = file_path.file_name().unwrap().to_string_lossy();
                    let matched = patterns.iter().any(|p| {
                        glob::Pattern::new(p)
                            .map(|pattern| pattern.matches(&file_name))
                            .unwrap_or(false)
                    });
                    if !matched {
                        continue;
                    }
                }

                let file_path = file_path.to_str().ok_or_else(|| {
                    DataChainError::StorageError("文件路径不是有效的 UTF-8 路径".to_string())
                })?;
                versions.push(self.track_file(file_path, author, "")?);
            }
        }

        Ok(versions)
    }

    /// 获取文件版本历史
    pub fn get_version_history(&self, file_path: &str) -> Vec<Version> {
        let versions = self.versions.read();
        versions.get(file_path).cloned().unwrap_or_default()
    }

    /// 获取指定版本
    pub fn get_version(&self, version_id: &str) -> Option<Version> {
        let versions = self.versions.read();
        for file_versions in versions.values() {
            for version in file_versions {
                if version.version_id == version_id {
                    return Some(version.clone());
                }
            }
        }
        None
    }

    /// 获取最新版本
    pub fn get_latest_version(&self, file_path: &str) -> Option<Version> {
        let versions = self.versions.read();
        versions.get(file_path).and_then(|v| v.last().cloned())
    }

    /// 获取所有版本
    pub fn get_all_versions(&self) -> Vec<Version> {
        let versions = self.versions.read();
        versions.values().flatten().cloned().collect()
    }

    /// 获取所有追踪的文件
    pub fn get_tracked_files(&self) -> Vec<String> {
        let versions = self.versions.read();
        versions.keys().cloned().collect()
    }

    /// 加载版本（从存储恢复）
    pub fn load_version(&self, version: Version) {
        let mut versions = self.versions.write();
        versions
            .entry(version.file_path.clone())
            .or_insert_with(Vec::new)
            .push(version);
    }

    /// 按版本 ID 读取不可变内容快照，不会读取当前文件路径。
    pub fn get_version_content(&self, version_id: &str) -> Result<Vec<u8>> {
        let version = self
            .get_version(version_id)
            .ok_or_else(|| DataChainError::VersionNotFound(version_id.to_string()))?;
        self.content_storage
            .retrieve_content(&version.content_hash)
            .map_err(Into::into)
    }

    /// 使用两个版本的历史快照计算文本差异，不依赖当前文件内容。
    pub fn get_version_diff(
        &self,
        old_version_id: &str,
        new_version_id: &str,
    ) -> Result<DiffResult> {
        let old_content =
            String::from_utf8(self.get_version_content(old_version_id)?).map_err(|_| {
                DataChainError::StorageError(format!(
                    "版本 {} 的快照不是有效 UTF-8 文本",
                    old_version_id
                ))
            })?;
        let new_content =
            String::from_utf8(self.get_version_content(new_version_id)?).map_err(|_| {
                DataChainError::StorageError(format!(
                    "版本 {} 的快照不是有效 UTF-8 文本",
                    new_version_id
                ))
            })?;

        Ok(DiffCalculator::compute_version_diff(
            old_version_id,
            new_version_id,
            &old_content,
            &new_content,
        ))
    }

    /// 回滚尚未成功写入存储的新版本。
    pub fn remove_version(&self, version_id: &str) -> bool {
        let mut versions = self.versions.write();
        let mut removed = false;
        for file_versions in versions.values_mut() {
            if let Some(pos) = file_versions
                .iter()
                .position(|version| version.version_id == version_id)
            {
                file_versions.remove(pos);
                removed = true;
                break;
            }
        }
        versions.retain(|_, file_versions| !file_versions.is_empty());
        removed
    }

    /// 获取统计信息
    pub fn get_statistics(&self) -> VersionStatistics {
        let versions = self.versions.read();
        let total_versions: usize = versions.values().map(|v| v.len()).sum();
        let total_size: i64 = versions.values().flatten().map(|v| v.size).sum();

        let mut authors: HashMap<String, usize> = HashMap::new();
        for version in versions.values().flatten() {
            *authors.entry(version.author.clone()).or_insert(0) += 1;
        }

        VersionStatistics {
            tracked_files: versions.len(),
            total_versions,
            total_size,
            authors: authors.into_iter().collect(),
        }
    }
}

impl Default for VersionTracker {
    fn default() -> Self {
        Self::new()
    }
}

/// 版本统计
#[derive(Debug, Clone, Serialize)]
pub struct VersionStatistics {
    pub tracked_files: usize,
    pub total_versions: usize,
    pub total_size: i64,
    pub authors: Vec<(String, usize)>,
}

/// 创建共享的 VersionTracker 实例
pub fn create_version_tracker() -> Arc<VersionTracker> {
    Arc::new(VersionTracker::new())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn track_file_saves_and_reads_snapshot() {
        let source_dir = tempdir().unwrap();
        let snapshot_dir = tempdir().unwrap();
        let file = source_dir.path().join("tracked.txt");
        std::fs::write(&file, "first\n").unwrap();

        let tracker = VersionTracker::new_with_content_dir(snapshot_dir.path()).unwrap();
        let first = tracker
            .track_file(file.to_str().unwrap(), "tester", "initial")
            .unwrap();
        assert_eq!(
            tracker.get_version_content(&first.version_id).unwrap(),
            b"first\n"
        );

        std::fs::write(&file, "second\n").unwrap();
        let second = tracker
            .track_file(file.to_str().unwrap(), "tester", "update")
            .unwrap();
        let diff = tracker
            .get_version_diff(&first.version_id, &second.version_id)
            .unwrap();
        assert_eq!(diff.old_version, first.version_id);
        assert_eq!(diff.new_version, second.version_id);
        assert_eq!(diff.modifications, 1);
    }

    #[test]
    fn missing_snapshot_is_reported() {
        let source_dir = tempdir().unwrap();
        let snapshot_dir = tempdir().unwrap();
        let file = source_dir.path().join("tracked.txt");
        std::fs::write(&file, "content").unwrap();

        let tracker = VersionTracker::new_with_content_dir(snapshot_dir.path()).unwrap();
        let version = Version::new(
            file.to_string_lossy().to_string(),
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string(),
            7,
            "tester".to_string(),
            "loaded".to_string(),
        );
        let version_id = version.version_id.clone();
        tracker.load_version(version);
        assert!(tracker.get_version_content(&version_id).is_err());
    }
}
