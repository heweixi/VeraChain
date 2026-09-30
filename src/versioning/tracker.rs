use chrono::{DateTime, Utc};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use sha2::{Sha256, Digest};
use std::collections::HashMap;
use std::fs::File;
use std::io::Read;
use std::path::Path;
use std::sync::Arc;

use crate::error::{DataChainError, Result};

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
    pub fn new(file_path: String, content_hash: String, size: i64, author: String, message: String) -> Self {
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
}

impl VersionTracker {
    /// 创建版本追踪器
    pub fn new() -> Self {
        Self {
            versions: RwLock::new(HashMap::new()),
        }
    }

    /// 追踪文件变更
    pub fn track_file(&self, file_path: &str, author: &str, message: &str) -> Result<Version> {
        let path = Path::new(file_path);
        
        // 读取文件
        let mut file = File::open(path)?;
        let mut content = Vec::new();
        file.read_to_end(&mut content)?;

        // 获取文件信息
        let metadata = std::fs::metadata(path)?;
        let size = metadata.len() as i64;

        // 计算哈希
        let mut hasher = Sha256::new();
        hasher.update(&content);
        let content_hash = hex::encode(hasher.finalize());

        // 检查是否有变更
        let versions = self.versions.read();
        if let Some(file_versions) = versions.get(file_path) {
            if let Some(last) = file_versions.last() {
                if last.content_hash == content_hash {
                    return Ok(last.clone()); // 无变更
                }
            }
        }
        drop(versions);

        // 创建新版本
        let mut version = Version::new(
            file_path.to_string(),
            content_hash,
            size,
            author.to_string(),
            message.to_string(),
        );

        // 设置父版本
        let mut versions = self.versions.write();
        if let Some(file_versions) = versions.get(file_path) {
            if let Some(last) = file_versions.last() {
                version.parent_version = Some(last.version_id.clone());
            }
        }

        // 保存版本
        versions
            .entry(file_path.to_string())
            .or_insert_with(Vec::new)
            .push(version.clone());

        Ok(version)
    }

    /// 追踪目录下所有文件
    pub fn track_directory(&self, dir_path: &str, patterns: &[String], author: &str) -> Result<Vec<Version>> {
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
                // 检查是否匹配模式
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

                if let Ok(version) = self.track_file(file_path.to_str().unwrap(), author, "") {
                    versions.push(version);
                }
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
            for v in file_versions {
                if v.version_id == version_id {
                    return Some(v.clone());
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

    /// 回滚尚未成功写入存储的新版本。
    pub fn remove_version(&self, version_id: &str) -> bool {
        let mut versions = self.versions.write();
        let mut removed = false;
        for file_versions in versions.values_mut() {
            if let Some(pos) = file_versions.iter().position(|version| version.version_id == version_id) {
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
        let total_size: i64 = versions
            .values()
            .flatten()
            .map(|v| v.size)
            .sum();

        let mut authors: HashMap<String, usize> = HashMap::new();
        for v in versions.values().flatten() {
            *authors.entry(v.author.clone()).or_insert(0) += 1;
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
