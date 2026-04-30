use parking_lot::RwLock;
use std::collections::HashMap;
use std::hash::Hash;
use std::time::{Duration, Instant};

/// 缓存条目
struct CacheEntry<V> {
    value: V,
    created_at: Instant,
    ttl: Duration,
}

impl<V> CacheEntry<V> {
    fn is_expired(&self) -> bool {
        self.created_at.elapsed() > self.ttl
    }
}

/// LRU 缓存
pub struct Cache<K, V> {
    data: RwLock<HashMap<K, CacheEntry<V>>>,
    default_ttl: Duration,
    max_size: usize,
}

impl<K: Eq + Hash + Clone, V: Clone> Cache<K, V> {
    /// 创建缓存
    pub fn new(max_size: usize, default_ttl_secs: u64) -> Self {
        Self {
            data: RwLock::new(HashMap::new()),
            default_ttl: Duration::from_secs(default_ttl_secs),
            max_size,
        }
    }

    /// 获取缓存值
    pub fn get(&self, key: &K) -> Option<V> {
        let data = self.data.read();
        if let Some(entry) = data.get(key) {
            if !entry.is_expired() {
                return Some(entry.value.clone());
            }
        }
        None
    }

    /// 设置缓存值
    pub fn set(&self, key: K, value: V) {
        self.set_with_ttl(key, value, self.default_ttl);
    }

    /// 设置缓存值（自定义 TTL）
    pub fn set_with_ttl(&self, key: K, value: V, ttl: Duration) {
        let mut data = self.data.write();

        // 检查大小限制
        if data.len() >= self.max_size {
            self.evict_expired(&mut data);
        }

        data.insert(
            key,
            CacheEntry {
                value,
                created_at: Instant::now(),
                ttl,
            },
        );
    }

    /// 删除缓存值
    pub fn delete(&self, key: &K) -> bool {
        let mut data = self.data.write();
        data.remove(key).is_some()
    }

    /// 检查是否存在
    pub fn contains(&self, key: &K) -> bool {
        let data = self.data.read();
        if let Some(entry) = data.get(key) {
            return !entry.is_expired();
        }
        false
    }

    /// 清空缓存
    pub fn clear(&self) {
        let mut data = self.data.write();
        data.clear();
    }

    /// 获取缓存大小
    pub fn len(&self) -> usize {
        let data = self.data.read();
        data.len()
    }

    /// 检查是否为空
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// 清理过期条目
    fn evict_expired(&self, data: &mut HashMap<K, CacheEntry<V>>) {
        data.retain(|_, entry| !entry.is_expired());
    }

    /// 获取或设置
    pub fn get_or_set<F>(&self, key: K, f: F) -> V
    where
        F: FnOnce() -> V,
    {
        if let Some(value) = self.get(&key) {
            return value;
        }

        let value = f();
        self.set(key, value.clone());
        value
    }
}

impl<K: Eq + Hash + Clone, V: Clone> Default for Cache<K, V> {
    fn default() -> Self {
        Self::new(1000, 300) // 默认 1000 条目，5 分钟 TTL
    }
}

/// 缓存装饰器宏
#[macro_export]
macro_rules! cached {
    ($cache:expr, $key:expr, $body:expr) => {{
        if let Some(value) = $cache.get(&$key) {
            value
        } else {
            let value = $body;
            $cache.set($key.clone(), value.clone());
            value
        }
    }};
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread::sleep;

    #[test]
    fn test_cache_basic() {
        let cache: Cache<String, i32> = Cache::new(100, 60);

        cache.set("key1".to_string(), 42);
        assert_eq!(cache.get(&"key1".to_string()), Some(42));
        assert_eq!(cache.get(&"key2".to_string()), None);
    }

    #[test]
    fn test_cache_expiration() {
        let cache: Cache<String, i32> = Cache::new(100, 1);

        cache.set_with_ttl("key1".to_string(), 42, Duration::from_millis(100));
        assert_eq!(cache.get(&"key1".to_string()), Some(42));

        sleep(Duration::from_millis(150));
        assert_eq!(cache.get(&"key1".to_string()), None);
    }

    #[test]
    fn test_cache_get_or_set() {
        let cache: Cache<String, i32> = Cache::new(100, 60);

        let value = cache.get_or_set("key1".to_string(), || 42);
        assert_eq!(value, 42);

        let value = cache.get_or_set("key1".to_string(), || 100);
        assert_eq!(value, 42); // 应该返回缓存的值
    }
}
