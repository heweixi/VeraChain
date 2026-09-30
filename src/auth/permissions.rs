use std::collections::{HashMap, HashSet};

use super::Role;

/// 权限枚举
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Permission {
    // 用户权限
    UserCreate,
    UserRead,
    UserUpdate,
    UserDelete,

    // 元数据权限
    MetadataCreate,
    MetadataRead,
    MetadataUpdate,
    MetadataDelete,

    // 区块权限
    BlockRead,
    BlockMine,

    // 汇总权限
    AggregationRead,
    AggregationCreate,
    AggregationTrigger,

    // 版本权限
    VersionRead,
    VersionTrack,

    // 统计权限
    StatsRead,

    // 系统权限
    SystemConfig,
    SystemMonitor,
    SystemAdmin,
}

impl std::fmt::Display for Permission {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Permission::UserCreate => "user:create",
            Permission::UserRead => "user:read",
            Permission::UserUpdate => "user:update",
            Permission::UserDelete => "user:delete",
            Permission::MetadataCreate => "metadata:create",
            Permission::MetadataRead => "metadata:read",
            Permission::MetadataUpdate => "metadata:update",
            Permission::MetadataDelete => "metadata:delete",
            Permission::BlockRead => "block:read",
            Permission::BlockMine => "block:mine",
            Permission::AggregationRead => "aggregation:read",
            Permission::AggregationCreate => "aggregation:create",
            Permission::AggregationTrigger => "aggregation:trigger",
            Permission::VersionRead => "version:read",
            Permission::VersionTrack => "version:track",
            Permission::StatsRead => "stats:read",
            Permission::SystemConfig => "system:config",
            Permission::SystemMonitor => "system:monitor",
            Permission::SystemAdmin => "system:admin",
        };
        write!(f, "{}", s)
    }
}

/// 权限管理器
pub struct PermissionManager {
    role_permissions: HashMap<Role, HashSet<Permission>>,
}

impl PermissionManager {
    /// 创建权限管理器
    pub fn new() -> Self {
        let mut manager = Self {
            role_permissions: HashMap::new(),
        };
        manager.initialize_default_roles();
        manager
    }

    /// 初始化默认角色权限
    fn initialize_default_roles(&mut self) {
        // Admin - 所有权限
        let admin_perms: HashSet<Permission> = [
            Permission::UserCreate,
            Permission::UserRead,
            Permission::UserUpdate,
            Permission::UserDelete,
            Permission::MetadataCreate,
            Permission::MetadataRead,
            Permission::MetadataUpdate,
            Permission::MetadataDelete,
            Permission::BlockRead,
            Permission::BlockMine,
            Permission::AggregationRead,
            Permission::AggregationCreate,
            Permission::AggregationTrigger,
            Permission::VersionRead,
            Permission::VersionTrack,
            Permission::StatsRead,
            Permission::SystemConfig,
            Permission::SystemMonitor,
            Permission::SystemAdmin,
        ]
        .into_iter()
        .collect();
        self.role_permissions.insert(Role::Admin, admin_perms);

        // User - 基本权限
        // 注:对齐 Python/Go 基准,user 不含 block:mine(普通用户不应有出块/挖矿权)
        let user_perms: HashSet<Permission> = [
            Permission::UserRead,
            Permission::MetadataCreate,
            Permission::MetadataRead,
            Permission::MetadataUpdate,
            Permission::MetadataDelete,
            Permission::BlockRead,
            Permission::AggregationRead,
            Permission::VersionRead,
            Permission::VersionTrack,
            Permission::StatsRead,
        ]
        .into_iter()
        .collect();
        self.role_permissions.insert(Role::User, user_perms);

        // Auditor - 只读权限
        let auditor_perms: HashSet<Permission> = [
            Permission::UserRead,
            Permission::MetadataRead,
            Permission::BlockRead,
            Permission::AggregationRead,
            Permission::VersionRead,
            Permission::StatsRead,
            Permission::SystemMonitor,
        ]
        .into_iter()
        .collect();
        self.role_permissions.insert(Role::Auditor, auditor_perms);

        // Guest - 最小权限
        let guest_perms: HashSet<Permission> = [Permission::MetadataRead, Permission::BlockRead]
            .into_iter()
            .collect();
        self.role_permissions.insert(Role::Guest, guest_perms);
    }

    /// 检查角色是否有权限
    pub fn has_permission(&self, role: Role, permission: Permission) -> bool {
        self.role_permissions
            .get(&role)
            .map(|perms| perms.contains(&permission))
            .unwrap_or(false)
    }

    /// 获取角色的所有权限
    pub fn get_permissions(&self, role: Role) -> Vec<Permission> {
        self.role_permissions
            .get(&role)
            .map(|perms| perms.iter().copied().collect())
            .unwrap_or_default()
    }

    /// 获取所有角色
    pub fn get_all_roles(&self) -> Vec<Role> {
        self.role_permissions.keys().copied().collect()
    }
}

impl Default for PermissionManager {
    fn default() -> Self {
        Self::new()
    }
}

/// 全局权限管理器
lazy_static::lazy_static! {
    static ref PERMISSION_MANAGER: PermissionManager = PermissionManager::new();
}

/// 检查权限（便捷函数）
pub fn check_permission(role: Role, permission: Permission) -> bool {
    PERMISSION_MANAGER.has_permission(role, permission)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_admin_permissions() {
        let manager = PermissionManager::new();
        assert!(manager.has_permission(Role::Admin, Permission::SystemAdmin));
        assert!(manager.has_permission(Role::Admin, Permission::UserDelete));
    }

    #[test]
    fn test_user_permissions() {
        let manager = PermissionManager::new();
        assert!(manager.has_permission(Role::User, Permission::MetadataCreate));
        assert!(manager.has_permission(Role::User, Permission::BlockRead));
        assert!(!manager.has_permission(Role::User, Permission::SystemAdmin));
        // 对齐 Python/Go:普通 user 不应有出块/挖矿权
        assert!(!manager.has_permission(Role::User, Permission::BlockMine));
    }

    #[test]
    fn test_guest_permissions() {
        let manager = PermissionManager::new();
        assert!(manager.has_permission(Role::Guest, Permission::BlockRead));
        assert!(!manager.has_permission(Role::Guest, Permission::MetadataCreate));
    }
}
