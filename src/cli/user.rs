use clap::Subcommand;

use crate::auth::{create_auth_service, LoginRequest, RegisterRequest, Role};
use crate::config::AppConfig;
use crate::storage::create_storage;

#[derive(Subcommand)]
pub enum UserAction {
    /// 创建用户
    Create {
        /// 用户名
        #[arg(short, long)]
        username: String,
        /// 密码
        #[arg(short, long)]
        password: String,
        /// 邮箱
        #[arg(short, long)]
        email: String,
        /// 角色
        #[arg(short, long, default_value = "user")]
        role: String,
    },
    /// 列出用户
    List,
    /// 获取用户
    Get {
        /// 用户名
        username: String,
    },
    /// 用户登录
    Login {
        /// 用户名
        #[arg(short, long)]
        username: String,
        /// 密码
        #[arg(short, long)]
        password: String,
    },
}

/// 运行用户命令
pub async fn run_user(config: &AppConfig, action: UserAction) -> anyhow::Result<()> {
    let storage = create_storage(&config.database.dsn).await?;
    let auth_service = create_auth_service(config.jwt.secret.clone(), config.jwt.expire_hours);

    // 加载用户
    let users = storage.get_all_users().await?;
    for user in users {
        auth_service.load_user(user);
    }

    match action {
        UserAction::Create {
            username,
            password,
            email,
            role,
        } => {
            let role: Role = role.parse().unwrap_or(Role::User);

            let req = RegisterRequest {
                username: username.clone(),
                password,
                email,
                role: Some(role),
            };

            match auth_service.register_with_role(&req, role) {
                Ok(user) => {
                    storage.save_user(&user).await?;
                    println!("✓ 用户已创建");
                    println!("  用户 ID: {}", user.user_id);
                    println!("  用户名: {}", user.username);
                    println!("  角色: {}", user.role);
                }
                Err(e) => {
                    println!("✗ 创建用户失败: {}", e);
                }
            }
        }
        UserAction::List => {
            let users = auth_service.get_all_users();
            println!("用户列表 (共 {} 个)", users.len());
            println!("=========");

            for user in users {
                println!(
                    "{} | {} | {} | {}",
                    user.username,
                    user.email,
                    user.role,
                    if user.is_active { "活跃" } else { "停用" }
                );
            }
        }
        UserAction::Get { username } => match auth_service.get_user(&username) {
            Ok(user) => {
                println!("用户详情");
                println!("========");
                println!("用户 ID: {}", user.user_id);
                println!("用户名: {}", user.username);
                println!("邮箱: {}", user.email);
                println!("角色: {}", user.role);
                println!("状态: {}", if user.is_active { "活跃" } else { "停用" });
                println!("创建时间: {}", user.created_at);
                if let Some(last_login) = user.last_login {
                    println!("最后登录: {}", last_login);
                }
            }
            Err(e) => {
                println!("✗ 用户未找到: {}", e);
            }
        },
        UserAction::Login { username, password } => {
            let req = LoginRequest { username, password };

            match auth_service.login(&req) {
                Ok(resp) => {
                    println!("✓ 登录成功");
                    println!("  用户: {}", resp.user.username);
                    println!("  角色: {}", resp.user.role);
                    println!("  令牌: {}...", &resp.token[..50]);
                    println!("  过期时间: {}", resp.expires_at);
                }
                Err(e) => {
                    println!("✗ 登录失败: {}", e);
                }
            }
        }
    }

    Ok(())
}
