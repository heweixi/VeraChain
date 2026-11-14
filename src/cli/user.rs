use clap::Subcommand;
use std::io::{BufRead, Read};

use crate::auth::{
    create_auth_service_with_settings, LoginContext, LoginRequest, RegisterRequest, Role,
};
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
    /// 停用用户(撤销其全部会话;运行中的服务最迟一个缓存 TTL 内生效)
    Deactivate {
        /// 用户名
        username: String,
    },
    /// 启用用户(不恢复已撤销的会话,需重新登录)
    Activate {
        /// 用户名
        username: String,
    },
    /// 重置用户密码(从 stdin 读一行新密码,不验旧密码;撤销该用户全部会话)
    Passwd {
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
    let auth_service = create_auth_service_with_settings(
        config.jwt.secret.clone(),
        storage.clone(),
        config.auth_settings(),
    );

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

            // 策略拒绝 / 用户已存在 / 保存失败都返回 Err(退出码非 0);错误文本不含密码。
            // 直接用 `?` 传播,保留 DataChainError 类型供 exit_code_for downcast(其他错误为 1)。
            let user = auth_service.register_validated(&req, role).await?;
            if let Err(e) = storage.save_user(&user).await {
                auth_service.remove_user(&user.user_id);
                return Err(e.into());
            }
            println!("✓ 用户已创建");
            println!("  用户 ID: {}", user.user_id);
            println!("  用户名: {}", user.username);
            println!("  角色: {}", user.role);
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
        UserAction::Deactivate { username } => {
            let user = auth_service
                .get_user(&username)
                .map_err(|_| anyhow::anyhow!("用户不存在: {}", username.escape_debug()))?;
            let revoked = auth_service.deactivate_user(&user.user_id).await?;
            println!("✓ 用户已停用");
            println!("  用户名: {}", user.username);
            println!("  已撤销会话数: {}", revoked);
        }
        UserAction::Activate { username } => {
            let user = auth_service
                .get_user(&username)
                .map_err(|_| anyhow::anyhow!("用户不存在: {}", username.escape_debug()))?;
            auth_service.activate_user(&user.user_id).await?;
            println!("✓ 用户已启用(旧会话不会恢复,需重新登录)");
            println!("  用户名: {}", user.username);
        }
        UserAction::Passwd { username } => {
            let user = auth_service
                .get_user(&username)
                .map_err(|_| anyhow::anyhow!("用户不存在: {}", username.escape_debug()))?;

            // 只读一行,最多 1 KiB;超长无换行的输入会被截成 1 KiB,随后被策略按 too long 拒绝。
            let mut line = String::new();
            std::io::stdin().lock().take(1024).read_line(&mut line)?;
            let password = line
                .strip_suffix('\n')
                .map(|s| s.strip_suffix('\r').unwrap_or(s))
                .unwrap_or(&line);
            if password.is_empty() {
                return Err(anyhow::anyhow!("未从 stdin 读取到新密码"));
            }

            // 策略拒绝(password too short 等)直接传播;错误文本不含密码。
            let revoked = auth_service
                .reset_password(&user.user_id, password, &LoginContext::default())
                .await?;
            println!("✓ 密码已重置(已撤销 {} 个会话)", revoked);
            println!("  用户名: {}", user.username);
        }
        UserAction::Login { username, password } => {
            let req = LoginRequest { username, password };

            match auth_service.login(&req, &LoginContext::default()).await {
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
