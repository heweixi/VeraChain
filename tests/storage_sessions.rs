//! S1:Storage 会话(sessions)与用户启停公开方法的行为测试。

use datachain::auth::{Role, User};
use datachain::storage::{create_storage, SessionRecord, Storage};
use std::sync::Arc;

async fn new_storage() -> (Arc<Storage>, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("sessions.db");
    let storage = create_storage(path.to_str().unwrap()).await.unwrap();
    (storage, dir)
}

fn session(id: &str, user_id: &str, family: &str, expires_at: i64) -> SessionRecord {
    SessionRecord {
        id: id.to_string(),
        user_id: user_id.to_string(),
        refresh_family: family.to_string(),
        created_at: 1_000,
        last_seen_at: 1_000,
        expires_at,
        revoked_at: None,
        revoke_reason: None,
        ip_hash: Some("abcd".to_string()),
        ip_hint: None,
        user_agent: Some("test-agent".to_string()),
    }
}

const FAR_FUTURE: i64 = 4_102_444_800; // 2100-01-01

#[tokio::test]
async fn created_session_can_be_read_back_and_listed() {
    let (storage, _dir) = new_storage().await;
    storage
        .create_session(&session("s1", "u1", "fam1", FAR_FUTURE))
        .await
        .unwrap();

    let got = storage
        .get_session("s1")
        .await
        .unwrap()
        .expect("会话应存在");
    assert_eq!(got.user_id, "u1");
    assert_eq!(got.refresh_family, "fam1");
    assert_eq!(got.expires_at, FAR_FUTURE);
    assert_eq!(got.revoked_at, None);
    assert_eq!(got.user_agent.as_deref(), Some("test-agent"));

    assert!(storage.get_session("missing").await.unwrap().is_none());

    let active = storage.list_active_sessions("u1", 2_000).await.unwrap();
    assert_eq!(active.len(), 1);
    assert_eq!(active[0].id, "s1");
    // 其他用户看不到。
    assert!(storage
        .list_active_sessions("u2", 2_000)
        .await
        .unwrap()
        .is_empty());
}

#[tokio::test]
async fn expired_sessions_are_not_listed_as_active() {
    let (storage, _dir) = new_storage().await;
    storage
        .create_session(&session("old", "u1", "fam-old", 1_500))
        .await
        .unwrap();
    storage
        .create_session(&session("new", "u1", "fam-new", FAR_FUTURE))
        .await
        .unwrap();

    let active = storage.list_active_sessions("u1", 2_000).await.unwrap();
    let ids: Vec<&str> = active.iter().map(|s| s.id.as_str()).collect();
    assert_eq!(ids, vec!["new"]);
}

#[tokio::test]
async fn revoking_session_marks_it_and_revokes_refresh_family() {
    let (storage, _dir) = new_storage().await;
    storage
        .create_session(&session("s1", "u1", "fam1", FAR_FUTURE))
        .await
        .unwrap();
    assert!(!storage.is_family_revoked("u1", "fam1").await.unwrap());

    let newly = storage
        .revoke_session("s1", "logout", 7 * 24 * 3600)
        .await
        .unwrap();
    assert!(newly, "首次撤销应返回 true");

    let got = storage.get_session("s1").await.unwrap().unwrap();
    assert!(got.revoked_at.is_some(), "会话应已撤销");
    assert_eq!(got.revoke_reason.as_deref(), Some("logout"));
    assert!(
        storage.is_family_revoked("u1", "fam1").await.unwrap(),
        "撤销会话必须联动撤销 refresh family"
    );
    assert!(storage
        .list_active_sessions("u1", 2_000)
        .await
        .unwrap()
        .is_empty());

    // 幂等:再次撤销返回 false,不报错。
    assert!(!storage.revoke_session("s1", "logout", 3600).await.unwrap());
    // 不存在的会话返回 false。
    assert!(!storage
        .revoke_session("nope", "logout", 3600)
        .await
        .unwrap());
}

#[tokio::test]
async fn user_active_flag_reads_and_writes_database() {
    let (storage, _dir) = new_storage().await;
    let user = User::new(
        "alice".to_string(),
        "hash".to_string(),
        "alice@example.com".to_string(),
        Role::User,
    );
    storage.save_user(&user).await.unwrap();

    assert!(storage.is_user_active(&user.user_id).await.unwrap());

    assert!(storage.set_user_active(&user.user_id, false).await.unwrap());
    assert!(!storage.is_user_active(&user.user_id).await.unwrap());

    assert!(storage.set_user_active(&user.user_id, true).await.unwrap());
    assert!(storage.is_user_active(&user.user_id).await.unwrap());

    // 不存在的用户:视为非活跃(fail-closed),set 返回 false。
    assert!(!storage.is_user_active("ghost").await.unwrap());
    assert!(!storage.set_user_active("ghost", true).await.unwrap());
}
