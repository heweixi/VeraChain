-- 管理员操作的操作者 user_id,user_id 列仍表示被操作对象
ALTER TABLE auth_audit_log ADD COLUMN actor_user_id TEXT
