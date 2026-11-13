-- 会话列表对外展示的脱敏 IP 提示(如 203.0.x.x),不含完整 IP
ALTER TABLE sessions ADD COLUMN ip_hint TEXT
