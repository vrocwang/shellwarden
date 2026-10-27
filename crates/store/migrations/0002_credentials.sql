-- 加密后的主机密码（AES-256-GCM）。密钥在应用数据目录的 secret.key。
CREATE TABLE IF NOT EXISTS host_credentials (
    host_id   TEXT PRIMARY KEY REFERENCES hosts(id) ON DELETE CASCADE,
    ciphertext BLOB NOT NULL,
    nonce      BLOB NOT NULL,
    updated_at TEXT NOT NULL
);
