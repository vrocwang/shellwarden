-- 私钥文件路径与口令的独立保存；PEM 内容仍在 host_private_keys。
CREATE TABLE IF NOT EXISTS host_key_auth (
    host_id                 TEXT PRIMARY KEY REFERENCES hosts(id) ON DELETE CASCADE,
    mode                    TEXT NOT NULL CHECK (mode IN ('file', 'pem')),
    key_path                TEXT,
    passphrase_ciphertext   BLOB,
    passphrase_nonce        BLOB,
    updated_at              TEXT NOT NULL
);
