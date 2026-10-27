-- 主机私钥加密存储与主机目录（分组）。
CREATE TABLE IF NOT EXISTS host_private_keys (
    host_id                 TEXT PRIMARY KEY REFERENCES hosts(id) ON DELETE CASCADE,
    ciphertext              BLOB NOT NULL,
    nonce                   BLOB NOT NULL,
    passphrase_ciphertext   BLOB,
    passphrase_nonce        BLOB,
    updated_at              TEXT NOT NULL
);

ALTER TABLE hosts ADD COLUMN group_name TEXT NOT NULL DEFAULT '';
