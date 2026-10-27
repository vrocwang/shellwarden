//! 本地加密存储：密码用 AES-256-GCM 加密后写入 SQLite。
//!
//! 密钥保存在应用数据目录的 `secret.key`（Unix 下权限 0600），首次启动自动生成。
//! 这样不依赖 macOS Keychain / Windows Credential Manager / Secret Service，
//! 三平台行为一致。
//!
//! 安全边界（必须如实说明）：它能防止「数据库文件被单独拷走/备份泄漏」直接读到密码；
//! 但能读到 `secret.key` 的本机用户仍然可以解密。需要更强保护时应引入主密码派生
//! （Argon2id），当前未实现。

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use aes_gcm::aead::{rand_core::RngCore, Aead, KeyInit, OsRng};
use aes_gcm::{Aes256Gcm, Nonce};

use shellwarden_core::error::{AppError, Result};

const KEY_FILE: &str = "secret.key";
const KEY_LEN: usize = 32;
const NONCE_LEN: usize = 12;

pub struct SecretBox {
    cipher: Aes256Gcm,
    #[allow(dead_code)] // 仅用于诊断与测试
    key_path: PathBuf,
}

impl SecretBox {
    pub fn load_or_create(dir: &Path) -> Result<Self> {
        fs::create_dir_all(dir).map_err(|e| {
            AppError::new("secret.key_unavailable", format!("创建数据目录失败: {e}"))
        })?;
        let path = dir.join(KEY_FILE);

        let key = match fs::read(&path) {
            Ok(bytes) if bytes.len() == KEY_LEN => bytes,
            Ok(_) => {
                return Err(AppError::new(
                    "secret.invalid_key",
                    "secret.key 长度不正确（应为 32 字节）；请备份后删除该文件重新生成",
                ))
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                let mut key = vec![0u8; KEY_LEN];
                OsRng.fill_bytes(&mut key);
                write_key_file(&path, &key)?;
                key
            }
            Err(error) => {
                return Err(AppError::new(
                    "secret.key_unavailable",
                    format!("读取 secret.key 失败: {error}"),
                ))
            }
        };

        let cipher = Aes256Gcm::new_from_slice(&key)
            .map_err(|_| AppError::new("secret.invalid_key", "secret.key 无法用于 AES-256-GCM"))?;
        Ok(Self {
            cipher,
            key_path: path,
        })
    }

    pub fn encrypt(&self, plaintext: &str) -> Result<(Vec<u8>, Vec<u8>)> {
        let mut nonce = [0u8; NONCE_LEN];
        OsRng.fill_bytes(&mut nonce);
        let ciphertext = self
            .cipher
            .encrypt(Nonce::from_slice(&nonce), plaintext.as_bytes())
            .map_err(|_| AppError::new("secret.encrypt_failed", "加密密码失败"))?;
        Ok((ciphertext, nonce.to_vec()))
    }

    pub fn decrypt(&self, ciphertext: &[u8], nonce: &[u8]) -> Result<String> {
        if nonce.len() != NONCE_LEN {
            return Err(AppError::new("secret.invalid_nonce", "密码记录已损坏"));
        }
        let plaintext = self
            .cipher
            .decrypt(Nonce::from_slice(nonce), ciphertext)
            .map_err(|_| {
                AppError::new(
                    "secret.decrypt_failed",
                    "解密密码失败：secret.key 可能已更换，请重新输入并保存密码",
                )
            })?;
        String::from_utf8(plaintext)
            .map_err(|_| AppError::new("secret.invalid_utf8", "密码记录不是合法文本"))
    }

    #[allow(dead_code)]
    pub fn key_path(&self) -> &Path {
        &self.key_path
    }
}

fn write_key_file(path: &Path, key: &[u8]) -> Result<()> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path).map_err(|e| {
        AppError::new(
            "secret.key_unavailable",
            format!("创建 secret.key 失败: {e}"),
        )
    })?;
    file.write_all(key)
        .and_then(|_| file.sync_all())
        .map_err(|e| {
            AppError::new(
                "secret.key_unavailable",
                format!("写入 secret.key 失败: {e}"),
            )
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_and_persistence() {
        let dir = tempfile::tempdir().unwrap();
        let secrets = SecretBox::load_or_create(dir.path()).unwrap();
        let (ct, nonce) = secrets.encrypt("hunter2").unwrap();
        assert_ne!(ct, b"hunter2");
        assert_eq!(secrets.decrypt(&ct, &nonce).unwrap(), "hunter2");

        // 重新加载同一密钥文件仍能解密
        let again = SecretBox::load_or_create(dir.path()).unwrap();
        assert_eq!(again.decrypt(&ct, &nonce).unwrap(), "hunter2");
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let dir = tempfile::tempdir().unwrap();
        let secrets = SecretBox::load_or_create(dir.path()).unwrap();
        let (mut ct, nonce) = secrets.encrypt("secret").unwrap();
        ct[0] ^= 0xff;
        assert!(secrets.decrypt(&ct, &nonce).is_err());
    }

    #[test]
    fn wrong_nonce_length_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let secrets = SecretBox::load_or_create(dir.path()).unwrap();
        let (ct, _) = secrets.encrypt("x").unwrap();
        assert!(secrets.decrypt(&ct, &[0u8; 8]).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn key_file_permissions_are_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let secrets = SecretBox::load_or_create(dir.path()).unwrap();
        let mode = fs::metadata(secrets.key_path())
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);
    }

    #[test]
    fn password_roundtrips_through_database() {
        use shellwarden_store::{Db, NewHost};

        let dir = tempfile::tempdir().unwrap();
        let db = Db::open_in_memory().unwrap();
        let host = db
            .create_host(NewHost {
                name: "prod".into(),
                hostname: "10.0.0.1".into(),
                port: 22,
                default_username: "ops".into(),
                tags: vec![],
                ssh_backend: "auto".into(),
                group_name: String::new(),
            })
            .unwrap();

        let secrets = SecretBox::load_or_create(dir.path()).unwrap();
        let (ciphertext, nonce) = secrets.encrypt("s3cret").unwrap();
        db.save_credential(&host.id, &ciphertext, &nonce).unwrap();

        let (stored, stored_nonce) = db.load_credential(&host.id).unwrap().unwrap();
        assert_ne!(stored, b"s3cret");
        assert_eq!(secrets.decrypt(&stored, &stored_nonce).unwrap(), "s3cret");
    }

    #[test]
    fn corrupted_key_file_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join(KEY_FILE), b"short").unwrap();
        assert!(SecretBox::load_or_create(dir.path()).is_err());
    }
}
