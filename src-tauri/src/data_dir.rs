//! 数据目录迁移：DB、WAL、密钥、known_hosts 必须一起移动。

use std::path::{Path, PathBuf};

use shellwarden_core::error::{AppError, Result};

const FILES: &[&str] = &[
    "shellwarden.db",
    "shellwarden.db-wal",
    "shellwarden.db-shm",
    "secret.key",
    "known_hosts.json",
];

pub fn has_complete_data(dir: &Path) -> bool {
    dir.join("shellwarden.db").is_file() && dir.join("secret.key").is_file()
}

/// 把 source 中的数据复制到 target；source 保留作为备份。
/// target 中已有的完整数据不会被覆盖。
pub fn migrate_data_dir(source: &Path, target: &Path) -> Result<bool> {
    if source == target || !has_complete_data(source) {
        return Ok(false);
    }
    if has_complete_data(target) {
        return Ok(false);
    }
    std::fs::create_dir_all(target).map_err(|error| {
        AppError::new(
            "data.migrate_failed",
            format!("创建数据目录 {} 失败: {error}", target.display()),
        )
    })?;

    for name in FILES {
        let from = source.join(name);
        if !from.is_file() {
            continue;
        }
        let to = target.join(name);
        std::fs::copy(&from, &to).map_err(|error| {
            AppError::new(
                "data.migrate_failed",
                format!("迁移 {} 到 {} 失败: {error}", from.display(), to.display()),
            )
        })?;
    }
    if !has_complete_data(target) {
        return Err(AppError::new(
            "data.migrate_failed",
            format!("迁移到 {} 后缺少数据库或密钥", target.display()),
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(metadata) = std::fs::metadata(target.join("secret.key")) {
            let mut permissions = metadata.permissions();
            permissions.set_mode(0o600);
            let _ = std::fs::set_permissions(target.join("secret.key"), permissions);
        }
    }
    Ok(true)
}

pub fn absolute(path: &Path) -> PathBuf {
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .map(|cwd| cwd.join(path))
            .unwrap_or_else(|_| path.to_path_buf())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn migration_copies_db_and_key_together() {
        let source = tempfile::tempdir().unwrap();
        let target = tempfile::tempdir().unwrap();
        std::fs::write(source.path().join("shellwarden.db"), b"db").unwrap();
        std::fs::write(source.path().join("secret.key"), [7u8; 32]).unwrap();
        std::fs::write(source.path().join("known_hosts.json"), b"{}").unwrap();

        assert!(migrate_data_dir(source.path(), target.path()).unwrap());
        assert_eq!(
            std::fs::read(target.path().join("shellwarden.db")).unwrap(),
            b"db"
        );
        assert_eq!(
            std::fs::read(target.path().join("secret.key")).unwrap(),
            [7u8; 32]
        );
        assert!(target.path().join("known_hosts.json").is_file());
        assert!(has_complete_data(target.path()));
    }

    #[test]
    fn incomplete_target_is_filled_from_source() {
        let source = tempfile::tempdir().unwrap();
        let target = tempfile::tempdir().unwrap();
        std::fs::write(source.path().join("shellwarden.db"), b"db").unwrap();
        std::fs::write(source.path().join("secret.key"), [1u8; 32]).unwrap();
        std::fs::write(target.path().join("shellwarden.db"), b"partial").unwrap();

        assert!(migrate_data_dir(source.path(), target.path()).unwrap());
        assert_eq!(
            std::fs::read(target.path().join("secret.key")).unwrap(),
            [1u8; 32]
        );
    }
}
