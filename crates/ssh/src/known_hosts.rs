use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use chrono::{DateTime, SecondsFormat, Utc};
use serde::{Deserialize, Serialize};

use crate::config::{HostKeyInfo, TrustState};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KnownHostEntry {
    pub host: String,
    pub port: u16,
    pub algorithm: String,
    pub fingerprint: String,
    pub first_seen_at: String,
    pub last_seen_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct FileData {
    version: u32,
    entries: Vec<KnownHostEntry>,
}

impl Default for FileData {
    fn default() -> Self {
        Self {
            version: 1,
            entries: Vec::new(),
        }
    }
}

/// 应用自管的 known_hosts。与 OpenSSH 的 known_hosts 分开：
/// 便于按主机展示、单独备份，也避免误改用户的系统文件。
#[derive(Debug)]
pub struct KnownHostsStore {
    path: PathBuf,
    data: FileData,
}

impl KnownHostsStore {
    pub fn load(path: impl AsRef<Path>) -> Result<Self, String> {
        let path = path.as_ref().to_path_buf();
        if !path.exists() {
            return Ok(Self {
                path,
                data: FileData::default(),
            });
        }
        let raw = fs::read_to_string(&path).map_err(|e| format!("读取 known_hosts 失败: {e}"))?;
        let data: FileData =
            serde_json::from_str(&raw).map_err(|e| format!("known_hosts 解析失败: {e}"))?;
        Ok(Self { path, data })
    }

    pub fn entries(&self) -> &[KnownHostEntry] {
        &self.data.entries
    }

    pub fn verify(&self, host: &str, port: u16, info: &HostKeyInfo) -> TrustState {
        match self.find(host, port) {
            None => TrustState::Unknown,
            Some(entry)
                if entry.fingerprint == info.fingerprint && entry.algorithm == info.algorithm =>
            {
                TrustState::Trusted
            }
            Some(entry) => TrustState::Changed {
                known: HostKeyInfo {
                    algorithm: entry.algorithm.clone(),
                    fingerprint: entry.fingerprint.clone(),
                },
            },
        }
    }

    fn find(&self, host: &str, port: u16) -> Option<&KnownHostEntry> {
        self.data
            .entries
            .iter()
            .find(|e| e.host == host && e.port == port)
    }

    /// 取已记录的指纹，供建立会话时作为期望值。
    pub fn get(&self, host: &str, port: u16) -> Option<HostKeyInfo> {
        self.find(host, port).map(|e| HostKeyInfo {
            algorithm: e.algorithm.clone(),
            fingerprint: e.fingerprint.clone(),
        })
    }

    /// 记录或更新信任。只应在用户确认指纹后调用。
    pub fn trust(
        &mut self,
        host: &str,
        port: u16,
        info: &HostKeyInfo,
        now: DateTime<Utc>,
    ) -> Result<(), String> {
        let ts = now.to_rfc3339_opts(SecondsFormat::Millis, true);
        if let Some(entry) = self
            .data
            .entries
            .iter_mut()
            .find(|e| e.host == host && e.port == port)
        {
            entry.algorithm = info.algorithm.clone();
            entry.fingerprint = info.fingerprint.clone();
            entry.last_seen_at = ts;
        } else {
            self.data.entries.push(KnownHostEntry {
                host: host.to_string(),
                port,
                algorithm: info.algorithm.clone(),
                fingerprint: info.fingerprint.clone(),
                first_seen_at: ts.clone(),
                last_seen_at: ts,
            });
        }
        self.save()
    }

    pub fn forget(&mut self, host: &str, port: u16) -> Result<bool, String> {
        let before = self.data.entries.len();
        self.data
            .entries
            .retain(|e| !(e.host == host && e.port == port));
        let removed = before != self.data.entries.len();
        if removed {
            self.save()?;
        }
        Ok(removed)
    }

    fn save(&self) -> Result<(), String> {
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent).map_err(|e| format!("创建目录失败: {e}"))?;
        }
        let tmp = self.path.with_extension("json.tmp");
        let raw = serde_json::to_string_pretty(&self.data)
            .map_err(|e| format!("序列化 known_hosts 失败: {e}"))?;
        let mut options = fs::OpenOptions::new();
        options.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options
            .open(&tmp)
            .map_err(|e| format!("写入 known_hosts 失败: {e}"))?;
        file.write_all(raw.as_bytes())
            .and_then(|_| file.sync_all())
            .map_err(|e| format!("写入 known_hosts 失败: {e}"))?;
        match fs::rename(&tmp, &self.path) {
            Ok(()) => Ok(()),
            Err(error) => {
                // Windows 的 rename 不能覆盖已存在文件；删除旧文件后重试。
                #[cfg(windows)]
                {
                    fs::remove_file(&self.path).map_err(|remove_error| {
                        format!("替换 known_hosts 失败: {error}; 清理旧文件失败: {remove_error}")
                    })?;
                    fs::rename(&tmp, &self.path).map_err(|e| format!("替换 known_hosts 失败: {e}"))
                }
                #[cfg(not(windows))]
                {
                    Err(format!("替换 known_hosts 失败: {error}"))
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn info(fp: &str) -> HostKeyInfo {
        HostKeyInfo {
            algorithm: "ssh-ed25519".into(),
            fingerprint: fp.into(),
        }
    }

    fn store() -> (tempfile::TempDir, KnownHostsStore) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("known_hosts.json");
        let store = KnownHostsStore::load(&path).unwrap();
        (dir, store)
    }

    #[test]
    fn unknown_host_is_unknown() {
        let (_dir, s) = store();
        assert_eq!(
            s.verify("10.0.0.1", 22, &info("SHA256:aaa")),
            TrustState::Unknown
        );
    }

    #[test]
    fn trusted_host_matches_exactly() {
        let (_dir, mut s) = store();
        s.trust("10.0.0.1", 22, &info("SHA256:aaa"), Utc::now())
            .unwrap();
        assert_eq!(
            s.verify("10.0.0.1", 22, &info("SHA256:aaa")),
            TrustState::Trusted
        );
    }

    #[test]
    fn store_uses_only_its_own_path() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("known_hosts.json");
        let mut store = KnownHostsStore::load(&path).unwrap();
        store
            .trust("10.0.0.1", 22, &info("SHA256:aaa"), Utc::now())
            .unwrap();

        // 应用自管文件必须落在给定路径；不能顺手创建/读取系统 ~/.ssh/known_hosts。
        assert!(path.exists());
        assert!(!dir.path().join(".ssh").exists());
        let reloaded = KnownHostsStore::load(&path).unwrap();
        assert_eq!(
            reloaded.verify("10.0.0.1", 22, &info("SHA256:aaa")),
            TrustState::Trusted
        );
    }

    #[test]
    fn changed_fingerprint_is_reported() {
        let (_dir, mut s) = store();
        s.trust("10.0.0.1", 22, &info("SHA256:aaa"), Utc::now())
            .unwrap();
        match s.verify("10.0.0.1", 22, &info("SHA256:bbb")) {
            TrustState::Changed { known } => assert_eq!(known.fingerprint, "SHA256:aaa"),
            other => panic!("expected changed, got {other:?}"),
        }
    }

    #[test]
    fn port_is_part_of_identity() {
        let (_dir, mut s) = store();
        s.trust("10.0.0.1", 22, &info("SHA256:aaa"), Utc::now())
            .unwrap();
        assert_eq!(
            s.verify("10.0.0.1", 2222, &info("SHA256:aaa")),
            TrustState::Unknown
        );
    }

    #[test]
    fn persists_and_reloads() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("known_hosts.json");
        {
            let mut s = KnownHostsStore::load(&path).unwrap();
            s.trust("host", 22, &info("SHA256:aaa"), Utc::now())
                .unwrap();
        }
        let s = KnownHostsStore::load(&path).unwrap();
        assert_eq!(s.entries().len(), 1);
        assert_eq!(
            s.verify("host", 22, &info("SHA256:aaa")),
            TrustState::Trusted
        );
    }

    #[test]
    fn forget_removes_entry() {
        let (_dir, mut s) = store();
        s.trust("host", 22, &info("SHA256:aaa"), Utc::now())
            .unwrap();
        assert!(s.forget("host", 22).unwrap());
        assert!(!s.forget("host", 22).unwrap());
        assert_eq!(
            s.verify("host", 22, &info("SHA256:aaa")),
            TrustState::Unknown
        );
    }

    #[cfg(unix)]
    #[test]
    fn saved_file_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let (dir, mut s) = store();
        s.trust("host", 22, &info("SHA256:aaa"), Utc::now())
            .unwrap();
        let mode = fs::metadata(dir.path().join("known_hosts.json"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);
    }
}
