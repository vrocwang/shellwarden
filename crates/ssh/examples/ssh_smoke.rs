//! 真实 SSH 冒烟测试（不参与发布）：
//!
//! ```bash
//! cargo run -p shellwarden-ssh --example ssh_smoke -- 127.0.0.1 2222 "$USER" /tmp/sw-sshd/clientkey
//! ```
//!
//! 流程：探测指纹 → 写入临时 known_hosts → 私钥认证 → PTY 执行 `echo` → exec 执行一次。

use std::sync::{Arc, Mutex};
use std::time::Duration;

use shellwarden_ssh::{
    AuthMethod, ConnectConfig, KnownHostsStore, OutputSink, PtySize, RusshBackend, SharedSink,
    SshBackend,
};

#[derive(Default)]
struct Printer {
    buffer: Mutex<Vec<u8>>,
}

impl OutputSink for Printer {
    fn on_data(&self, _id: &str, data: &[u8]) {
        self.buffer.lock().unwrap().extend_from_slice(data);
        print!("{}", String::from_utf8_lossy(data));
    }
    fn on_closed(&self, _id: &str, code: Option<u32>) {
        println!("\n[closed] exit={code:?}");
    }
    fn on_error(&self, _id: &str, message: &str) {
        eprintln!("\n[error] {message}");
    }
}

#[tokio::main]
async fn main() {
    let mut args = std::env::args().skip(1);
    let host = args.next().unwrap_or_else(|| "127.0.0.1".into());
    let port: u16 = args.next().and_then(|p| p.parse().ok()).unwrap_or(22);
    let user = args.next().unwrap_or_else(|| "root".into());
    let key = args
        .next()
        .expect("usage: ssh_smoke <host> <port> <user> <key_path>");

    let backend = RusshBackend::new();
    let mut config = ConnectConfig::new(host.clone(), port, user);
    config.timeout = Duration::from_secs(10);
    config.auth = AuthMethod::Agent;

    println!("== probe {host}:{port}");
    let observed = backend.probe_host_key(&config).await.expect("probe failed");
    println!(
        "fingerprint: {} {}",
        observed.algorithm, observed.fingerprint
    );

    let dir = std::env::temp_dir().join(format!("sw-smoke-{}", std::process::id()));
    let mut store = KnownHostsStore::load(dir.join("known_hosts.json")).expect("store");
    store
        .trust(&host, port, &observed, chrono::Utc::now())
        .expect("trust");
    assert_eq!(
        store.verify(&host, port, &observed),
        shellwarden_ssh::TrustState::Trusted
    );

    config.expected_host_key = Some(observed);
    config.auth = AuthMethod::PrivateKey {
        path: key.into(),
        passphrase: None,
    };

    println!("== open pty");
    let printer = Arc::new(Printer::default());
    let sink: SharedSink = printer.clone();
    let session = backend
        .open_pty(
            &config,
            PtySize {
                cols: 100,
                rows: 30,
            },
            sink,
        )
        .await
        .expect("open_pty failed");
    println!("session: {}", session.id);
    session
        .write(b"echo SMOKE_PTY_OK; exit\n".to_vec())
        .await
        .unwrap();

    let deadline = tokio::time::Instant::now() + Duration::from_secs(8);
    loop {
        if String::from_utf8_lossy(&printer.buffer.lock().unwrap()).contains("SMOKE_PTY_OK") {
            break;
        }
        if tokio::time::Instant::now() > deadline {
            panic!("PTY 未在 8s 内返回预期输出");
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    session.close().await.ok();

    println!("== exec");
    let result = backend
        .exec(
            &config,
            "echo SMOKE_EXEC_OK",
            1024 * 1024,
            Duration::from_secs(20),
        )
        .await
        .expect("exec failed");
    println!(
        "exit={:?} stdout={}",
        result.exit_code,
        String::from_utf8_lossy(&result.stdout).trim()
    );
    assert_eq!(result.exit_code, Some(0));

    println!("SMOKE: OK");
}
