//! 端到端：用进程内 russh 服务端验证「探测指纹 → 信任 → 密码认证 → PTY 双向数据」。
//!
//! 这条测试是 M1 的验收核心：它不依赖外部 sshd，也不发送任何真实凭证。

use std::sync::{Arc, Mutex};
use std::time::Duration;

use russh::keys::{Algorithm, PrivateKey};
use russh::server::{Auth, ChannelOpenHandle, Msg, Server as _, Session};
use russh::ChannelId;
use tokio::net::TcpListener;

use shellwarden_ssh::{
    AuthMethod, ConnectConfig, HostKeyInfo, KnownHostsStore, OutputSink, PtySize, RusshBackend,
    SshBackend, TrustState,
};

struct TestServer;

struct TestHandler;

impl russh::server::Server for TestServer {
    type Handler = TestHandler;

    fn new_client(&mut self, _addr: Option<std::net::SocketAddr>) -> TestHandler {
        TestHandler
    }
}

impl russh::server::Handler for TestHandler {
    type Error = russh::Error;

    async fn auth_password(&mut self, _user: &str, password: &str) -> Result<Auth, Self::Error> {
        Ok(if password == "secret" {
            Auth::Accept
        } else {
            Auth::reject()
        })
    }

    async fn channel_open_session(
        &mut self,
        _channel: russh::Channel<Msg>,
        reply: ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        reply.accept().await;
        Ok(())
    }

    async fn data(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        // 回声：足以证明 PTY 通道双向可用。
        session.data(channel, data.to_vec())?;
        Ok(())
    }
}

async fn spawn_server() -> u16 {
    let config = Arc::new(russh::server::Config {
        inactivity_timeout: Some(Duration::from_secs(30)),
        auth_rejection_time: Duration::from_millis(10),
        auth_rejection_time_initial: Some(Duration::ZERO),
        keys: vec![PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).unwrap()],
        ..Default::default()
    });

    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let port = listener.local_addr().unwrap().port();

    tokio::spawn(async move {
        let mut server = TestServer;
        let future = server.run_on_socket(config, &listener);
        let _ = future.await;
    });

    port
}

#[derive(Default)]
struct RecordingSink {
    data: Mutex<Vec<u8>>,
    closed: Mutex<bool>,
}

impl OutputSink for RecordingSink {
    fn on_data(&self, _session_id: &str, data: &[u8]) {
        self.data.lock().unwrap().extend_from_slice(data);
    }
    fn on_closed(&self, _session_id: &str, _exit_code: Option<u32>) {
        *self.closed.lock().unwrap() = true;
    }
    fn on_error(&self, _session_id: &str, _message: &str) {}
}

#[tokio::test]
async fn probe_trust_authenticate_and_echo_over_pty() {
    let port = spawn_server().await;
    let backend = RusshBackend::new();

    // 1. 探测：不应发送任何凭证
    let mut probe_cfg = ConnectConfig::new("127.0.0.1", port, "tester");
    probe_cfg.auth = AuthMethod::Password("wrong".into());
    probe_cfg.timeout = Duration::from_secs(5);
    let observed = backend.probe_host_key(&probe_cfg).await.unwrap();
    assert_eq!(observed.algorithm, "ssh-ed25519");
    assert!(observed.fingerprint.starts_with("SHA256:"));

    // 2. 信任（应用自管 known_hosts）
    let dir = tempfile::tempdir().unwrap();
    let mut store = KnownHostsStore::load(dir.path().join("known_hosts.json")).unwrap();
    assert_eq!(
        store.verify("127.0.0.1", port, &observed),
        TrustState::Unknown
    );
    store
        .trust("127.0.0.1", port, &observed, chrono::Utc::now())
        .unwrap();
    assert_eq!(
        store.verify("127.0.0.1", port, &observed),
        TrustState::Trusted
    );

    // 3. 未提供期望指纹时拒绝建立会话
    let mut bad_cfg = ConnectConfig::new("127.0.0.1", port, "tester");
    bad_cfg.auth = AuthMethod::Password("secret".into());
    bad_cfg.timeout = Duration::from_secs(5);
    let sink: shellwarden_ssh::SharedSink = Arc::new(RecordingSink::default());
    let err = backend
        .open_pty(&bad_cfg, PtySize::default(), sink.clone())
        .await
        .unwrap_err();
    assert_eq!(err.code, "ssh.host_key.unknown");

    // 4. 错误的密码 → 认证失败
    let mut wrong_cfg = ConnectConfig::new("127.0.0.1", port, "tester");
    wrong_cfg.auth = AuthMethod::Password("nope".into());
    wrong_cfg.expected_host_key = Some(observed.clone());
    wrong_cfg.timeout = Duration::from_secs(5);
    let err = backend
        .open_pty(&wrong_cfg, PtySize::default(), sink.clone())
        .await
        .unwrap_err();
    assert_eq!(err.code, "ssh.auth.failed");

    // 5. 正确密码 + 期望指纹 → PTY 可用
    let mut cfg = ConnectConfig::new("127.0.0.1", port, "tester");
    cfg.auth = AuthMethod::Password("secret".into());
    cfg.expected_host_key = Some(observed);
    cfg.timeout = Duration::from_secs(5);

    let recording = Arc::new(RecordingSink::default());
    let session = backend
        .open_pty(
            &cfg,
            PtySize {
                cols: 100,
                rows: 30,
            },
            recording.clone(),
        )
        .await
        .unwrap();
    // 模拟 UI 挂载：attach 后输出才会实时推给 sink；attach 前的输出从 backlog 取。
    let _ = session.attach();
    session.resize(120, 40).await.unwrap();
    session.write(b"echo hello\n".to_vec()).await.unwrap();

    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        if String::from_utf8_lossy(&recording.data.lock().unwrap()).contains("echo hello") {
            break;
        }
        if tokio::time::Instant::now() > deadline {
            panic!(
                "did not receive echoed data, got {:?}",
                recording.data.lock().unwrap()
            );
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    session.close().await.unwrap();
    let _ = tokio::time::timeout(Duration::from_secs(2), async {
        while !*recording.closed.lock().unwrap() {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await;
}

#[tokio::test]
async fn changed_host_key_is_rejected_before_auth() {
    let port = spawn_server().await;
    let backend = RusshBackend::new();

    let mut probe_cfg = ConnectConfig::new("127.0.0.1", port, "tester");
    probe_cfg.timeout = Duration::from_secs(5);
    backend.probe_host_key(&probe_cfg).await.unwrap();

    let mut cfg = ConnectConfig::new("127.0.0.1", port, "tester");
    cfg.auth = AuthMethod::Password("secret".into());
    cfg.expected_host_key = Some(HostKeyInfo {
        algorithm: "ssh-ed25519".into(),
        fingerprint: "SHA256:definitely-not-the-server-key".into(),
    });
    cfg.timeout = Duration::from_secs(5);

    let sink: shellwarden_ssh::SharedSink = Arc::new(RecordingSink::default());
    let err = backend
        .open_pty(&cfg, PtySize::default(), sink)
        .await
        .unwrap_err();
    assert_eq!(err.code, "ssh.host_key.changed");
}
