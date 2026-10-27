//! 审计链持久化往返：哈希覆盖的时间戳必须在落库/读回后保持完全一致。
//!
//! 历史缺陷：哈希用纳秒、落库截到毫秒，重启后 `verify()` 必失败（v2 审查 P0-1）。

use chrono::Utc;
use shellwarden_core::audit::AuditChain;
use shellwarden_store::Db;

#[test]
fn audit_chain_survives_database_roundtrip() {
    let db = Db::open_in_memory().unwrap();
    let mut chain = AuditChain::new(1000);
    for index in 0..3 {
        let event = chain
            .append(
                "roundtrip.event",
                "test",
                serde_json::json!({ "index": index }),
                Utc::now(),
            )
            .unwrap()
            .clone();
        db.insert_audit_event(&event).unwrap();
    }

    let loaded = db.audit_events_all().unwrap();
    assert_eq!(loaded.len(), 3);
    let rebuilt = AuditChain::from_events(loaded, 1000);
    let report = rebuilt.verify();
    assert!(report.valid, "reloaded audit chain must verify: {report:?}");
}

#[test]
fn audit_chain_still_detects_tampering_after_reload() {
    let db = Db::open_in_memory().unwrap();
    let mut chain = AuditChain::new(1000);
    let event = chain
        .append(
            "tamper.event",
            "test",
            serde_json::json!({ "value": 1 }),
            Utc::now(),
        )
        .unwrap()
        .clone();
    db.insert_audit_event(&event).unwrap();

    let mut loaded = db.audit_events_all().unwrap();
    loaded[0].payload = serde_json::json!({ "value": 999 });
    let rebuilt = AuditChain::from_events(loaded, 1000);
    assert!(!rebuilt.verify().valid);
}
