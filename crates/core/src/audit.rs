use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::digest::{chain_hash, GENESIS};
use crate::error::{codes, AppError, Result};
use crate::ids::new_id;

/// 审计事实（文档 §14.2）。只由执行器与状态机产生，模型不能写入。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AuditEvent {
    pub seq: u64,
    pub event_id: String,
    pub event_type: String,
    pub timestamp: DateTime<Utc>,
    pub chain_segment: u32,
    pub actor: String,
    pub payload: Value,
    pub previous_hash: String,
    pub event_hash: String,
}

#[derive(Serialize)]
struct EventBody<'a> {
    seq: u64,
    event_id: &'a str,
    event_type: &'a str,
    timestamp: &'a DateTime<Utc>,
    chain_segment: u32,
    actor: &'a str,
    payload: &'a Value,
    previous_hash: &'a str,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Checkpoint {
    pub segment: u32,
    pub range_start: u64,
    pub range_end: u64,
    pub hash: String,
    pub at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct IntegrityReport {
    pub valid: bool,
    pub checked: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub broken_at: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// 进程内审计链。生产环境由 store 持久化，这里保证哈希语义可单测。
#[derive(Debug)]
pub struct AuditChain {
    events: Vec<AuditEvent>,
    segment_size: usize,
    next_seq: u64,
}

impl AuditChain {
    pub fn new(segment_size: usize) -> Self {
        assert!(segment_size > 0, "segment_size 必须大于 0");
        Self {
            events: Vec::new(),
            segment_size,
            next_seq: 1,
        }
    }

    pub fn with_defaults() -> Self {
        Self::new(1000)
    }

    pub fn events(&self) -> &[AuditEvent] {
        &self.events
    }

    /// 从已持久化的事件重建链（重启后继续追加，seq 不重置）。
    /// 调用方应先 `verify()`，避免在已损坏的链上继续写。
    pub fn from_events(events: Vec<AuditEvent>, segment_size: usize) -> Self {
        assert!(segment_size > 0, "segment_size 必须大于 0");
        let next_seq = events.last().map(|e| e.seq + 1).unwrap_or(1);
        Self {
            events,
            segment_size,
            next_seq,
        }
    }

    pub fn append(
        &mut self,
        event_type: &str,
        actor: &str,
        payload: Value,
        now: DateTime<Utc>,
    ) -> Result<&AuditEvent> {
        if event_type.trim().is_empty() {
            return Err(AppError::new(codes::AUDIT_INTEGRITY, "event_type 不能为空"));
        }
        let seq = self.next_seq;
        let segment = ((seq - 1) / self.segment_size as u64) as u32;
        let previous_hash = match self.events.last() {
            Some(last) if last.chain_segment == segment => last.event_hash.clone(),
            _ => GENESIS.to_string(),
        };
        let event_id = new_id("evt");

        let body = EventBody {
            seq,
            event_id: &event_id,
            event_type,
            timestamp: &now,
            chain_segment: segment,
            actor,
            payload: &payload,
            previous_hash: &previous_hash,
        };
        let event_hash = chain_hash(&previous_hash, &body)?;

        self.events.push(AuditEvent {
            seq,
            event_id,
            event_type: event_type.to_string(),
            timestamp: now,
            chain_segment: segment,
            actor: actor.to_string(),
            payload,
            previous_hash,
            event_hash,
        });
        self.next_seq += 1;
        Ok(self.events.last().expect("just pushed"))
    }

    /// 校验整条链；返回首个断点，便于 UI 定位。
    pub fn verify(&self) -> IntegrityReport {
        let mut expected_prev = GENESIS.to_string();
        let mut current_segment = 0u32;

        for event in &self.events {
            if event.chain_segment != current_segment {
                current_segment = event.chain_segment;
                expected_prev = GENESIS.to_string();
            }
            if event.previous_hash != expected_prev {
                return IntegrityReport {
                    valid: false,
                    checked: self.events.len(),
                    broken_at: Some(event.seq),
                    reason: Some("previous_hash 与上一条不一致（记录被删改或乱序）".into()),
                };
            }
            let body = EventBody {
                seq: event.seq,
                event_id: &event.event_id,
                event_type: &event.event_type,
                timestamp: &event.timestamp,
                chain_segment: event.chain_segment,
                actor: &event.actor,
                payload: &event.payload,
                previous_hash: &event.previous_hash,
            };
            match chain_hash(&event.previous_hash, &body) {
                Ok(hash) if hash == event.event_hash => {
                    expected_prev = event.event_hash.clone();
                }
                _ => {
                    return IntegrityReport {
                        valid: false,
                        checked: self.events.len(),
                        broken_at: Some(event.seq),
                        reason: Some("event_hash 与内容不一致（内容被修改）".into()),
                    };
                }
            }
        }

        IntegrityReport {
            valid: true,
            checked: self.events.len(),
            broken_at: None,
            reason: None,
        }
    }

    /// 回滚最后一条事件（用于「链已追加、持久化失败」时保持一致）。
    pub fn rollback_last(&mut self) -> Option<AuditEvent> {
        let event = self.events.pop()?;
        self.next_seq = event.seq;
        Some(event)
    }

    pub fn checkpoint(&self, now: DateTime<Utc>) -> Option<Checkpoint> {
        let last = self.events.last()?;
        let segment = last.chain_segment;
        let first_seq = self
            .events
            .iter()
            .find(|e| e.chain_segment == segment)
            .map(|e| e.seq)?;
        Some(Checkpoint {
            segment,
            range_start: first_seq,
            range_end: last.seq,
            hash: last.event_hash.clone(),
            at: now,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn chain() -> AuditChain {
        AuditChain::new(3)
    }

    #[test]
    fn appends_and_verifies() {
        let mut c = chain();
        c.append(
            "check.created",
            "state-machine",
            json!({"task":"t1"}),
            Utc::now(),
        )
        .unwrap();
        c.append("check.validated", "validator", json!({"v":1}), Utc::now())
            .unwrap();
        assert!(c.verify().valid);
        assert_eq!(c.events().len(), 2);
        assert_eq!(c.events()[0].seq, 1);
    }

    #[test]
    fn tampering_payload_is_detected() {
        let mut c = chain();
        c.append("exec.step", "executor", json!({"cmd":"uptime"}), Utc::now())
            .unwrap();
        c.events[0].payload = json!({"cmd":"rm -rf /"});
        let report = c.verify();
        assert!(!report.valid);
        assert_eq!(report.broken_at, Some(1));
    }

    #[test]
    fn segment_boundary_restarts_chain() {
        let mut c = chain();
        for i in 0..3 {
            c.append("tick", "test", json!({"i":i}), Utc::now())
                .unwrap();
        }
        c.append("tick", "test", json!({"i":3}), Utc::now())
            .unwrap();
        assert_eq!(c.events()[2].chain_segment, 0);
        assert_eq!(c.events()[3].chain_segment, 1);
        assert_eq!(c.events()[3].previous_hash, GENESIS);
        assert!(c.verify().valid);
    }

    #[test]
    fn deleting_an_event_breaks_the_chain() {
        let mut c = chain();
        for i in 0..3 {
            c.append("tick", "test", json!({"i":i}), Utc::now())
                .unwrap();
        }
        c.events.remove(1);
        let report = c.verify();
        assert!(!report.valid);
    }

    #[test]
    fn rebuild_continues_sequence() {
        let mut c = chain();
        c.append("a", "t", json!({}), Utc::now()).unwrap();
        c.append("b", "t", json!({}), Utc::now()).unwrap();
        let events = c.events().to_vec();
        let mut rebuilt = AuditChain::from_events(events, 3);
        assert!(rebuilt.verify().valid);
        let next = rebuilt.append("c", "t", json!({}), Utc::now()).unwrap();
        assert_eq!(next.seq, 3);
    }

    #[test]
    fn rollback_restores_sequence() {
        let mut c = chain();
        c.append("a", "t", json!({}), Utc::now()).unwrap();
        c.append("b", "t", json!({}), Utc::now()).unwrap();
        let removed = c.rollback_last().unwrap();
        assert_eq!(removed.seq, 2);
        let next = c.append("c", "t", json!({}), Utc::now()).unwrap();
        assert_eq!(next.seq, 2);
        assert!(c.verify().valid);
    }

    #[test]
    fn checkpoint_covers_current_segment() {
        let mut c = AuditChain::new(2);
        c.append("a", "t", json!({}), Utc::now()).unwrap();
        c.append("b", "t", json!({}), Utc::now()).unwrap();
        c.append("c", "t", json!({}), Utc::now()).unwrap();
        let cp = c.checkpoint(Utc::now()).unwrap();
        assert_eq!(cp.segment, 1);
        assert_eq!(cp.range_start, 3);
        assert_eq!(cp.range_end, 3);
    }
}
