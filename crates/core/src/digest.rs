use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::error::{codes, AppError, Result};

/// 规范化 JSON（RFC 8785 / JCS）后取 SHA-256。
///
/// 约束（文档 §6.3）：
/// - 只在核心层计算，前端只显示前 8 位；
/// - 调用方负责「哪些字段进入摘要」——这里不做字段级裁剪；
/// - 键排序、数字规范化、UTF-8 由 serde_jcs 保证。
pub fn canonical_bytes<T: Serialize + ?Sized>(value: &T) -> Result<Vec<u8>> {
    serde_jcs::to_vec(value)
        .map_err(|e| AppError::new(codes::DIGEST_FAILED, format!("canonical JSON 失败: {e}")))
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("{:x}", hasher.finalize())
}

/// 返回 `sha256:<hex>` 形式的完整摘要。
pub fn digest_of<T: Serialize + ?Sized>(value: &T) -> Result<String> {
    let bytes = canonical_bytes(value)?;
    Ok(format!("sha256:{}", sha256_hex(&bytes)))
}

/// 链式哈希：`H(previous_hash || canonical(event))`。
pub fn chain_hash(previous_hash: &str, value: &impl Serialize) -> Result<String> {
    let body = canonical_bytes(value)?;
    let mut buf = Vec::with_capacity(previous_hash.len() + 1 + body.len());
    buf.extend_from_slice(previous_hash.as_bytes());
    buf.push(b'\n');
    buf.extend_from_slice(&body);
    Ok(format!("sha256:{}", sha256_hex(&buf)))
}

/// 链起点标记（不是摘要，避免与真实 hash 混淆）。
pub const GENESIS: &str = "genesis";

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn key_order_does_not_change_digest() {
        let a = json!({ "b": 2, "a": 1 });
        let b = json!({ "a": 1, "b": 2 });
        assert_eq!(digest_of(&a).unwrap(), digest_of(&b).unwrap());
    }

    #[test]
    fn odd_whitespace_does_not_change_digest() {
        // 同一个值经由不同序列化路径产生，摘要必须一致
        let a: serde_json::Value =
            serde_json::from_str(r#"{ "x": [1, 2, {"y": "中文"}] }"#).unwrap();
        let b: serde_json::Value = serde_json::from_str(r#"{"x":[1,2,{"y":"中文"}]}"#).unwrap();
        assert_eq!(digest_of(&a).unwrap(), digest_of(&b).unwrap());
    }

    #[test]
    fn value_change_changes_digest() {
        let a = json!({ "cwd": "/srv" });
        let b = json!({ "cwd": "/tmp" });
        assert_ne!(digest_of(&a).unwrap(), digest_of(&b).unwrap());
    }

    #[test]
    fn null_and_missing_differ() {
        let with_null = json!({ "a": null });
        let empty = json!({});
        assert_ne!(digest_of(&with_null).unwrap(), digest_of(&empty).unwrap());
    }

    #[test]
    fn digest_is_prefixed_sha256() {
        let d = digest_of(&json!({"a":1})).unwrap();
        assert!(d.starts_with("sha256:"));
        assert_eq!(d.len(), "sha256:".len() + 64);
    }

    #[test]
    fn canonical_vectors() {
        // 输入 → RFC 8785 规范化后的期望字节（键排序、无空白、字符串按最小转义）。
        let cases: &[(&str, &str)] = &[
            (r#"{"b":1,"a":2}"#, r#"{"a":2,"b":1}"#),
            (r#"{"a":{"d":4,"c":3}}"#, r#"{"a":{"c":3,"d":4}}"#),
            (r#"[3,1,2]"#, r#"[3,1,2]"#),
            (r#"{"s":"中"}"#, r#"{"s":"中"}"#),
            (r#"{"b":true,"a":null}"#, r#"{"a":null,"b":true}"#),
            (r#"null"#, r#"null"#),
            (r#"{}"#, r#"{}"#),
            (r#"[]"#, r#"[]"#),
            (r#"{"":1}"#, r#"{"":1}"#),
            (r#"{"a":[[],{}]}"#, r#"{"a":[[],{}]}"#),
            (r#"{"z":[{"b":2,"a":1}]}"#, r#"{"z":[{"a":1,"b":2}]}"#),
            (r#"{"a":"x\"y"}"#, r#"{"a":"x\"y"}"#),
            (r#"{"a":"line\nnext"}"#, r#"{"a":"line\nnext"}"#),
            (r#"{"u":"\u4e2d"}"#, r#"{"u":"中"}"#),
            (r#"{"b":"a\\b"}"#, r#"{"b":"a\\b"}"#),
            (r#"{"n":-12.0}"#, r#"{"n":-12}"#),
            // 第 17–20 条：Unicode 转义、指数、斜杠、控制字符。
            (r#"{"a":"\u00e9"}"#, r#"{"a":"é"}"#),
            (r#"{"n":1e2}"#, r#"{"n":100}"#),
            (r#"{"a":"/"}"#, r#"{"a":"/"}"#),
            (r#"{"a":"\u0001"}"#, r#"{"a":"\u0001"}"#),
        ];

        for (input, expected) in cases {
            let value: serde_json::Value = serde_json::from_str(input).unwrap();
            let bytes = canonical_bytes(&value).unwrap();
            assert_eq!(
                std::str::from_utf8(&bytes).unwrap(),
                *expected,
                "input: {input}"
            );
        }
    }

    #[test]
    fn chain_hash_depends_on_previous() {
        let h1 = chain_hash(GENESIS, &json!({"e":1})).unwrap();
        let h2 = chain_hash(GENESIS, &json!({"e":1})).unwrap();
        let h3 = chain_hash(&h1, &json!({"e":1})).unwrap();
        assert_eq!(h1, h2);
        assert_ne!(h1, h3);
    }
}
