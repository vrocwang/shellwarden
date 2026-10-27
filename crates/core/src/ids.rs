use uuid::Uuid;

/// 生成带语义前缀的 ID，例如 `host_0192f...`。
/// 使用 UUID v7：时间有序，便于审计与索引局部性。
pub fn new_id(prefix: &str) -> String {
    format!("{prefix}_{}", Uuid::now_v7().simple())
}

/// 审批卡只展示摘要前 8 位；校验永远使用完整摘要。
pub fn short_digest(digest: &str) -> String {
    let raw = digest.strip_prefix("sha256:").unwrap_or(digest);
    raw.chars().take(8).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids_have_prefix_and_are_unique() {
        let a = new_id("host");
        let b = new_id("host");
        assert!(a.starts_with("host_"));
        assert_ne!(a, b);
        assert!(a.len() > 20);
    }

    #[test]
    fn short_digest_strips_prefix() {
        let d = "sha256:0123456789abcdef";
        assert_eq!(short_digest(d), "01234567");
        assert_eq!(short_digest("abcdef0123456789"), "abcdef01");
    }
}
