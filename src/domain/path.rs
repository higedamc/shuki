//! [`VaultPath`] — validated slash-separated entry path (`web/github.com/alice`).

use serde::{Deserialize, Serialize};

use crate::error::{Result, ShukiError};

/// Maximum byte length of a full path.
pub const MAX_PATH_BYTES: usize = 512;

/// A validated vault entry path.
///
/// Invariants (enforced by [`VaultPath::parse`]):
/// - non-empty, at most [`MAX_PATH_BYTES`] bytes
/// - no leading/trailing/double `/`
/// - no `.` or `..` segments (path-traversal guard)
/// - no ASCII control characters
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct VaultPath(String);

impl VaultPath {
    pub fn parse(s: &str) -> Result<Self> {
        if s.is_empty() {
            return Err(ShukiError::InvalidPath("empty path".into()));
        }
        if s.len() > MAX_PATH_BYTES {
            return Err(ShukiError::InvalidPath(format!(
                "path exceeds {MAX_PATH_BYTES} bytes"
            )));
        }
        if s.chars().any(|c| c.is_control()) {
            return Err(ShukiError::InvalidPath("control character in path".into()));
        }
        if s.starts_with('/') || s.ends_with('/') {
            return Err(ShukiError::InvalidPath(format!(
                "leading/trailing '/' not allowed: {s}"
            )));
        }
        for seg in s.split('/') {
            if seg.is_empty() {
                return Err(ShukiError::InvalidPath(format!("empty segment in: {s}")));
            }
            if seg == "." || seg == ".." {
                return Err(ShukiError::InvalidPath(format!(
                    "'.' / '..' segments not allowed: {s}"
                )));
            }
        }
        Ok(Self(s.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn segments(&self) -> impl Iterator<Item = &str> {
        self.0.split('/')
    }

    /// Parent path, or `None` for a top-level entry.
    pub fn parent(&self) -> Option<VaultPath> {
        self.0.rsplit_once('/').map(|(p, _)| Self(p.to_owned()))
    }

    /// Last segment.
    pub fn name(&self) -> &str {
        self.0.rsplit_once('/').map_or(&self.0, |(_, n)| n)
    }

    /// Whether `self` equals `prefix` or lives underneath it.
    pub fn starts_with(&self, prefix: &VaultPath) -> bool {
        self.0 == prefix.0
            || (self.0.len() > prefix.0.len()
                && self.0.starts_with(&prefix.0)
                && self.0.as_bytes()[prefix.0.len()] == b'/')
    }
}

impl std::fmt::Display for VaultPath {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl TryFrom<String> for VaultPath {
    type Error = ShukiError;
    fn try_from(s: String) -> Result<Self> {
        Self::parse(&s)
    }
}

impl From<VaultPath> for String {
    fn from(p: VaultPath) -> String {
        p.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_valid_paths() {
        for p in ["a", "web/github.com/alice", "日本語/サイト", "a-b_c.d/e"] {
            assert_eq!(VaultPath::parse(p).unwrap().as_str(), p);
        }
    }

    #[test]
    fn rejects_invalid_paths() {
        for p in [
            "", "/a", "a/", "a//b", ".", "..", "a/../b", "a/./b", "a\nb", "a\x07b",
        ] {
            assert!(VaultPath::parse(p).is_err(), "should reject: {p:?}");
        }
        assert!(VaultPath::parse(&"x".repeat(MAX_PATH_BYTES + 1)).is_err());
    }

    #[test]
    fn parent_name_segments() {
        let p = VaultPath::parse("a/b/c").unwrap();
        assert_eq!(p.name(), "c");
        assert_eq!(p.parent().unwrap().as_str(), "a/b");
        assert_eq!(p.segments().collect::<Vec<_>>(), ["a", "b", "c"]);
        assert!(VaultPath::parse("top").unwrap().parent().is_none());
    }

    #[test]
    fn starts_with_is_segment_aware() {
        let base = VaultPath::parse("a/b").unwrap();
        assert!(VaultPath::parse("a/b").unwrap().starts_with(&base));
        assert!(VaultPath::parse("a/b/c").unwrap().starts_with(&base));
        assert!(!VaultPath::parse("a/bc").unwrap().starts_with(&base));
    }

    #[test]
    fn serde_roundtrip_and_validation() {
        let p: VaultPath = serde_json::from_str("\"a/b\"").unwrap();
        assert_eq!(p.as_str(), "a/b");
        assert!(serde_json::from_str::<VaultPath>("\"/bad\"").is_err());
        assert_eq!(serde_json::to_string(&p).unwrap(), "\"a/b\"");
    }
}
