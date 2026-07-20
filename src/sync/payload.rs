//! The frozen wire schema — plaintext JSON that gets NIP-44 encrypted into
//! kind-30078 event content. Changing this requires a schema-version bump
//! and a contract PR.

use serde::{Deserialize, Serialize};

use crate::domain::{Entry, EntryFields, VaultPath};
use crate::error::{Result, ShukiError};

/// Restore-time filter magic: payloads whose `app` differs are not ours.
pub const APP_MAGIC: &str = "shuki";
pub const SCHEMA_VERSION: u32 = 1;
/// NIP-78 application-specific data.
pub const ENTRY_KIND: u16 = 30078;
/// NIP-44 caps plaintext at 65535 bytes; we stop well before it.
pub const MAX_PLAINTEXT_BYTES: usize = 60_000;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SyncPayload {
    pub app: String,
    pub v: u32,
    pub path: VaultPath,
    #[serde(default)]
    pub fields: EntryFields,
    /// Unix seconds — the LWW authority (NOT the event `created_at`).
    pub updated_at: u64,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub deleted: bool,
}

impl SyncPayload {
    pub fn from_entry(e: &Entry) -> Self {
        Self {
            app: APP_MAGIC.to_owned(),
            v: SCHEMA_VERSION,
            path: e.path.clone(),
            fields: e.fields.clone(),
            updated_at: e.updated_at,
            deleted: false,
        }
    }

    pub fn tombstone(path: VaultPath, updated_at: u64) -> Self {
        Self {
            app: APP_MAGIC.to_owned(),
            v: SCHEMA_VERSION,
            path,
            fields: EntryFields::default(),
            updated_at,
            deleted: true,
        }
    }

    /// Serialize for encryption. Errors if the plaintext would exceed
    /// [`MAX_PLAINTEXT_BYTES`] (NIP-44 hard limit safety margin).
    pub fn encode(&self) -> Result<Vec<u8>> {
        let bytes =
            serde_json::to_vec(self).map_err(|e| ShukiError::Crypto(format!("encode: {e}")))?;
        if bytes.len() > MAX_PLAINTEXT_BYTES {
            return Err(ShukiError::Crypto(format!(
                "entry too large: {} bytes (max {MAX_PLAINTEXT_BYTES})",
                bytes.len()
            )));
        }
        Ok(bytes)
    }

    /// Parse decrypted bytes. Rejects foreign apps and newer schemas.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let p: SyncPayload = serde_json::from_slice(bytes)
            .map_err(|e| ShukiError::Corrupt(format!("payload parse: {e}")))?;
        if p.app != APP_MAGIC {
            return Err(ShukiError::Corrupt(format!(
                "foreign app payload: {}",
                p.app
            )));
        }
        if p.v > SCHEMA_VERSION {
            return Err(ShukiError::Corrupt(format!(
                "payload schema v{} newer than supported v{SCHEMA_VERSION}",
                p.v
            )));
        }
        Ok(p)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::SecretField;

    fn sample_entry() -> Entry {
        Entry {
            path: VaultPath::parse("web/example.com").unwrap(),
            fields: EntryFields {
                password: Some(SecretField::from("s3cret")),
                username: Some("alice".into()),
                ..Default::default()
            },
            updated_at: 1_700_000_000,
        }
    }

    #[test]
    fn roundtrip_entry() {
        let p = SyncPayload::from_entry(&sample_entry());
        let back = SyncPayload::decode(&p.encode().unwrap()).unwrap();
        assert_eq!(back.path.as_str(), "web/example.com");
        assert_eq!(back.fields.password, Some(SecretField::from("s3cret")));
        assert!(!back.deleted);
        assert_eq!(back.updated_at, 1_700_000_000);
    }

    #[test]
    fn tombstone_roundtrip_and_compactness() {
        let p = SyncPayload::tombstone(VaultPath::parse("a/b").unwrap(), 42);
        let json = String::from_utf8(p.encode().unwrap()).unwrap();
        assert!(json.contains("\"deleted\":true"));
        let back = SyncPayload::decode(json.as_bytes()).unwrap();
        assert!(back.deleted);
        // `deleted:false` is omitted on live entries.
        let live = SyncPayload::from_entry(&sample_entry());
        assert!(!String::from_utf8(live.encode().unwrap())
            .unwrap()
            .contains("deleted"));
    }

    #[test]
    fn rejects_foreign_and_future() {
        let mut p = SyncPayload::from_entry(&sample_entry());
        p.app = "other".into();
        let bytes = serde_json::to_vec(&p).unwrap();
        assert!(SyncPayload::decode(&bytes).is_err());

        let mut p2 = SyncPayload::from_entry(&sample_entry());
        p2.v = SCHEMA_VERSION + 1;
        let bytes2 = serde_json::to_vec(&p2).unwrap();
        assert!(SyncPayload::decode(&bytes2).is_err());
    }

    #[test]
    fn rejects_oversize() {
        let mut e = sample_entry();
        e.fields.notes = Some(SecretField::new("x".repeat(MAX_PLAINTEXT_BYTES)));
        assert!(SyncPayload::from_entry(&e).encode().is_err());
    }

    #[test]
    fn rejects_garbage() {
        assert!(SyncPayload::decode(b"not json").is_err());
        assert!(SyncPayload::decode(b"{}").is_err());
    }
}
