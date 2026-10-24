//! Shared fixtures for the `axiam-pki` integration tests.

/// The AES-256-GCM key a test deployment wraps CA keys with: random per
/// process, stable within one, so no key-shaped literal appears in the source.
pub fn test_key() -> [u8; 32] {
    static KEY: std::sync::OnceLock<[u8; 32]> = std::sync::OnceLock::new();
    *KEY.get_or_init(|| {
        let mut key = [0u8; 32];
        key[..16].copy_from_slice(uuid::Uuid::new_v4().as_bytes());
        key[16..].copy_from_slice(uuid::Uuid::new_v4().as_bytes());
        key
    })
}
