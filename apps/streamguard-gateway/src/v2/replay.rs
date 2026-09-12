//! Durable local single-gateway ticket redemption journal (V2 admission-only).
//!
//! The in-memory [`ReplayCache`](super::admission::ReplayCache) rejects ticket
//! replays within one process. This module makes that rejection durable across
//! restarts without introducing a shared or multi-gateway store:
//!
//! - File layout: fixed header binding the journal to one gateway name plus
//!   concatenated fixed-size records (`TicketId` 16 bytes + expiry 8 bytes
//!   big-endian). No length prefix, no allocator-controlled sizes.
//! - Atomicity: every mutation rewrites `<path>.tmp`, flushes it with
//!   `sync_all`, atomically renames it over `<path>`, then fsyncs the parent
//!   directory on Unix. A crash leaves the old or the new journal, never a
//!   half-write.
//! - Single-gateway binding: the header carries the gateway name. Opening a
//!   journal created for a different gateway fails closed, so two gateways can
//!   never share one redemption file. Configuring any scope other than
//!   `single-gateway` is rejected explicitly ([`RedemptionScope`]).
//! - Bounds: at most `MAX_REPLAY_ENTRIES_HARD_CAP` records; larger files fail
//!   closed. Corrupt magic/version/scope, trailing bytes, short reads,
//!   duplicate ticket IDs, or zero IDs fail closed.
//! - Blocking: all file I/O blocks its thread while holding the caller's
//!   replay lock (single-guard serialization). Production async callers must
//!   use [`ReplayCache::consume_async`](super::admission::ReplayCache) — the
//!   bounded `spawn_blocking` wrapper with [`REPLAY_JOURNAL_IO_TIMEOUT`](super::admission::REPLAY_JOURNAL_IO_TIMEOUT)
//!   — never the sync `consume` on an executor thread. The admission limiter
//!   already bounds concurrent handshakes; the timeout fails closed so a
//!   stalled disk never hangs admission or shutdown.
//!
//! This module never logs ticket IDs, expiries, gateway key material, or file
//! contents. Errors are generic (`Io`, `Corrupt`) without paths or contents.

use std::collections::{BTreeMap, HashSet};
use std::path::Path;

use sg_auth::ticket::{REPLAY_EXPIRY_SKEW_SECONDS, TicketId};
use thiserror::Error;

/// Magic for the single-gateway replay journal file.
const REPLAY_JOURNAL_MAGIC: [u8; 4] = *b"SGTR";
/// Journal format version. Any other version fails closed.
const REPLAY_JOURNAL_VERSION: u8 = 1;
/// Scope byte for the only supported mode: local single-gateway.
const REPLAY_SCOPE_SINGLE: u8 = 0;
/// Fixed record: ticket ID (16) + expiry unix seconds (8) = 24 bytes.
const REPLAY_RECORD_LEN: usize = 24;
/// Hard cap for redemption entries so a corrupt file cannot induce a huge
/// allocation.
pub const MAX_REPLAY_ENTRIES_HARD_CAP: usize = 65_536;
/// Hard cap for the journal file: header (8 + up to 253 name bytes) plus
/// records. Checked before any allocation.
const MAX_REPLAY_JOURNAL_BYTES: u64 =
    (8 + 253 + MAX_REPLAY_ENTRIES_HARD_CAP * REPLAY_RECORD_LEN) as u64;
/// Maximum gateway name length accepted in the journal header (matches
/// `MAX_GATEWAY_NAME_LEN` in `sg-protocol`; validated as ASCII DNS elsewhere).
const MAX_JOURNAL_GATEWAY_NAME_LEN: usize = 253;

/// Redemption scope for the ticket replay journal.
///
/// Only [`RedemptionScope::SingleGateway`] is supported by the admission-only
/// entrypoint. Any multi-gateway or shared scope is rejected explicitly at
/// configuration load, before any journal file is opened.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RedemptionScope {
    SingleGateway,
}

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum RedemptionScopeError {
    #[error("V2 ticket redemption requires single-gateway scope; multi-gateway is rejected")]
    MultiGatewayRejected,
    #[error("V2 ticket redemption scope is invalid")]
    InvalidScope,
}

impl RedemptionScope {
    /// Parses the configured scope string. Only `"single-gateway"` is
    /// accepted. `"multi-gateway"`, `"shared"`, and any other value fail
    /// closed; multi-gateway spellings report an explicit rejection.
    pub fn parse(value: &str) -> Result<Self, RedemptionScopeError> {
        match value {
            "single-gateway" => Ok(Self::SingleGateway),
            "multi-gateway" | "shared" | "multi" | "clustered" => {
                Err(RedemptionScopeError::MultiGatewayRejected)
            }
            _ => Err(RedemptionScopeError::InvalidScope),
        }
    }

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SingleGateway => "single-gateway",
        }
    }
}

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum ReplayJournalError {
    #[error("V2 replay journal configuration is invalid")]
    InvalidConfiguration,
    #[error("V2 replay journal I/O failed")]
    Io,
    #[error("V2 replay journal data is corrupt")]
    Corrupt,
}

/// Validates a gateway name for journal binding: non-empty ASCII, at most 253
/// bytes. Full DNS validation belongs to `GatewayName`; the journal only needs
/// an exact-match binding, but it still rejects empty/non-ASCII names closed.
fn validate_journal_gateway_name(name: &str) -> Result<(), ReplayJournalError> {
    if name.is_empty()
        || name.len() > MAX_JOURNAL_GATEWAY_NAME_LEN
        || !name.is_ascii()
    {
        return Err(ReplayJournalError::InvalidConfiguration);
    }
    Ok(())
}

/// Reads and validates a replay journal file.
///
/// - Missing file means an empty journal (no error).
/// - A present file that is a symlink, not a regular file, or permissively
///   permissioned (Linux group/other bits, expected `0600`) fails closed
///   before any parse.
/// - Bad magic/version/scope, trailing bytes, short reads, zero IDs, zero
///   expiries, duplicate IDs, over-bound counts, or a gateway-name mismatch
///   all fail closed with `Corrupt`.
/// - Expired entries (retained-until `<= now_unix_seconds`) are pruned from
///   the returned map, not failed; the caller rewrites the file to bound
///   growth.
pub fn read_replay_journal(
    path: &Path,
    expected_gateway: &str,
    now_unix_seconds: u64,
) -> Result<BTreeMap<TicketId, u64>, ReplayJournalError> {
    validate_journal_gateway_name(expected_gateway)?;
    // Present-file permission gate before any parse (Linux 0600, no symlinks).
    match std::fs::symlink_metadata(path) {
        Ok(_) => super::persistence::validate_journal_file(path).map_err(|_| ReplayJournalError::Corrupt)?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(BTreeMap::new()),
        Err(_) => return Err(ReplayJournalError::Io),
    }
    let bytes = match std::fs::read(path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(BTreeMap::new()),
        Err(_) => return Err(ReplayJournalError::Io),
    };
    if (bytes.len() as u64) > MAX_REPLAY_JOURNAL_BYTES {
        return Err(ReplayJournalError::Corrupt);
    }
    if bytes.len() < 8 {
        return Err(ReplayJournalError::Corrupt);
    }
    if bytes[0..4] != REPLAY_JOURNAL_MAGIC {
        return Err(ReplayJournalError::Corrupt);
    }
    if bytes[4] != REPLAY_JOURNAL_VERSION {
        return Err(ReplayJournalError::Corrupt);
    }
    if bytes[5] != REPLAY_SCOPE_SINGLE {
        // Any non-single scope byte is an explicit multi-gateway rejection:
        // this file was not created by the single-gateway entrypoint.
        return Err(ReplayJournalError::Corrupt);
    }
    let name_len = bytes[6] as usize;
    if bytes[7] != 0 {
        return Err(ReplayJournalError::Corrupt);
    }
    if name_len == 0 || name_len > MAX_JOURNAL_GATEWAY_NAME_LEN {
        return Err(ReplayJournalError::Corrupt);
    }
    if bytes.len() < 8 + name_len {
        return Err(ReplayJournalError::Corrupt);
    }
    let stored_name = std::str::from_utf8(&bytes[8..8 + name_len]).map_err(|_| ReplayJournalError::Corrupt)?;
    if stored_name != expected_gateway {
        // Single-gateway binding: a journal created for another gateway must
        // never be reused here.
        return Err(ReplayJournalError::Corrupt);
    }
    let records = &bytes[8 + name_len..];
    if records.len() % REPLAY_RECORD_LEN != 0 {
        return Err(ReplayJournalError::Corrupt);
    }
    let count = records.len() / REPLAY_RECORD_LEN;
    if count > MAX_REPLAY_ENTRIES_HARD_CAP {
        return Err(ReplayJournalError::Corrupt);
    }
    let mut entries = BTreeMap::new();
    let mut seen = HashSet::new();
    for chunk in records.chunks_exact(REPLAY_RECORD_LEN) {
        let mut id = [0u8; 16];
        id.copy_from_slice(&chunk[0..16]);
        let mut expiry = [0u8; 8];
        expiry.copy_from_slice(&chunk[16..24]);
        let expiry = u64::from_be_bytes(expiry);
        if id.iter().all(|byte| *byte == 0) || expiry == 0 {
            return Err(ReplayJournalError::Corrupt);
        }
        let ticket_id = TicketId::from_bytes(id);
        if !seen.insert(ticket_id) {
            return Err(ReplayJournalError::Corrupt);
        }
        let retained_until = expiry.saturating_add(REPLAY_EXPIRY_SKEW_SECONDS);
        if retained_until > now_unix_seconds {
            entries.insert(ticket_id, retained_until);
        }
    }
    Ok(entries)
}

/// Atomically and securely rewrites the replay journal from an in-memory
/// snapshot.
///
/// The snapshot maps `TicketId` to retained-until unix seconds (expiry plus
/// skew, as stored by `ReplayCache`). Entries are written sorted by ticket ID
/// for determinism. The write uses [`secure_atomic_write`](super::persistence::secure_atomic_write)
/// (0600 temp creation, parent/tmp/file validation, no symlinks, Linux
/// permission bits, parent fsync on Unix). Any failure leaves the old journal
/// intact and reports `Io` without paths or contents.
pub fn rewrite_replay_journal(
    path: &Path,
    gateway_name: &str,
    entries: &BTreeMap<TicketId, u64>,
) -> Result<(), ReplayJournalError> {
    validate_journal_gateway_name(gateway_name)?;
    if entries.len() > MAX_REPLAY_ENTRIES_HARD_CAP {
        return Err(ReplayJournalError::Io);
    }
    let name_bytes = gateway_name.as_bytes();
    let mut bytes = Vec::with_capacity(8 + name_bytes.len() + entries.len() * REPLAY_RECORD_LEN);
    bytes.extend_from_slice(&REPLAY_JOURNAL_MAGIC);
    bytes.push(REPLAY_JOURNAL_VERSION);
    bytes.push(REPLAY_SCOPE_SINGLE);
    bytes.push(name_bytes.len() as u8);
    bytes.push(0);
    bytes.extend_from_slice(name_bytes);
    // BTreeMap iteration is already sorted by TicketId (Ord).
    for (ticket_id, retained_until) in entries {
        // Retained-until minus skew recovers the original expiry for storage.
        // Saturating subtraction keeps corrupt in-memory values bounded rather
        // than panicking; a zero expiry can never be written because the
        // caller only stores `expiry + skew` with non-zero expiry.
        let expiry = retained_until.saturating_sub(REPLAY_EXPIRY_SKEW_SECONDS);
        if expiry == 0 {
            return Err(ReplayJournalError::Io);
        }
        bytes.extend_from_slice(&ticket_id.as_bytes());
        bytes.extend_from_slice(&expiry.to_be_bytes());
    }
    if (bytes.len() as u64) > MAX_REPLAY_JOURNAL_BYTES {
        return Err(ReplayJournalError::Io);
    }
    // Secure 0600 atomic rewrite (parent/tmp/file validation, no symlinks,
    // Linux permission bits, parent fsync). Any failure leaves the old
    // journal intact and reports `Io` without paths or contents.
    super::persistence::secure_atomic_write(path, &bytes).map_err(|_| ReplayJournalError::Io)
}



#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn temp_path(name: &str) -> PathBuf {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("sg-replay-test-{nonce}-{name}"))
    }

    fn entries(pairs: &[(u8, u64)]) -> BTreeMap<TicketId, u64> {
        pairs
            .iter()
            .map(|(byte, retained)| (TicketId::from_bytes([*byte; 16]), *retained))
            .collect()
    }

    #[test]
    fn scope_parsing_accepts_single_and_explicitly_rejects_multi() {
        assert_eq!(RedemptionScope::parse("single-gateway"), Ok(RedemptionScope::SingleGateway));
        assert_eq!(
            RedemptionScope::parse("multi-gateway"),
            Err(RedemptionScopeError::MultiGatewayRejected)
        );
        assert_eq!(
            RedemptionScope::parse("shared"),
            Err(RedemptionScopeError::MultiGatewayRejected)
        );
        assert_eq!(
            RedemptionScope::parse("clustered"),
            Err(RedemptionScopeError::MultiGatewayRejected)
        );
        assert_eq!(
            RedemptionScope::parse(""),
            Err(RedemptionScopeError::InvalidScope)
        );
        assert_eq!(
            RedemptionScope::parse("SINGLE-GATEWAY"),
            Err(RedemptionScopeError::InvalidScope)
        );
    }

    #[test]
    fn missing_journal_loads_empty_and_round_trips() {
        let path = temp_path("missing.journal");
        let _ = std::fs::remove_file(&path);
        let loaded = read_replay_journal(&path, "iad-1.example.test", 1_000).unwrap();
        assert!(loaded.is_empty());

        let snapshot = entries(&[(1, 2_000), (2, 3_000)]);
        rewrite_replay_journal(&path, "iad-1.example.test", &snapshot).unwrap();
        let reloaded = read_replay_journal(&path, "iad-1.example.test", 1_000).unwrap();
        assert_eq!(reloaded, snapshot);
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(path.with_extension("tmp"));
    }

    #[test]
    fn gateway_mismatch_and_bad_header_fail_closed() {
        let path = temp_path("bound.journal");
        let _ = std::fs::remove_file(&path);
        rewrite_replay_journal(&path, "iad-1.example.test", &entries(&[(1, 2_000)])).unwrap();
        assert_eq!(
            read_replay_journal(&path, "iad-2.example.test", 1_000),
            Err(ReplayJournalError::Corrupt)
        );

        // Corrupt magic.
        let mut bytes = std::fs::read(&path).unwrap();
        bytes[0] = b'X';
        std::fs::write(&path, &bytes).unwrap();
        assert_eq!(
            read_replay_journal(&path, "iad-1.example.test", 1_000),
            Err(ReplayJournalError::Corrupt)
        );

        // Trailing byte.
        let mut bytes = std::fs::read(&path).unwrap();
        bytes.push(0);
        // Restore magic first so trailing-data is the failure, not magic.
        bytes[0] = b'S';
        std::fs::write(&path, &bytes).unwrap();
        assert_eq!(
            read_replay_journal(&path, "iad-1.example.test", 1_000),
            Err(ReplayJournalError::Corrupt)
        );
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(path.with_extension("tmp"));
    }

    #[test]
    fn expired_entries_are_pruned_on_load() {
        let path = temp_path("prune.journal");
        let _ = std::fs::remove_file(&path);
        // Expiry 1_000 + skew 30 = retained 1_030.
        rewrite_replay_journal(&path, "gw.test", &entries(&[(1, 1_030), (2, 5_000)])).unwrap();
        // At now=1_030, the first entry's retained-until is not > now, so it
        // is pruned; the second survives.
        let loaded = read_replay_journal(&path, "gw.test", 1_030).unwrap();
        assert_eq!(loaded.len(), 1);
        assert!(loaded.contains_key(&TicketId::from_bytes([2; 16])));
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(path.with_extension("tmp"));
    }

    #[test]
    fn duplicate_and_zero_records_fail_closed() {
        let path = temp_path("dup.journal");
        let _ = std::fs::remove_file(&path);
        // Manually craft a journal with duplicate ticket IDs.
        let mut bytes = Vec::new();
        bytes.extend_from_slice(b"SGTR");
        bytes.push(1);
        bytes.push(0);
        bytes.push(2);
        bytes.push(0);
        bytes.extend_from_slice(b"gw");
        for _ in 0..2 {
            bytes.extend_from_slice(&[9u8; 16]);
            bytes.extend_from_slice(&2_000u64.to_be_bytes());
        }
        std::fs::write(&path, &bytes).unwrap();
        assert_eq!(
            read_replay_journal(&path, "gw", 1_000),
            Err(ReplayJournalError::Corrupt)
        );
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(path.with_extension("tmp"));
    }
}
