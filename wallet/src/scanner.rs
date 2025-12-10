//! Note Scanning Service for Shielded Wallet
//!
//! This module provides efficient note scanning capabilities for the wallet.
//! It scans encrypted notes from the blockchain, trial-decrypts them using
//! the wallet's viewing key, and tracks owned notes.
//!
//! ## Design
//!
//! - **Trial Decryption**: Attempts ML-KEM-768 decapsulation on each note
//! - **Parallel Scanning**: Supports batch scanning for performance
//! - **Incremental Sync**: Only scans new notes since last sync
//!
//! ## Post-Quantum Security
//!
//! Note encryption uses ML-KEM-768 (FIPS 203) for key encapsulation,
//! providing 128-bit security against quantum attacks.
//!
//! ## Usage
//!
//! ```ignore
//! use wallet::scanner::{NoteScanner, ScannerConfig};
//!
//! let config = ScannerConfig::default();
//! let scanner = NoteScanner::new(viewing_key, config);
//!
//! let encrypted_notes = fetch_notes_from_chain(...);
//! let owned_notes = scanner.scan_batch(&encrypted_notes)?;
//! ```

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use crate::error::WalletError;
use crate::notes::NoteCiphertext;
use crate::viewing::{FullViewingKey, IncomingViewingKey, RecoveredNote};

/// Configuration for the note scanner.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ScannerConfig {
    /// Maximum batch size for parallel scanning.
    pub batch_size: usize,
    /// Number of diversifier indices to try per note.
    /// Default: 100 (covers typical wallet usage).
    pub diversifier_range: u32,
    /// Enable parallel scanning (requires rayon feature).
    pub parallel: bool,
    /// Scan timeout per note.
    pub note_timeout: Duration,
}

impl Default for ScannerConfig {
    fn default() -> Self {
        Self {
            batch_size: 256,
            diversifier_range: 100,
            parallel: false, // Disable by default for simplicity
            note_timeout: Duration::from_secs(1),
        }
    }
}

impl ScannerConfig {
    /// Create a config optimized for fast scanning.
    pub fn fast() -> Self {
        Self {
            batch_size: 512,
            diversifier_range: 50,
            parallel: true,
            note_timeout: Duration::from_millis(500),
        }
    }

    /// Create a config for comprehensive scanning.
    pub fn thorough() -> Self {
        Self {
            batch_size: 128,
            diversifier_range: 1000,
            parallel: true,
            note_timeout: Duration::from_secs(5),
        }
    }
}

/// Encrypted note with position metadata.
#[derive(Clone, Debug)]
pub struct PositionedNote {
    /// Index/position in the commitment tree.
    pub position: u64,
    /// The encrypted note ciphertext.
    pub ciphertext: NoteCiphertext,
    /// Block height where this note was added (if known).
    pub block_height: Option<u64>,
}

impl PositionedNote {
    /// Create a new positioned note.
    pub fn new(position: u64, ciphertext: NoteCiphertext) -> Self {
        Self {
            position,
            ciphertext,
            block_height: None,
        }
    }

    /// Create with block height.
    pub fn with_height(position: u64, ciphertext: NoteCiphertext, height: u64) -> Self {
        Self {
            position,
            ciphertext,
            block_height: Some(height),
        }
    }
}

/// A successfully scanned note with all metadata.
#[derive(Clone, Debug)]
pub struct ScannedNote {
    /// The recovered note data.
    pub recovered: RecoveredNote,
    /// Position in the commitment tree.
    pub position: u64,
    /// Computed nullifier (if full viewing key available).
    pub nullifier: Option<[u8; 32]>,
    /// Block height where found.
    pub block_height: Option<u64>,
}

impl ScannedNote {
    /// Get the note value.
    pub fn value(&self) -> u64 {
        self.recovered.note.value
    }

    /// Get the asset ID.
    pub fn asset_id(&self) -> u64 {
        self.recovered.note.asset_id
    }
}

/// Result of a scanning operation.
#[derive(Clone, Debug, Default)]
pub struct ScanResult {
    /// Successfully decrypted notes.
    pub notes: Vec<ScannedNote>,
    /// Total notes scanned.
    pub total_scanned: usize,
    /// Notes that failed decryption (not owned by this wallet).
    pub not_owned: usize,
    /// Notes that had decryption errors.
    pub errors: usize,
    /// Time spent scanning.
    pub scan_time: Duration,
}

impl ScanResult {
    /// Get the number of owned notes found.
    pub fn owned_count(&self) -> usize {
        self.notes.len()
    }

    /// Get total value of owned notes by asset.
    pub fn total_value_by_asset(&self) -> HashMap<u64, u64> {
        let mut totals = HashMap::new();
        for note in &self.notes {
            *totals.entry(note.asset_id()).or_default() += note.value();
        }
        totals
    }
}

/// Note scanner using incoming viewing key.
///
/// The scanner trial-decrypts notes using ML-KEM-768 to determine ownership.
/// Only notes encrypted to this wallet's public key will decrypt successfully.
pub struct NoteScanner {
    /// Incoming viewing key for trial decryption.
    incoming_key: IncomingViewingKey,
    /// Full viewing key for nullifier computation (optional).
    full_viewing_key: Option<FullViewingKey>,
    /// Scanner configuration.
    config: ScannerConfig,
}

impl NoteScanner {
    /// Create a new scanner with incoming viewing key only.
    ///
    /// This scanner can detect owned notes but cannot compute nullifiers.
    pub fn new(incoming_key: IncomingViewingKey, config: ScannerConfig) -> Self {
        Self {
            incoming_key,
            full_viewing_key: None,
            config,
        }
    }

    /// Create a scanner with full viewing key.
    ///
    /// This scanner can detect owned notes and compute their nullifiers.
    pub fn with_full_key(full_key: FullViewingKey, config: ScannerConfig) -> Self {
        Self {
            incoming_key: full_key.incoming().clone(),
            full_viewing_key: Some(full_key),
            config,
        }
    }

    /// Get the scanner configuration.
    pub fn config(&self) -> &ScannerConfig {
        &self.config
    }

    /// Check if this scanner can compute nullifiers.
    pub fn can_compute_nullifiers(&self) -> bool {
        self.full_viewing_key.is_some()
    }

    /// Scan a single note.
    ///
    /// Returns `Some(ScannedNote)` if the note belongs to this wallet.
    pub fn scan_note(&self, note: &PositionedNote) -> Option<ScannedNote> {
        // Try to decrypt with the incoming viewing key
        match self.incoming_key.decrypt_note(&note.ciphertext) {
            Ok(recovered) => {
                // Compute nullifier if we have full viewing key
                let nullifier = self
                    .full_viewing_key
                    .as_ref()
                    .map(|fvk| fvk.compute_nullifier(&recovered.note.rho, note.position));

                Some(ScannedNote {
                    recovered,
                    position: note.position,
                    nullifier,
                    block_height: note.block_height,
                })
            }
            Err(WalletError::NoteMismatch(_)) => {
                // Not our note
                None
            }
            Err(_) => {
                // Decryption error - treat as not owned
                None
            }
        }
    }

    /// Scan a batch of notes.
    ///
    /// Returns a `ScanResult` with all owned notes found.
    pub fn scan_batch(&self, notes: &[PositionedNote]) -> ScanResult {
        let start = Instant::now();
        let mut result = ScanResult::default();
        result.total_scanned = notes.len();

        for note in notes {
            match self.scan_note(note) {
                Some(scanned) => result.notes.push(scanned),
                None => result.not_owned += 1,
            }
        }

        result.scan_time = start.elapsed();
        result
    }

    /// Scan notes incrementally, starting from a given position.
    ///
    /// This is useful for syncing only new notes since the last scan.
    pub fn scan_incremental(&self, notes: &[PositionedNote], start_position: u64) -> ScanResult {
        let filtered: Vec<_> = notes
            .iter()
            .filter(|n| n.position >= start_position)
            .cloned()
            .collect();
        self.scan_batch(&filtered)
    }
}

/// Shared scanner for concurrent access.
///
/// Wraps `NoteScanner` with `Arc` for use in async contexts.
pub struct SharedScanner {
    inner: Arc<NoteScanner>,
}

impl SharedScanner {
    /// Create a new shared scanner.
    pub fn new(scanner: NoteScanner) -> Self {
        Self {
            inner: Arc::new(scanner),
        }
    }

    /// Scan a batch of notes.
    pub fn scan_batch(&self, notes: &[PositionedNote]) -> ScanResult {
        self.inner.scan_batch(notes)
    }

    /// Get a reference to the inner scanner.
    pub fn inner(&self) -> &NoteScanner {
        &self.inner
    }
}

impl Clone for SharedScanner {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
        }
    }
}

/// Statistics for scanner performance.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ScannerStats {
    /// Total notes scanned.
    pub total_scanned: u64,
    /// Total notes owned.
    pub total_owned: u64,
    /// Total scan time.
    pub total_time: Duration,
    /// Average time per note.
    pub avg_time_per_note: Duration,
    /// Notes per second throughput.
    pub notes_per_second: f64,
}

impl ScannerStats {
    /// Update stats with a scan result.
    pub fn record(&mut self, result: &ScanResult) {
        self.total_scanned += result.total_scanned as u64;
        self.total_owned += result.owned_count() as u64;
        self.total_time += result.scan_time;

        if self.total_scanned > 0 {
            self.avg_time_per_note = self.total_time / self.total_scanned as u32;
            self.notes_per_second = self.total_scanned as f64 / self.total_time.as_secs_f64();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::RootSecret;
    use crate::notes::{MemoPlaintext, NotePlaintext};
    use rand::{rngs::StdRng, SeedableRng};

    fn create_test_scanner() -> (NoteScanner, crate::keys::DerivedKeys) {
        let mut rng = StdRng::seed_from_u64(42);
        let root = RootSecret::from_rng(&mut rng);
        let keys = root.derive();
        let fvk = FullViewingKey::from_keys(&keys);
        let scanner = NoteScanner::with_full_key(fvk, ScannerConfig::default());
        (scanner, keys)
    }

    #[test]
    fn test_config_defaults() {
        let config = ScannerConfig::default();
        assert_eq!(config.batch_size, 256);
        assert_eq!(config.diversifier_range, 100);
    }

    #[test]
    fn test_scan_empty_batch() {
        let (scanner, _) = create_test_scanner();
        let result = scanner.scan_batch(&[]);
        assert_eq!(result.total_scanned, 0);
        assert_eq!(result.owned_count(), 0);
    }

    #[test]
    fn test_scan_owned_note() {
        let (scanner, keys) = create_test_scanner();
        let mut rng = StdRng::seed_from_u64(123);

        // Create an address and encrypt a note to it
        let material = keys.address(0).unwrap();
        let address = material.shielded_address();
        let note = NotePlaintext::random(1000, 1, MemoPlaintext::default(), &mut rng);
        let ciphertext = NoteCiphertext::encrypt(&address, &note, &mut rng).unwrap();

        let positioned = PositionedNote::new(0, ciphertext);
        let result = scanner.scan_batch(&[positioned]);

        assert_eq!(result.total_scanned, 1);
        assert_eq!(result.owned_count(), 1);
        assert_eq!(result.notes[0].value(), 1000);
    }

    #[test]
    fn test_scan_not_owned_note() {
        let (scanner, _) = create_test_scanner();
        let mut rng = StdRng::seed_from_u64(456);

        // Create a different wallet's keys
        let other_root = RootSecret::from_rng(&mut rng);
        let other_keys = other_root.derive();
        let other_material = other_keys.address(0).unwrap();
        let other_address = other_material.shielded_address();

        // Encrypt to the other wallet
        let note = NotePlaintext::random(500, 1, MemoPlaintext::default(), &mut rng);
        let ciphertext = NoteCiphertext::encrypt(&other_address, &note, &mut rng).unwrap();

        let positioned = PositionedNote::new(0, ciphertext);
        let result = scanner.scan_batch(&[positioned]);

        assert_eq!(result.total_scanned, 1);
        assert_eq!(result.owned_count(), 0);
        assert_eq!(result.not_owned, 1);
    }

    #[test]
    fn test_scan_result_totals() {
        let mut result = ScanResult::default();
        result.notes.push(ScannedNote {
            recovered: RecoveredNote {
                diversifier_index: 0,
                note: NotePlaintext {
                    value: 100,
                    asset_id: 1,
                    rho: [0u8; 32],
                    r: [0u8; 32],
                    memo: MemoPlaintext::default(),
                },
                note_data: transaction_circuit::note::NoteData {
                    value: 100,
                    asset_id: 1,
                    pk_recipient: [0u8; 32],
                    rho: [0u8; 32],
                    r: [0u8; 32],
                },
                address: crate::address::ShieldedAddress::default(),
            },
            position: 0,
            nullifier: None,
            block_height: None,
        });

        let totals = result.total_value_by_asset();
        assert_eq!(totals.get(&1), Some(&100));
    }

    #[test]
    fn test_scanner_stats() {
        let mut stats = ScannerStats::default();
        let result = ScanResult {
            notes: vec![],
            total_scanned: 100,
            not_owned: 100,
            errors: 0,
            scan_time: Duration::from_millis(100),
        };

        stats.record(&result);
        assert_eq!(stats.total_scanned, 100);
        assert!(stats.notes_per_second > 0.0);
    }
}
