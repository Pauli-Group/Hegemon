use crate::{NetworkError, wire};
use serde::{Deserialize, Serialize};
use std::collections::hash_map::Entry;
use std::collections::{HashMap, HashSet};
use std::fs;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
struct PeerRecord {
    addr: SocketAddr,
    last_updated: SystemTime,
    last_connected: Option<SystemTime>,
}

#[derive(Clone, Debug)]
pub struct PeerStoreConfig {
    pub path: PathBuf,
    pub ttl: Duration,
    pub max_entries: usize,
}

impl Default for PeerStoreConfig {
    fn default() -> Self {
        Self {
            path: PathBuf::from("p2p_peers.bin"),
            ttl: Duration::from_secs(24 * 60 * 60),
            max_entries: 512,
        }
    }
}

impl PeerStoreConfig {
    pub fn with_path(path: impl AsRef<Path>) -> Self {
        Self {
            path: path.as_ref().to_path_buf(),
            ..Self::default()
        }
    }
}

#[derive(Debug)]
pub struct PeerStore {
    config: PeerStoreConfig,
    entries: HashMap<SocketAddr, PeerRecord>,
}

impl PeerStore {
    pub fn new(config: PeerStoreConfig) -> Self {
        Self {
            config,
            entries: HashMap::new(),
        }
    }

    pub fn addresses(&self) -> Vec<SocketAddr> {
        self.entries.keys().copied().collect()
    }

    pub fn load(&mut self) -> Result<(), NetworkError> {
        if let Ok(bytes) = fs::read(&self.config.path) {
            match wire::decode::<Vec<PeerRecord>>(&bytes, wire::MAX_PEER_STORE_LEN) {
                Ok(records) => {
                    self.entries = records.into_iter().map(|rec| (rec.addr, rec)).collect();
                    let pruned = self.prune_stale();
                    let capped = self.enforce_max_entries();
                    if pruned || capped {
                        self.persist()?;
                    }
                }
                Err(_) => {
                    let corrupt_path = self.config.path.with_extension("corrupt");
                    let _ = fs::rename(&self.config.path, corrupt_path);
                    self.entries.clear();
                }
            }
        }

        Ok(())
    }

    pub fn record_connected(&mut self, addr: SocketAddr) -> Result<(), NetworkError> {
        let now = SystemTime::now();
        let mut changed = self.prune_stale();

        match self.entries.entry(addr) {
            Entry::Vacant(entry) => {
                entry.insert(PeerRecord {
                    addr,
                    last_updated: now,
                    last_connected: Some(now),
                });
                changed = true;
            }
            Entry::Occupied(mut entry) => {
                let record = entry.get_mut();
                if record.last_updated != now {
                    record.last_updated = now;
                    changed = true;
                }
                if record.last_connected != Some(now) {
                    record.last_connected = Some(now);
                    changed = true;
                }
            }
        }

        let capped = self.enforce_max_entries();
        if changed || capped {
            self.persist()?;
        }

        Ok(())
    }

    pub fn record_disconnected(&mut self, addr: SocketAddr) -> Result<(), NetworkError> {
        let now = SystemTime::now();
        let mut changed = self.prune_stale();

        match self.entries.entry(addr) {
            Entry::Vacant(entry) => {
                entry.insert(PeerRecord {
                    addr,
                    last_updated: now,
                    last_connected: None,
                });
                changed = true;
            }
            Entry::Occupied(mut entry) => {
                let record = entry.get_mut();
                if record.last_updated != now {
                    record.last_updated = now;
                    changed = true;
                }
            }
        }

        let capped = self.enforce_max_entries();
        if changed || capped {
            self.persist()?;
        }

        Ok(())
    }

    pub fn record_learned(
        &mut self,
        addrs: impl IntoIterator<Item = SocketAddr>,
    ) -> Result<(), NetworkError> {
        let mut changed = self.prune_stale();
        let now = SystemTime::now();

        for addr in addrs {
            match self.entries.entry(addr) {
                Entry::Vacant(entry) => {
                    entry.insert(PeerRecord {
                        addr,
                        last_updated: now,
                        last_connected: None,
                    });
                    changed = true;
                }
                Entry::Occupied(mut entry) => {
                    let record = entry.get_mut();
                    if record.last_updated != now {
                        record.last_updated = now;
                        changed = true;
                    }
                }
            }
        }

        let capped = self.enforce_max_entries();
        if changed || capped {
            self.persist()?;
        }

        Ok(())
    }

    pub fn remove_addresses(
        &mut self,
        addrs: impl IntoIterator<Item = SocketAddr>,
    ) -> Result<(), NetworkError> {
        let mut changed = false;
        for addr in addrs {
            changed |= self.entries.remove(&addr).is_some();
        }
        if changed {
            self.persist()?;
        }
        Ok(())
    }

    pub fn recent_connected_peers(
        &mut self,
        limit: usize,
        exclude: &HashSet<SocketAddr>,
    ) -> Result<Vec<SocketAddr>, NetworkError> {
        let pruned = self.prune_stale();
        if pruned {
            self.persist()?;
        }

        let mut entries: Vec<_> = self
            .entries
            .values()
            .filter(|entry| entry.last_connected.is_some())
            .filter(|entry| !exclude.contains(&entry.addr))
            .cloned()
            .collect();

        entries.sort_by(|a, b| {
            let a_time = a.last_connected.unwrap_or(a.last_updated);
            let b_time = b.last_connected.unwrap_or(b.last_updated);
            b_time.cmp(&a_time)
        });

        Ok(entries
            .into_iter()
            .take(limit)
            .map(|entry| entry.addr)
            .collect())
    }

    fn prune_stale(&mut self) -> bool {
        let now = SystemTime::now();
        let ttl = self.config.ttl;
        let before = self.entries.len();

        self.entries
            .retain(|_, entry| match now.duration_since(entry.last_updated) {
                Ok(age) => age <= ttl,
                Err(_) => true,
            });

        before != self.entries.len()
    }

    fn enforce_max_entries(&mut self) -> bool {
        if self.entries.len() <= self.config.max_entries {
            return false;
        }

        let mut records: Vec<_> = self.entries.values().cloned().collect();
        records.sort_by(|a, b| {
            let a_time = a.last_connected.unwrap_or(a.last_updated);
            let b_time = b.last_connected.unwrap_or(b.last_updated);
            b_time.cmp(&a_time)
        });

        records.truncate(self.config.max_entries);
        let allowed: HashSet<_> = records.into_iter().map(|record| record.addr).collect();
        let before = self.entries.len();
        self.entries.retain(|addr, _| allowed.contains(addr));
        before != self.entries.len()
    }

    fn persist(&self) -> Result<(), NetworkError> {
        if let Some(parent) = self.config.path.parent()
            && !parent.as_os_str().is_empty()
        {
            fs::create_dir_all(parent)?;
        }
        let tmp_path = self.config.path.with_extension("tmp");
        let data = wire::encode(
            &self.entries.values().cloned().collect::<Vec<_>>(),
            wire::MAX_PEER_STORE_LEN,
        )?;
        fs::write(&tmp_path, data)?;
        fs::rename(tmp_path, &self.config.path)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;
    use std::time::Duration;

    fn temp_path(name: &str) -> PathBuf {
        let mut path = std::env::temp_dir();
        path.push(format!("{}_{}", name, uuid()));
        path
    }

    fn uuid() -> String {
        format!("{:x}", rand::random::<u64>())
    }

    #[derive(Deserialize)]
    struct LeanPeerStoreCapacityVectorFile {
        schema_version: u32,
        default_max_peer_store_entries: usize,
        capacity_cases: Vec<LeanPeerStoreCapacityCase>,
    }

    #[derive(Deserialize)]
    struct LeanPeerStoreCapacityCase {
        name: String,
        max_entries: usize,
        entry_ids_by_recency: Vec<u16>,
        expected_retained_ids: Vec<u16>,
        expected_dropped_ids: Vec<u16>,
        expected_retained_count: usize,
        expected_dropped_count: usize,
        expected_changed: bool,
        expected_count_within_max: bool,
        expected_retained_is_recency_prefix: bool,
        expected_dropped_ids_absent: bool,
    }

    fn addr_for_peer_id(id: u16) -> SocketAddr {
        format!("127.0.0.1:{}", 10_000u32 + u32::from(id))
            .parse()
            .expect("test peer addr")
    }

    fn store_with_recency_order(case: &LeanPeerStoreCapacityCase) -> PeerStore {
        let path = temp_path(&format!("peer_store_capacity_{}", case.name));
        let mut store = PeerStore::new(PeerStoreConfig {
            path,
            ttl: Duration::from_secs(60),
            max_entries: case.max_entries,
        });
        let base_time = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        let entry_count = case.entry_ids_by_recency.len();

        for (idx, id) in case.entry_ids_by_recency.iter().enumerate() {
            let timestamp = base_time + Duration::from_secs((entry_count - idx) as u64);
            let addr = addr_for_peer_id(*id);
            store.entries.insert(
                addr,
                PeerRecord {
                    addr,
                    last_updated: timestamp,
                    last_connected: Some(timestamp),
                },
            );
        }

        store
    }

    #[test]
    fn persists_and_prunes_by_ttl() {
        let path = temp_path("peer_store");
        let mut store = PeerStore::new(PeerStoreConfig {
            path: path.clone(),
            ttl: Duration::from_secs(5),
            max_entries: 16,
        });

        let active: SocketAddr = "127.0.0.1:9001".parse().unwrap();
        let stale: SocketAddr = "127.0.0.1:9002".parse().unwrap();

        store.record_connected(active).unwrap();
        store.record_learned([stale]).unwrap();

        // Force the stale entry to age out on reload.
        let now = SystemTime::now();
        if let Some(entry) = store.entries.get_mut(&stale) {
            entry.last_updated = now - Duration::from_secs(2);
        }
        if let Some(entry) = store.entries.get_mut(&active) {
            entry.last_updated = now;
            entry.last_connected = Some(now);
        }
        store.persist().unwrap();

        let mut reloaded = PeerStore::new(PeerStoreConfig {
            path: path.clone(),
            ttl: Duration::from_secs(1),
            max_entries: 16,
        });
        reloaded.load().unwrap();

        assert!(reloaded.entries.contains_key(&active));
        assert!(!reloaded.entries.contains_key(&stale));
    }

    #[test]
    fn lean_generated_peer_store_capacity_vectors_match_production() {
        let Ok(path) = std::env::var("HEGEMON_LEAN_PEER_STORE_CAPACITY_ADMISSION_VECTORS") else {
            eprintln!("skipping Lean peer-store capacity vectors; env var not set");
            return;
        };
        let contents =
            std::fs::read_to_string(path).expect("read Lean peer-store capacity vectors");
        let vectors: LeanPeerStoreCapacityVectorFile =
            serde_json::from_str(&contents).expect("parse Lean peer-store capacity vectors");
        assert_eq!(vectors.schema_version, 1);
        assert_eq!(
            vectors.default_max_peer_store_entries,
            PeerStoreConfig::default().max_entries,
            "default peer-store cap drifted from Lean"
        );

        for case in &vectors.capacity_cases {
            let mut store = store_with_recency_order(case);
            let changed = store.enforce_max_entries();
            assert_eq!(changed, case.expected_changed, "{}", case.name);
            assert_eq!(
                store.entries.len(),
                case.expected_retained_count,
                "{} retained count",
                case.name
            );
            assert_eq!(
                store.entries.len() <= case.max_entries,
                case.expected_count_within_max,
                "{} retained count within max",
                case.name
            );

            let retained: HashSet<_> = store.entries.keys().copied().collect();
            let actual_retained_ids_by_recency: Vec<_> = case
                .entry_ids_by_recency
                .iter()
                .copied()
                .filter(|id| retained.contains(&addr_for_peer_id(*id)))
                .collect();
            let actual_dropped_ids_by_recency: Vec<_> = case
                .entry_ids_by_recency
                .iter()
                .copied()
                .filter(|id| !retained.contains(&addr_for_peer_id(*id)))
                .collect();
            assert_eq!(
                actual_retained_ids_by_recency, case.expected_retained_ids,
                "{} retained recency prefix",
                case.name
            );
            assert_eq!(
                actual_dropped_ids_by_recency, case.expected_dropped_ids,
                "{} dropped recency suffix",
                case.name
            );
            assert_eq!(
                actual_dropped_ids_by_recency.len(),
                case.expected_dropped_count,
                "{} dropped count",
                case.name
            );
            assert_eq!(
                case.entry_ids_by_recency
                    .iter()
                    .take(case.expected_retained_ids.len())
                    .copied()
                    .collect::<Vec<_>>()
                    == case.expected_retained_ids,
                case.expected_retained_is_recency_prefix,
                "{} retained prefix expectation",
                case.name
            );
            for id in &case.expected_retained_ids {
                assert!(
                    retained.contains(&addr_for_peer_id(*id)),
                    "{} retained expected peer {id}",
                    case.name
                );
            }
            for id in &case.expected_dropped_ids {
                assert!(
                    !retained.contains(&addr_for_peer_id(*id)),
                    "{} dropped overflow peer {id}",
                    case.name
                );
            }
            assert_eq!(
                case.expected_dropped_ids
                    .iter()
                    .all(|id| !retained.contains(&addr_for_peer_id(*id))),
                case.expected_dropped_ids_absent,
                "{} dropped ids absent expectation",
                case.name
            );
        }
    }

    #[test]
    fn returns_recent_peers_in_order_with_limit() {
        let path = temp_path("peer_store_recent");
        let mut store = PeerStore::new(PeerStoreConfig {
            path,
            ttl: Duration::from_secs(60),
            max_entries: 10,
        });

        let base_time = SystemTime::now();
        let addrs: Vec<SocketAddr> = (0..6)
            .map(|i| format!("127.0.0.1:9{:03}", i).parse().unwrap())
            .collect();

        for (i, addr) in addrs.iter().enumerate() {
            store.entries.insert(
                *addr,
                PeerRecord {
                    addr: *addr,
                    last_updated: base_time + Duration::from_secs(i as u64),
                    last_connected: Some(base_time + Duration::from_secs(i as u64)),
                },
            );
        }

        let exclude: HashSet<_> = [addrs[1]].into_iter().collect();
        let recent = store.recent_connected_peers(5, &exclude).unwrap();

        // Should skip excluded, take most recent first, and cap at 5 entries.
        assert_eq!(recent.len(), 5);
        assert_eq!(recent[0], addrs[5]);
        assert_eq!(recent[1], addrs[4]);
        assert_eq!(recent[2], addrs[3]);
        assert_eq!(recent[3], addrs[2]);
        assert_eq!(recent[4], addrs[0]);
    }

    #[test]
    fn disconnect_does_not_promote_failed_endpoint_or_erase_success_recency() {
        let path = temp_path("peer_store_disconnect_recency");
        let mut store = PeerStore::new(PeerStoreConfig {
            path,
            ttl: Duration::from_secs(60),
            max_entries: 10,
        });
        let connected: SocketAddr = "127.0.0.1:9050".parse().unwrap();
        let failed: SocketAddr = "127.0.0.1:9051".parse().unwrap();
        let connected_at = SystemTime::now() - Duration::from_secs(10);

        store.entries.insert(
            connected,
            PeerRecord {
                addr: connected,
                last_updated: connected_at,
                last_connected: Some(connected_at),
            },
        );

        store.record_disconnected(connected).unwrap();
        store.record_disconnected(failed).unwrap();

        assert_eq!(
            store.entries[&connected].last_connected,
            Some(connected_at),
            "disconnect bookkeeping must preserve the last successful connection time"
        );
        assert_eq!(store.entries[&failed].last_connected, None);
        assert_eq!(
            store.recent_connected_peers(10, &HashSet::new()).unwrap(),
            vec![connected],
            "never-connected endpoints stay out of persistent reconnect targets"
        );
    }

    #[test]
    fn enforce_max_entries_retains_newest_connected_peers() {
        let path = temp_path("peer_store_capacity_connected");
        let mut store = PeerStore::new(PeerStoreConfig {
            path,
            ttl: Duration::from_secs(60),
            max_entries: 3,
        });

        let base_time = SystemTime::now();
        let addrs: Vec<SocketAddr> = (0..6)
            .map(|i| format!("127.0.0.1:91{:02}", i).parse().unwrap())
            .collect();

        for (i, addr) in addrs.iter().enumerate() {
            let timestamp = base_time + Duration::from_secs(i as u64);
            store.entries.insert(
                *addr,
                PeerRecord {
                    addr: *addr,
                    last_updated: timestamp,
                    last_connected: Some(timestamp),
                },
            );
        }

        assert!(store.enforce_max_entries());
        assert_eq!(store.entries.len(), 3);
        assert!(store.entries.contains_key(&addrs[5]));
        assert!(store.entries.contains_key(&addrs[4]));
        assert!(store.entries.contains_key(&addrs[3]));
        assert!(!store.entries.contains_key(&addrs[2]));
        assert!(!store.entries.contains_key(&addrs[1]));
        assert!(!store.entries.contains_key(&addrs[0]));
    }

    #[test]
    fn record_learned_enforces_max_entries_before_persisting() {
        let path = temp_path("peer_store_learned_cap");
        let mut store = PeerStore::new(PeerStoreConfig {
            path: path.clone(),
            ttl: Duration::from_secs(60),
            max_entries: 2,
        });
        let addrs: Vec<SocketAddr> = (0..5)
            .map(|i| format!("127.0.0.1:93{:02}", i).parse().unwrap())
            .collect();

        store.record_learned(addrs).unwrap();
        assert_eq!(store.entries.len(), 2);

        let mut reloaded = PeerStore::new(PeerStoreConfig {
            path,
            ttl: Duration::from_secs(60),
            max_entries: 2,
        });
        reloaded.load().unwrap();
        assert_eq!(reloaded.entries.len(), 2);
    }

    #[test]
    fn record_connected_enforces_max_entries_before_persisting() {
        let path = temp_path("peer_store_connected_cap");
        let mut store = PeerStore::new(PeerStoreConfig {
            path: path.clone(),
            ttl: Duration::from_secs(60),
            max_entries: 2,
        });
        for i in 0..5 {
            let addr: SocketAddr = format!("127.0.0.1:94{:02}", i).parse().unwrap();
            store.record_connected(addr).unwrap();
        }
        assert_eq!(store.entries.len(), 2);

        let mut reloaded = PeerStore::new(PeerStoreConfig {
            path,
            ttl: Duration::from_secs(60),
            max_entries: 2,
        });
        reloaded.load().unwrap();
        assert_eq!(reloaded.entries.len(), 2);
    }

    #[test]
    fn load_enforces_max_entries_for_directly_written_store() {
        let path = temp_path("peer_store_load_cap");
        let base_time = SystemTime::now();
        let records = (0..5)
            .map(|i| {
                let addr: SocketAddr = format!("127.0.0.1:95{:02}", i).parse().unwrap();
                PeerRecord {
                    addr,
                    last_updated: base_time + Duration::from_secs(i),
                    last_connected: Some(base_time + Duration::from_secs(i)),
                }
            })
            .collect::<Vec<_>>();
        fs::write(
            &path,
            wire::encode(&records, wire::MAX_PEER_STORE_LEN).expect("encode peer records"),
        )
        .unwrap();

        let mut store = PeerStore::new(PeerStoreConfig {
            path: path.clone(),
            ttl: Duration::from_secs(60),
            max_entries: 2,
        });
        store.load().unwrap();
        assert_eq!(store.entries.len(), 2);

        let persisted = fs::read(path).unwrap();
        let persisted_records: Vec<PeerRecord> =
            wire::decode(&persisted, wire::MAX_PEER_STORE_LEN).unwrap();
        assert_eq!(persisted_records.len(), 2);
        assert!(store.entries.contains_key(&records[4].addr));
        assert!(store.entries.contains_key(&records[3].addr));
    }

    #[test]
    fn enforce_max_entries_uses_recent_connected_or_learned_time() {
        let path = temp_path("peer_store_capacity_mixed");
        let mut store = PeerStore::new(PeerStoreConfig {
            path,
            ttl: Duration::from_secs(60),
            max_entries: 2,
        });

        let base_time = SystemTime::now();
        let old_connection_with_new_update: SocketAddr = "127.0.0.1:9200".parse().unwrap();
        let newest_learned: SocketAddr = "127.0.0.1:9201".parse().unwrap();
        let newest_connected: SocketAddr = "127.0.0.1:9202".parse().unwrap();
        let older_learned: SocketAddr = "127.0.0.1:9203".parse().unwrap();

        store.entries.insert(
            old_connection_with_new_update,
            PeerRecord {
                addr: old_connection_with_new_update,
                last_updated: base_time + Duration::from_secs(100),
                last_connected: Some(base_time + Duration::from_secs(1)),
            },
        );
        store.entries.insert(
            newest_learned,
            PeerRecord {
                addr: newest_learned,
                last_updated: base_time + Duration::from_secs(50),
                last_connected: None,
            },
        );
        store.entries.insert(
            newest_connected,
            PeerRecord {
                addr: newest_connected,
                last_updated: base_time + Duration::from_secs(2),
                last_connected: Some(base_time + Duration::from_secs(40)),
            },
        );
        store.entries.insert(
            older_learned,
            PeerRecord {
                addr: older_learned,
                last_updated: base_time + Duration::from_secs(10),
                last_connected: None,
            },
        );

        assert!(store.enforce_max_entries());
        assert_eq!(store.entries.len(), 2);
        assert!(store.entries.contains_key(&newest_learned));
        assert!(store.entries.contains_key(&newest_connected));
        assert!(!store.entries.contains_key(&old_connection_with_new_update));
        assert!(!store.entries.contains_key(&older_learned));
    }
}
