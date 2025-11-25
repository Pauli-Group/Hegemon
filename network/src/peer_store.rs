use crate::NetworkError;
use serde::{Deserialize, Serialize};
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
            let records: Vec<PeerRecord> = bincode::deserialize(&bytes)?;
            self.entries = records.into_iter().map(|rec| (rec.addr, rec)).collect();
            if self.prune_stale() {
                self.persist()?;
            }
        }

        Ok(())
    }

    pub fn record_connected(&mut self, addr: SocketAddr) -> Result<(), NetworkError> {
        let now = SystemTime::now();
        let mut changed = self.prune_stale();
        let entry = self.entries.entry(addr).or_insert(PeerRecord {
            addr,
            last_updated: now,
            last_connected: Some(now),
        });

        if entry.last_updated != now {
            entry.last_updated = now;
            changed = true;
        }
        if entry.last_connected != Some(now) {
            entry.last_connected = Some(now);
            changed = true;
        }

        if changed || self.enforce_max_entries() {
            self.persist()?;
        }

        Ok(())
    }

    pub fn record_disconnected(&mut self, addr: SocketAddr) -> Result<(), NetworkError> {
        // Disconnections still refresh the timestamp so reconnect attempts prefer fresher peers.
        self.record_connected(addr)
    }

    pub fn record_learned(
        &mut self,
        addrs: impl IntoIterator<Item = SocketAddr>,
    ) -> Result<(), NetworkError> {
        let mut changed = self.prune_stale();
        let now = SystemTime::now();

        for addr in addrs {
            let entry = self.entries.entry(addr).or_insert(PeerRecord {
                addr,
                last_updated: now,
                last_connected: None,
            });

            if entry.last_updated != now {
                entry.last_updated = now;
                changed = true;
            }
        }

        if changed || self.enforce_max_entries() {
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

    pub fn recent_peers(
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
            a_time.cmp(&b_time)
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
        let data = bincode::serialize(&self.entries.values().cloned().collect::<Vec<_>>())?;
        fs::write(&tmp_path, data)?;
        fs::rename(tmp_path, &self.config.path)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn temp_path(name: &str) -> PathBuf {
        let mut path = std::env::temp_dir();
        path.push(format!("{}_{}", name, uuid()));
        path
    }

    fn uuid() -> String {
        format!("{:x}", rand::random::<u64>())
    }

    #[test]
    fn persists_and_prunes_by_ttl() {
        let path = temp_path("peer_store");
        let mut store = PeerStore::new(PeerStoreConfig {
            path: path.clone(),
            ttl: Duration::from_millis(10),
            max_entries: 16,
        });

        let active: SocketAddr = "127.0.0.1:9001".parse().unwrap();
        let stale: SocketAddr = "127.0.0.1:9002".parse().unwrap();

        store.record_connected(active).unwrap();
        store.record_learned([stale]).unwrap();

        // Force the stale entry to age out on reload.
        if let Some(entry) = store.entries.get_mut(&stale) {
            entry.last_updated = SystemTime::now() - Duration::from_millis(100);
        }
        store.persist().unwrap();

        let mut reloaded = PeerStore::new(PeerStoreConfig {
            path: path.clone(),
            ttl: Duration::from_millis(50),
            max_entries: 16,
        });
        reloaded.load().unwrap();

        assert!(reloaded.entries.contains_key(&active));
        assert!(!reloaded.entries.contains_key(&stale));
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
        let recent = store.recent_peers(5, &exclude).unwrap();

        // Should skip excluded, take most recent first, and cap at 5 entries.
        assert_eq!(recent.len(), 5);
        assert_eq!(recent[0], addrs[5]);
        assert_eq!(recent[1], addrs[4]);
        assert_eq!(recent[2], addrs[3]);
        assert_eq!(recent[3], addrs[2]);
        assert_eq!(recent[4], addrs[0]);
    }
}
