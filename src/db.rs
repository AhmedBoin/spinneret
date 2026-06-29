use crate::error::Error;
use crate::proto::{unix_now, FilterMode, NetworkInfo, NetworkKind, PeerInfo};
use serde::{Deserialize, Serialize};
use sled::Db;
use std::collections::HashSet;

/// 10 minutes peer / network TTL
pub const TTL_SECS: u64 = 600;

// ── DB key namespaces ─────────────────────────────────────────────
// "P:<pubkey32>" → PeerRecord
// "N:<netid32>"  → NetworkRecord
// "F:<pubkey32>" → FilterRecord

fn pk(key: &[u8; 32]) -> Vec<u8> {
    let mut k = b"P:".to_vec();
    k.extend_from_slice(key);
    k
}
fn nk(id: &[u8; 32]) -> Vec<u8> {
    let mut k = b"N:".to_vec();
    k.extend_from_slice(id);
    k
}
fn fk(key: &[u8; 32]) -> Vec<u8> {
    let mut k = b"F:".to_vec();
    k.extend_from_slice(key);
    k
}

// ── Stored records ────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerRecord {
    pub info: PeerInfo,
    pub last_tangle: u64,
    pub created_at: u64,
}

impl PeerRecord {
    pub fn new(info: PeerInfo) -> Self {
        let now = unix_now();
        Self {
            info,
            last_tangle: now,
            created_at: now,
        }
    }
    pub fn is_alive(&self) -> bool {
        unix_now().saturating_sub(self.last_tangle) < TTL_SECS
    }
    pub fn touch(&mut self) {
        self.last_tangle = unix_now();
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkMember {
    pub pubkey: [u8; 32],
    pub index: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkRecord {
    pub id: [u8; 32],
    pub kind: NetworkKind,
    pub host_pubkey: Option<[u8; 32]>,
    pub members: Vec<NetworkMember>, // ordered by join time
    pub last_tangle: u64,
    pub created_at: u64,
}

impl NetworkRecord {
    pub fn new(
        id: [u8; 32],
        kind: NetworkKind,
        host_pubkey: Option<[u8; 32]>,
        creator: [u8; 32],
    ) -> Self {
        let now = unix_now();
        Self {
            id,
            kind,
            host_pubkey,
            members: vec![NetworkMember {
                pubkey: creator,
                index: 0,
            }],
            last_tangle: now,
            created_at: now,
        }
    }
    pub fn is_alive(&self) -> bool {
        unix_now().saturating_sub(self.last_tangle) < TTL_SECS
    }
    pub fn touch(&mut self) {
        self.last_tangle = unix_now();
    }
    pub fn contains(&self, key: &[u8; 32]) -> bool {
        self.members.iter().any(|m| &m.pubkey == key)
    }
    pub fn to_proto_info(&self) -> NetworkInfo {
        NetworkInfo {
            id: self.id,
            kind: self.kind,
            host_pubkey: self.host_pubkey,
            member_count: self.members.len() as u32,
        }
    }
    /// Add member; returns their index. No-op if already present.
    pub fn add_member(&mut self, key: [u8; 32]) -> u32 {
        if let Some(m) = self.members.iter().find(|m| m.pubkey == key) {
            return m.index;
        }
        let idx = self.members.len() as u32;
        self.members.push(NetworkMember {
            pubkey: key,
            index: idx,
        });
        idx
    }
    pub fn member_at(&self, idx: u32) -> Option<&NetworkMember> {
        self.members.iter().find(|m| m.index == idx)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FilterRecord {
    pub owner: [u8; 32],
    pub mode: FilterMode,
    pub keys: HashSet<[u8; 32]>, // keys in white/blacklist
}

impl FilterRecord {
    pub fn new(owner: [u8; 32], mode: FilterMode) -> Self {
        Self {
            owner,
            mode,
            keys: HashSet::new(),
        }
    }
    /// Returns true if the caller is allowed to spin the owner.
    pub fn allows_spin(&self, caller: &[u8; 32]) -> bool {
        match self.mode {
            FilterMode::Off => true,
            FilterMode::Whitelist => self.keys.contains(caller),
            FilterMode::Blacklist => !self.keys.contains(caller),
        }
    }
}

// ══════════════════════════════════════════════════════════════════
// StateDb
// ══════════════════════════════════════════════════════════════════

pub struct StateDb {
    pub db: Db,
}

impl StateDb {
    pub fn open(path: &str) -> Result<Self, Error> {
        if let Some(parent) = std::path::Path::new(path).parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent).ok();
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    let _ =
                        std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o755));
                }
            }
        }
        let db = sled::open(path).map_err(|e| Error::Db(format!("open {}: {}", path, e)))?;
        tracing::info!("db {} ({} bytes)", path, db.size_on_disk().unwrap_or(0));
        Ok(Self { db })
    }

    pub fn size_bytes(&self) -> u64 {
        self.db.size_on_disk().unwrap_or(0)
    }

    // ── Peer ─────────────────────────────────────────────────────

    pub fn save_peer(&self, r: &PeerRecord) -> Result<(), Error> {
        self.db.insert(pk(&r.info.pubkey), bincode::serialize(r)?)?;
        Ok(())
    }

    pub fn load_peer(&self, key: &[u8; 32]) -> Result<Option<PeerRecord>, Error> {
        Ok(match self.db.get(pk(key))? {
            None => None,
            Some(v) => Some(bincode::deserialize(&v)?),
        })
    }

    pub fn del_peer(&self, key: &[u8; 32]) -> Result<(), Error> {
        self.db.remove(pk(key))?;
        Ok(())
    }

    pub fn touch_peer(&self, key: &[u8; 32]) -> Result<(), Error> {
        if let Some(mut r) = self.load_peer(key)? {
            r.touch();
            self.save_peer(&r)?;
        }
        Ok(())
    }

    /// Load peer only if alive; deletes and returns None if expired.
    pub fn get_live_peer(&self, key: &[u8; 32]) -> Result<Option<PeerRecord>, Error> {
        match self.load_peer(key)? {
            None => Ok(None),
            Some(r) if !r.is_alive() => {
                self.del_peer(key)?;
                Ok(None)
            }
            Some(r) => Ok(Some(r)),
        }
    }

    // ── Network ──────────────────────────────────────────────────

    pub fn save_net(&self, r: &NetworkRecord) -> Result<(), Error> {
        self.db.insert(nk(&r.id), bincode::serialize(r)?)?;
        Ok(())
    }

    pub fn load_net(&self, id: &[u8; 32]) -> Result<Option<NetworkRecord>, Error> {
        Ok(match self.db.get(nk(id))? {
            None => None,
            Some(v) => Some(bincode::deserialize(&v)?),
        })
    }

    pub fn del_net(&self, id: &[u8; 32]) -> Result<(), Error> {
        self.db.remove(nk(id))?;
        Ok(())
    }

    pub fn get_live_net(&self, id: &[u8; 32]) -> Result<Option<NetworkRecord>, Error> {
        match self.load_net(id)? {
            None => Ok(None),
            Some(r) if !r.is_alive() => {
                self.del_net(id)?;
                Ok(None)
            }
            Some(r) => Ok(Some(r)),
        }
    }

    pub fn touch_net(&self, id: &[u8; 32]) -> Result<Vec<[u8; 32]>, Error> {
        if let Some(mut r) = self.get_live_net(id)? {
            r.touch();
            let members: Vec<[u8; 32]> = r.members.iter().map(|m| m.pubkey).collect();
            self.save_net(&r)?;
            return Ok(members);
        }
        Ok(vec![])
    }

    // ── Filter ───────────────────────────────────────────────────

    pub fn save_filter(&self, r: &FilterRecord) -> Result<(), Error> {
        self.db.insert(fk(&r.owner), bincode::serialize(r)?)?;
        Ok(())
    }

    pub fn load_filter(&self, owner: &[u8; 32]) -> Result<Option<FilterRecord>, Error> {
        Ok(match self.db.get(fk(owner))? {
            None => None,
            Some(v) => Some(bincode::deserialize(&v)?),
        })
    }

    pub fn del_filter(&self, owner: &[u8; 32]) -> Result<(), Error> {
        self.db.remove(fk(owner))?;
        Ok(())
    }

    /// Check whether a caller is allowed to spin owner.
    /// Returns true if no filter is set (off by default).
    pub fn spin_allowed(&self, owner: &[u8; 32], caller: &[u8; 32]) -> Result<bool, Error> {
        Ok(match self.load_filter(owner)? {
            None => true,
            Some(f) => f.allows_spin(caller),
        })
    }

    // ── GC ───────────────────────────────────────────────────────

    pub fn gc(&self) -> Result<usize, Error> {
        let mut del = Vec::new();
        for item in self.db.iter() {
            let (key, val) = item?;
            let ks = std::str::from_utf8(&key).unwrap_or("");
            let expired = if ks.starts_with("P:") {
                bincode::deserialize::<PeerRecord>(&val)
                    .map(|r| !r.is_alive())
                    .unwrap_or(false)
            } else if ks.starts_with("N:") {
                bincode::deserialize::<NetworkRecord>(&val)
                    .map(|r| !r.is_alive())
                    .unwrap_or(false)
            } else {
                false
            };
            if expired {
                del.push(key.to_vec());
            }
        }
        let n = del.len();
        for k in del {
            self.db.remove(k)?;
        }
        if n > 0 {
            let _ = self.db.flush();
        }
        Ok(n)
    }
}
