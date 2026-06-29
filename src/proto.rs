//! Spinneret wire protocol — plaintext layer (after decryption).

use crate::error::Error;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

// ── Command bytes ─────────────────────────────────────────────────
// Peer → Loom
pub const CMD_NAT: u8 = 0x00;
pub const CMD_CONAT: u8 = 0x01;
pub const CMD_LOGIN: u8 = 0x02;
pub const CMD_TANGLE: u8 = 0x03;
pub const CMD_SET_FILTER: u8 = 0x04;
pub const CMD_FILTER_INFO: u8 = 0x05;
pub const CMD_ADD_PEER_FILTER: u8 = 0x06;
pub const CMD_REMOVE_PEER_FILTER: u8 = 0x08; // 0x07 skipped for CMD_HOST_JOIN_RESP
pub const CMD_REGISTER_NETWORK: u8 = 0x09;
pub const CMD_NETWORK_INFO: u8 = 0x0A;
pub const CMD_GET_NET_PEER: u8 = 0x0B;
pub const CMD_TANGLE_NETWORK: u8 = 0x0C;
pub const CMD_JOIN_NETWORK: u8 = 0x0D;
pub const CMD_SPIN: u8 = 0x0E;

// Loom → Peer
pub const CMD_OK: u8 = 0xF0;
pub const CMD_ERR: u8 = 0xF1;
pub const CMD_PEER_INFO_RESP: u8 = 0xF2;
pub const CMD_NETWORK_INFO_RESP: u8 = 0xF3;
pub const CMD_FILTER_INFO_RESP: u8 = 0xF4;
pub const CMD_SPIN_NOTIFY: u8 = 0xF5;
pub const CMD_ASK_HOST_JOIN: u8 = 0xF6;
pub const CMD_HOST_JOIN_RESP: u8 = 0xF7;

// ── Error codes ───────────────────────────────────────────────────
pub const ERR_NOT_FOUND: u8 = 0x01;
pub const ERR_ALREADY_REG: u8 = 0x02;
pub const ERR_ALREADY_FILTER: u8 = 0x03;
pub const ERR_NOT_FILTER: u8 = 0x04;
pub const ERR_NO_FILTER: u8 = 0x05;
pub const ERR_BLOCKED: u8 = 0x06;
pub const ERR_NET_NOT_FOUND: u8 = 0x07;
pub const ERR_NET_EXISTS: u8 = 0x08;
pub const ERR_NOT_IN_NET: u8 = 0x09;
pub const ERR_JOIN_REFUSED: u8 = 0x0A;
pub const ERR_HOST_TIMEOUT: u8 = 0x0B;
pub const ERR_NOT_REG: u8 = 0x0C;
pub const ERR_UNKNOWN: u8 = 0xFF;

// ── Filter, NAT, Network enums ───────────────────────────────────
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[repr(u8)]
pub enum FilterMode {
    Off = 0x00,
    Whitelist = 0x01,
    Blacklist = 0x02,
}
impl FilterMode {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0x00 => Some(Self::Off),
            0x01 => Some(Self::Whitelist),
            0x02 => Some(Self::Blacklist),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[repr(u8)]
pub enum NatType {
    Fixed = 0x00,
    Variable = 0x01,
}
impl NatType {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0x00 => Some(Self::Fixed),
            0x01 => Some(Self::Variable),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[repr(u8)]
pub enum NetworkKind {
    Public = 0x00,
    Private = 0x01,
}
impl NetworkKind {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0x00 => Some(Self::Public),
            0x01 => Some(Self::Private),
            _ => None,
        }
    }
}

// ── PeerInfo ─────────────────────────────────────────────────────
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PeerInfo {
    pub pubkey: [u8; 32],
    pub global: StoredAddr,
    pub local: StoredAddr,
    pub nat: NatType,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct StoredAddr {
    pub ip: IpAddr,
    pub port: u16,
}
impl StoredAddr {
    pub fn from_socket(s: SocketAddr) -> Self {
        Self {
            ip: s.ip(),
            port: s.port(),
        }
    }
    pub fn to_socket(&self) -> SocketAddr {
        SocketAddr::new(self.ip, self.port)
    }
}
impl From<SocketAddr> for StoredAddr {
    fn from(s: SocketAddr) -> Self {
        Self::from_socket(s)
    }
}

// ── NetworkInfo ───────────────────────────────────────────────────
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct NetworkInfo {
    pub id: [u8; 32],
    pub kind: NetworkKind,
    pub host_pubkey: Option<[u8; 32]>,
    pub member_count: u32,
}

// ── FilterInfo ────────────────────────────────────────────────────
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct FilterInfo {
    pub mode: FilterMode,
    pub count: u32,
}

// ═══════════════════════════════════════════════════════════════
// Wire encoding helpers
// ═══════════════════════════════════════════════════════════════

pub fn enc_addr(addr: SocketAddr, buf: &mut Vec<u8>) {
    match addr.ip() {
        IpAddr::V4(v4) => {
            buf.push(4);
            buf.extend_from_slice(&v4.octets());
        }
        IpAddr::V6(v6) => {
            buf.push(6);
            buf.extend_from_slice(&v6.octets());
        }
    }
    buf.extend_from_slice(&addr.port().to_be_bytes());
}

pub fn dec_addr(buf: &[u8], off: usize) -> Result<(SocketAddr, usize), Error> {
    let fam = *buf.get(off).ok_or_else(|| pe("addr family"))?;
    match fam {
        4 => {
            if buf.len() < off + 7 {
                return Err(pe("IPv4 short"));
            }
            let ip = Ipv4Addr::new(buf[off + 1], buf[off + 2], buf[off + 3], buf[off + 4]);
            let port = u16::from_be_bytes([buf[off + 5], buf[off + 6]]);
            Ok((SocketAddr::new(IpAddr::V4(ip), port), off + 7))
        }
        6 => {
            if buf.len() < off + 19 {
                return Err(pe("IPv6 short"));
            }
            let mut o = [0u8; 16];
            o.copy_from_slice(&buf[off + 1..off + 17]);
            let port = u16::from_be_bytes([buf[off + 17], buf[off + 18]]);
            Ok((
                SocketAddr::new(IpAddr::V6(Ipv6Addr::from(o)), port),
                off + 19,
            ))
        }
        _ => Err(pe("bad addr family")),
    }
}

pub fn enc_peer(p: &PeerInfo, buf: &mut Vec<u8>) {
    buf.extend_from_slice(&p.pubkey);
    enc_addr(p.global.to_socket(), buf);
    enc_addr(p.local.to_socket(), buf);
    buf.push(p.nat as u8);
}

pub fn dec_peer(buf: &[u8], off: usize) -> Result<(PeerInfo, usize), Error> {
    if buf.len() < off + 32 {
        return Err(pe("peer pubkey short"));
    }
    let mut pk = [0u8; 32];
    pk.copy_from_slice(&buf[off..off + 32]);
    let (global, o1) = dec_addr(buf, off + 32)?;
    let (local, o2) = dec_addr(buf, o1)?;
    if buf.len() < o2 + 1 {
        return Err(pe("peer nat short"));
    }
    let nat = NatType::from_u8(buf[o2]).ok_or_else(|| pe("bad nat"))?;
    Ok((
        PeerInfo {
            pubkey: pk,
            global: StoredAddr::from_socket(global),
            local: StoredAddr::from_socket(local),
            nat,
        },
        o2 + 1,
    ))
}

fn pe(s: &str) -> Error {
    Error::Proto(s.to_string())
}

// ═══════════════════════════════════════════════════════════════
// Plaintext header
// ═══════════════════════════════════════════════════════════════

pub struct PlainHeader {
    pub timestamp: u64,
    pub validity_secs: u8,
}

impl PlainHeader {
    pub const LEN: usize = 9;

    pub fn encode_into(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(&self.timestamp.to_be_bytes());
        buf.push(self.validity_secs);
    }

    pub fn decode(raw: &[u8]) -> Result<(Self, usize), Error> {
        if raw.len() < Self::LEN {
            return Err(pe("header short"));
        }
        let ts = u64::from_be_bytes(raw[0..8].try_into().unwrap());
        let vs = raw[8];
        if vs == 0 || vs > 10 {
            return Err(Error::Proto(format!("bad validity {}", vs)));
        }
        Ok((
            Self {
                timestamp: ts,
                validity_secs: vs,
            },
            Self::LEN,
        ))
    }

    pub fn check_freshness(&self) -> Result<(), Error> {
        let now = unix_now();
        let age = now.saturating_sub(self.timestamp);
        if age > self.validity_secs as u64 {
            Err(Error::Expired)
        } else {
            Ok(())
        }
    }
}

// ═══════════════════════════════════════════════════════════════
// Command payloads
// ═══════════════════════════════════════════════════════════════

#[derive(Debug)]
pub enum Command {
    Nat {
        local: SocketAddr,
    },
    Conat {
        local: SocketAddr,
    },
    Login {
        info: PeerInfo,
    },
    Tangle,
    SetFilter {
        mode: FilterMode,
    },
    FilterInfo,
    AddPeerFilter {
        key: [u8; 32],
    },
    RemovePeerFilter {
        key: [u8; 32],
    },
    RegisterNetwork {
        id: [u8; 32],
        kind: NetworkKind,
    },
    NetworkInfo {
        id: [u8; 32],
    },
    GetNetPeer {
        net_id: [u8; 32],
        idx: u32,
    },
    TangleNetwork {
        id: [u8; 32],
    },
    JoinNetwork {
        id: [u8; 32],
    },
    Spin {
        target_key: [u8; 32],
    },
    HostJoinResp {
        net_id: [u8; 32],
        joiner_key: [u8; 32],
        approved: bool,
    },
}

impl Command {
    pub fn parse(raw: &[u8]) -> Result<Self, Error> {
        if raw.is_empty() {
            return Err(pe("empty cmd"));
        }
        let cmd = raw[0];
        let p = &raw[1..];

        match cmd {
            CMD_NAT => {
                let (local, _) = dec_addr(p, 0)?;
                Ok(Command::Nat { local })
            }
            CMD_CONAT => {
                let (local, _) = dec_addr(p, 0)?;
                Ok(Command::Conat { local })
            }
            CMD_LOGIN => {
                let (info, _) = dec_peer(p, 0)?;
                Ok(Command::Login { info })
            }
            CMD_TANGLE => Ok(Command::Tangle),
            CMD_FILTER_INFO => Ok(Command::FilterInfo),
            CMD_SET_FILTER => {
                let mode = FilterMode::from_u8(*p.first().ok_or_else(|| pe("SetFilter mode"))?)
                    .ok_or_else(|| pe("bad filter mode"))?;
                Ok(Command::SetFilter { mode })
            }
            CMD_ADD_PEER_FILTER | CMD_REMOVE_PEER_FILTER => {
                if p.len() < 32 {
                    return Err(pe("filter key short"));
                }
                let mut key = [0u8; 32];
                key.copy_from_slice(&p[..32]);
                if cmd == CMD_ADD_PEER_FILTER {
                    Ok(Command::AddPeerFilter { key })
                } else {
                    Ok(Command::RemovePeerFilter { key })
                }
            }
            CMD_REGISTER_NETWORK => {
                if p.len() < 33 {
                    return Err(pe("RegisterNetwork short"));
                }
                let mut id = [0u8; 32];
                id.copy_from_slice(&p[..32]);
                let kind = NetworkKind::from_u8(p[32]).ok_or_else(|| pe("bad net kind"))?;
                Ok(Command::RegisterNetwork { id, kind })
            }
            CMD_NETWORK_INFO => {
                if p.len() < 32 {
                    return Err(pe("NetworkInfo short"));
                }
                let mut id = [0u8; 32];
                id.copy_from_slice(&p[..32]);
                Ok(Command::NetworkInfo { id })
            }
            CMD_GET_NET_PEER => {
                if p.len() < 36 {
                    return Err(pe("GetNetPeer short"));
                }
                let mut net_id = [0u8; 32];
                net_id.copy_from_slice(&p[..32]);
                let idx = u32::from_be_bytes([p[32], p[33], p[34], p[35]]);
                Ok(Command::GetNetPeer { net_id, idx })
            }
            CMD_TANGLE_NETWORK => {
                if p.len() < 32 {
                    return Err(pe("TangleNetwork short"));
                }
                let mut id = [0u8; 32];
                id.copy_from_slice(&p[..32]);
                Ok(Command::TangleNetwork { id })
            }
            CMD_JOIN_NETWORK => {
                if p.len() < 32 {
                    return Err(pe("JoinNetwork short"));
                }
                let mut id = [0u8; 32];
                id.copy_from_slice(&p[..32]);
                Ok(Command::JoinNetwork { id })
            }
            CMD_SPIN => {
                if p.len() < 32 {
                    return Err(pe("Spin short"));
                }
                let mut key = [0u8; 32];
                key.copy_from_slice(&p[..32]);
                Ok(Command::Spin { target_key: key })
            }
            CMD_HOST_JOIN_RESP => {
                if p.len() < 65 {
                    return Err(pe("HostJoinResp short"));
                }
                let mut net_id = [0u8; 32];
                net_id.copy_from_slice(&p[..32]);
                let mut joiner_key = [0u8; 32];
                joiner_key.copy_from_slice(&p[32..64]);
                let approved = p[64] != 0;
                Ok(Command::HostJoinResp {
                    net_id,
                    joiner_key,
                    approved,
                })
            }
            _ => Err(pe(&format!("unknown cmd 0x{:02x}", cmd))),
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut b = Vec::new();
        match self {
            Command::Nat { local } => {
                b.push(CMD_NAT);
                enc_addr(*local, &mut b);
            }
            Command::Conat { local } => {
                b.push(CMD_CONAT);
                enc_addr(*local, &mut b);
            }
            Command::Login { info } => {
                b.push(CMD_LOGIN);
                enc_peer(info, &mut b);
            }
            Command::Tangle => b.push(CMD_TANGLE),
            Command::FilterInfo => b.push(CMD_FILTER_INFO),
            Command::SetFilter { mode } => {
                b.push(CMD_SET_FILTER);
                b.push(*mode as u8);
            }
            Command::AddPeerFilter { key } => {
                b.push(CMD_ADD_PEER_FILTER);
                b.extend_from_slice(key);
            }
            Command::RemovePeerFilter { key } => {
                b.push(CMD_REMOVE_PEER_FILTER);
                b.extend_from_slice(key);
            }
            Command::RegisterNetwork { id, kind } => {
                b.push(CMD_REGISTER_NETWORK);
                b.extend_from_slice(id);
                b.push(*kind as u8);
            }
            Command::NetworkInfo { id } => {
                b.push(CMD_NETWORK_INFO);
                b.extend_from_slice(id);
            }
            Command::GetNetPeer { net_id, idx } => {
                b.push(CMD_GET_NET_PEER);
                b.extend_from_slice(net_id);
                b.extend_from_slice(&idx.to_be_bytes());
            }
            Command::TangleNetwork { id } => {
                b.push(CMD_TANGLE_NETWORK);
                b.extend_from_slice(id);
            }
            Command::JoinNetwork { id } => {
                b.push(CMD_JOIN_NETWORK);
                b.extend_from_slice(id);
            }
            Command::Spin { target_key } => {
                b.push(CMD_SPIN);
                b.extend_from_slice(target_key);
            }
            Command::HostJoinResp {
                net_id,
                joiner_key,
                approved,
            } => {
                b.push(CMD_HOST_JOIN_RESP);
                b.extend_from_slice(net_id);
                b.extend_from_slice(joiner_key);
                b.push(if *approved { 1 } else { 0 });
            }
        }
        b
    }
}

// ═══════════════════════════════════════════════════════════════
// Responses
// ═══════════════════════════════════════════════════════════════

#[derive(Debug)]
pub enum Response {
    Ok,
    Err(u8),
    PeerInfo(PeerInfo),
    NetworkInfo(NetworkInfo),
    FilterInfo(FilterInfo),
    SpinNotify {
        caller: PeerInfo,
    },
    AskHostJoin {
        net_id: [u8; 32],
        joiner: PeerInfo,
    },
    HostJoinResp {
        net_id: [u8; 32],
        joiner_key: [u8; 32],
        approved: bool,
    },
}

impl Response {
    pub fn encode(&self) -> Vec<u8> {
        let mut b = Vec::new();
        match self {
            Response::Ok => b.push(CMD_OK),
            Response::Err(code) => {
                b.push(CMD_ERR);
                b.push(*code);
            }
            Response::PeerInfo(p) => {
                b.push(CMD_PEER_INFO_RESP);
                enc_peer(p, &mut b);
            }
            Response::NetworkInfo(n) => {
                b.push(CMD_NETWORK_INFO_RESP);
                b.extend_from_slice(&n.id);
                b.push(n.kind as u8);
                if let Some(hk) = &n.host_pubkey {
                    b.push(1);
                    b.extend_from_slice(hk);
                } else {
                    b.push(0);
                }
                b.extend_from_slice(&n.member_count.to_be_bytes());
            }
            Response::FilterInfo(f) => {
                b.push(CMD_FILTER_INFO_RESP);
                b.push(f.mode as u8);
                b.extend_from_slice(&f.count.to_be_bytes());
            }
            Response::SpinNotify { caller } => {
                b.push(CMD_SPIN_NOTIFY);
                enc_peer(caller, &mut b);
            }
            Response::AskHostJoin { net_id, joiner } => {
                b.push(CMD_ASK_HOST_JOIN);
                b.extend_from_slice(net_id);
                enc_peer(joiner, &mut b);
            }
            Response::HostJoinResp {
                net_id,
                joiner_key,
                approved,
            } => {
                b.push(CMD_HOST_JOIN_RESP);
                b.extend_from_slice(net_id);
                b.extend_from_slice(joiner_key);
                b.push(if *approved { 1 } else { 0 });
            }
        }
        b
    }

    pub fn parse(raw: &[u8]) -> Result<Self, Error> {
        if raw.is_empty() {
            return Err(pe("empty response"));
        }
        match raw[0] {
            CMD_OK => Ok(Response::Ok),
            CMD_ERR => Ok(Response::Err(*raw.get(1).unwrap_or(&ERR_UNKNOWN))),
            CMD_PEER_INFO_RESP => {
                let (info, _) = dec_peer(raw, 1)?;
                Ok(Response::PeerInfo(info))
            }
            CMD_NETWORK_INFO_RESP => {
                if raw.len() < 1 + 32 + 1 + 1 + 4 {
                    return Err(pe("NetworkInfoResp short"));
                }
                let mut id = [0u8; 32];
                id.copy_from_slice(&raw[1..33]);
                let kind = NetworkKind::from_u8(raw[33]).ok_or_else(|| pe("bad net kind"))?;
                let host_present = raw[34];
                let (host_pubkey, off) = if host_present != 0 {
                    if raw.len() < 35 + 32 {
                        return Err(pe("host key short"));
                    }
                    let mut hk = [0u8; 32];
                    hk.copy_from_slice(&raw[35..67]);
                    (Some(hk), 67usize)
                } else {
                    (None, 35usize)
                };
                if raw.len() < off + 4 {
                    return Err(pe("member_count short"));
                }
                let member_count = u32::from_be_bytes(raw[off..off + 4].try_into().unwrap());
                Ok(Response::NetworkInfo(NetworkInfo {
                    id,
                    kind,
                    host_pubkey,
                    member_count,
                }))
            }
            CMD_FILTER_INFO_RESP => {
                if raw.len() < 6 {
                    return Err(pe("FilterInfoResp short"));
                }
                let mode = FilterMode::from_u8(raw[1]).ok_or_else(|| pe("bad mode"))?;
                let count = u32::from_be_bytes(raw[2..6].try_into().unwrap());
                Ok(Response::FilterInfo(FilterInfo { mode, count }))
            }
            CMD_SPIN_NOTIFY => {
                let (caller, _) = dec_peer(raw, 1)?;
                Ok(Response::SpinNotify { caller })
            }
            CMD_ASK_HOST_JOIN => {
                if raw.len() < 33 {
                    return Err(pe("AskHostJoin short"));
                }
                let mut net_id = [0u8; 32];
                net_id.copy_from_slice(&raw[1..33]);
                let (joiner, _) = dec_peer(raw, 33)?;
                Ok(Response::AskHostJoin { net_id, joiner })
            }
            CMD_HOST_JOIN_RESP => {
                if raw.len() < 66 {
                    return Err(pe("HostJoinResp short"));
                }
                let mut net_id = [0u8; 32];
                net_id.copy_from_slice(&raw[1..33]);
                let mut joiner_key = [0u8; 32];
                joiner_key.copy_from_slice(&raw[33..65]);
                Ok(Response::HostJoinResp {
                    net_id,
                    joiner_key,
                    approved: raw[65] != 0,
                })
            }
            _ => Err(pe(&format!("unknown response 0x{:02x}", raw[0]))),
        }
    }
}

pub fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
