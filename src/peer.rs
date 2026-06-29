use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, oneshot, Mutex, RwLock};
use tokio::time::{sleep, timeout, Duration, Instant};
use tracing::{info, warn};

use crate::crypto::{open, random_nonce, seal, KeyPair, NONCE_LEN};
use crate::error::Error;
use crate::loom::{LOOM_PORT_1, LOOM_PORT_2};
use crate::proto::{
    unix_now, Command, FilterMode, NatType, NetworkKind, PeerInfo, PlainHeader, Response,
    ERR_BLOCKED, ERR_NOT_FOUND,
};

const MAX_DGRAM: usize = 1400;
const RPC_TIMEOUT_MS: u64 = 15_000;
const RPC_RETRIES: usize = 3;
const RPC_RETRY_DELAY_MS: u64 = 500;
const SILK_TIMEOUT_SECS: u64 = 15;
const ENTANGLE_IDLE_SECS: u64 = 30;
const NAT_RETRIES: usize = 3;
const NAT_RETRY_DELAY_MS: u64 = 500;
const VAR_EXTRA_SOCKS: usize = 100;
const VAR_PORT_RANGE: u16 = 50;
const POST_PUNCH_BLAST_MS: u64 = 3_000;
const PKT_VALIDITY: u8 = 5;
const MAX_SPIN_INBOX: usize = 1024;
const MAX_HOST_JOIN_INBOX: usize = 1024;
const PUNCH_DIRECT_TIMEOUT_SECS: u64 = 10;
const PUNCH_RETRIES: usize = 2;
const PUNCH_RETRY_DELAY_MS: u64 = 200;

// ─────────────────────────────────────────────────────────────────
// Silk — live P2P connection
// ─────────────────────────────────────────────────────────────────

pub struct Silk {
    pub remote_addr: SocketAddr,
    pub remote_info: PeerInfo,
    sock: Arc<UdpSocket>,
    rx: Mutex<mpsc::Receiver<Vec<u8>>>,
    last_activity: Mutex<Instant>,
}

impl Silk {
    pub async fn send(&self, data: &[u8]) -> Result<(), Error> {
        let mut pkt = vec![0xDA_u8];
        pkt.extend_from_slice(&(data.len() as u16).to_be_bytes());
        pkt.extend_from_slice(data);
        self.sock.send_to(&pkt, self.remote_addr).await?;
        *self.last_activity.lock().await = Instant::now();
        Ok(())
    }

    pub async fn recv(&self) -> Result<Vec<u8>, Error> {
        let d = self.rx.lock().await.recv().await.ok_or(Error::SilkFailed)?;
        *self.last_activity.lock().await = Instant::now();
        Ok(d)
    }

    pub async fn try_recv(&self) -> Option<Vec<u8>> {
        let d = self.rx.lock().await.try_recv().ok()?;
        *self.last_activity.lock().await = Instant::now();
        Some(d)
    }

    pub async fn idle_secs(&self) -> u64 {
        self.last_activity.lock().await.elapsed().as_secs()
    }
}

// ─────────────────────────────────────────────────────────────────
// Silk registry
// ─────────────────────────────────────────────────────────────────

pub struct SilkRegistry {
    by_addr: RwLock<HashMap<SocketAddr, Arc<Silk>>>,
    data_txs: RwLock<HashMap<SocketAddr, mpsc::Sender<Vec<u8>>>>,
}

impl SilkRegistry {
    fn new() -> Self {
        Self {
            by_addr: RwLock::new(HashMap::new()),
            data_txs: RwLock::new(HashMap::new()),
        }
    }

    async fn insert(&self, silk: Arc<Silk>, tx: mpsc::Sender<Vec<u8>>) {
        let addr = silk.remote_addr;
        self.by_addr.write().await.insert(addr, silk);
        self.data_txs.write().await.insert(addr, tx);
    }

    pub async fn get(&self, addr: SocketAddr) -> Option<Arc<Silk>> {
        self.by_addr.read().await.get(&addr).cloned()
    }

    pub async fn remove(&self, addr: SocketAddr) {
        self.by_addr.write().await.remove(&addr);
        self.data_txs.write().await.remove(&addr);
    }

    pub async fn deliver(&self, addr: SocketAddr, data: Vec<u8>) {
        let tx = self.data_txs.read().await.get(&addr).cloned();
        if let Some(tx) = tx {
            if let Some(silk) = self.get(addr).await {
                *silk.last_activity.lock().await = Instant::now();
            }
            let _ = tx.send(data).await;
        }
    }

    pub async fn all(&self) -> Vec<(SocketAddr, Arc<Silk>)> {
        self.by_addr
            .read()
            .await
            .iter()
            .map(|(a, s)| (*a, Arc::clone(s)))
            .collect()
    }
}

// ─────────────────────────────────────────────────────────────────
// Internal state
// ─────────────────────────────────────────────────────────────────

type ReplyTx = oneshot::Sender<Response>;

struct PeerState {
    waiters: HashMap<[u8; NONCE_LEN], ReplyTx>,
    spin_inbox: Vec<PeerInfo>,
    host_join_inbox: Vec<([u8; 32], PeerInfo)>,
    my_info: Option<PeerInfo>,
    nat_type: NatType,
    local_addr: Option<SocketAddr>,
    // Auto-accept fields
    auto_accept: bool,
    auto_silk_tx: Option<mpsc::Sender<Arc<Silk>>>,
    auto_accept_task: Option<tokio::task::JoinHandle<()>>,
}

impl PeerState {
    fn new() -> Self {
        Self {
            waiters: HashMap::new(),
            spin_inbox: Vec::new(),
            host_join_inbox: Vec::new(),
            my_info: None,
            nat_type: NatType::Variable,
            local_addr: None,
            auto_accept: false,
            auto_silk_tx: None,
            auto_accept_task: None,
        }
    }
}

// ─────────────────────────────────────────────────────────────────
// Peer
// ─────────────────────────────────────────────────────────────────
#[derive(Clone)]
pub struct Peer {
    keypair: KeyPair,
    sock: Arc<UdpSocket>,
    loom_p1: SocketAddr,
    loom_p2: SocketAddr,
    loom_pub: [u8; 32],
    state: Arc<RwLock<PeerState>>,
    pub silks: Arc<SilkRegistry>,
}

impl Peer {
    pub async fn new(keypair: KeyPair, loom_ip: IpAddr, loom_pub: [u8; 32]) -> Result<Self, Error> {
        Self::with_ports(keypair, loom_ip, LOOM_PORT_1, LOOM_PORT_2, loom_pub).await
    }

    pub async fn with_ports(
        keypair: KeyPair,
        loom_ip: IpAddr,
        p1: u16,
        p2: u16,
        loom_pub: [u8; 32],
    ) -> Result<Self, Error> {
        let sock = Arc::new(UdpSocket::bind("0.0.0.0:0").await?);
        let state = Arc::new(RwLock::new(PeerState::new()));
        let silks = Arc::new(SilkRegistry::new());
        let loom_p1 = SocketAddr::new(loom_ip, p1);
        let loom_p2 = SocketAddr::new(loom_ip, p2);

        let peer = Self {
            keypair,
            sock,
            loom_p1,
            loom_p2,
            loom_pub,
            state,
            silks,
        };
        peer.spawn_recv();
        Ok(peer)
    }

    pub fn public_key(&self) -> &[u8; 32] {
        &self.keypair.public
    }

    // ── Background receive loop ───────────────────────────────────

    fn spawn_recv(&self) {
        let sock = Arc::clone(&self.sock);
        let state = Arc::clone(&self.state);
        let silks = Arc::clone(&self.silks);
        let kp = self.keypair.clone();

        tokio::spawn(async move {
            let mut buf = [0u8; MAX_DGRAM];
            loop {
                let (len, from) = match sock.recv_from(&mut buf).await {
                    Ok(r) => r,
                    Err(e) => {
                        warn!("peer recv: {}", e);
                        break;
                    }
                };
                let raw = buf[..len].to_vec();
                if raw.is_empty() {
                    continue;
                }

                if raw[0] == 0xDA {
                    if raw.len() >= 3 {
                        let dlen = u16::from_be_bytes([raw[1], raw[2]]) as usize;
                        if raw.len() >= 3 + dlen {
                            silks.deliver(from, raw[3..3 + dlen].to_vec()).await;
                        }
                    }
                    continue;
                }

                if raw.len() == 1 && raw[0] == 0xEB {
                    let _ = sock.send_to(&[0xEC], from).await;
                    if let Some(silk) = silks.get(from).await {
                        *silk.last_activity.lock().await = Instant::now();
                    }
                    continue;
                }
                if raw.len() == 1 && raw[0] == 0xEC {
                    if let Some(silk) = silks.get(from).await {
                        *silk.last_activity.lock().await = Instant::now();
                    }
                    continue;
                }

                let mut raw_owned = raw;
                let (_sender_pub, nonce, plaintext) = match open(&kp, &mut raw_owned) {
                    Ok(r) => r,
                    Err(_) => {
                        warn!("decrypt failed from {}", from);
                        continue;
                    }
                };

                let (hdr, hdr_len) = match PlainHeader::decode(plaintext) {
                    Ok(r) => r,
                    Err(_) => continue,
                };
                if hdr.check_freshness().is_err() {
                    continue;
                }

                let body = &plaintext[hdr_len..];
                if body.is_empty() {
                    continue;
                }

                let resp = match Response::parse(body) {
                    Ok(r) => r,
                    Err(_) => continue,
                };

                match resp {
                    Response::SpinNotify { caller } => {
                        let mut s = state.write().await;
                        if s.spin_inbox.len() < MAX_SPIN_INBOX {
                            s.spin_inbox.push(caller);
                        } else {
                            warn!("spin_inbox full, dropping oldest");
                            s.spin_inbox.remove(0);
                            s.spin_inbox.push(caller);
                        }
                    }
                    Response::AskHostJoin { net_id, joiner } => {
                        let mut s = state.write().await;
                        if s.host_join_inbox.len() < MAX_HOST_JOIN_INBOX {
                            s.host_join_inbox.push((net_id, joiner));
                        } else {
                            warn!("host_join_inbox full, dropping oldest");
                            s.host_join_inbox.remove(0);
                            s.host_join_inbox.push((net_id, joiner));
                        }
                    }
                    other => {
                        let tx = state.write().await.waiters.remove(&nonce);
                        if let Some(tx) = tx {
                            let _ = tx.send(other);
                        }
                    }
                }
            }
        });
    }

    // ── RPC with retries ───────────────────────────────────────────

    async fn rpc(&self, cmd: Command, ms: u64) -> Result<Response, Error> {
        let mut last_err = Error::Timeout;
        for attempt in 0..RPC_RETRIES {
            if attempt > 0 {
                let delay = Duration::from_millis(RPC_RETRY_DELAY_MS * (1 << (attempt - 1)));
                sleep(delay).await;
                info!("RPC retry attempt {}", attempt + 1);
            }
            match self.rpc_once(&cmd, ms).await {
                Ok(resp) => return Ok(resp),
                Err(e) => {
                    last_err = e;
                    if !matches!(last_err, Error::Timeout) {
                        break;
                    }
                }
            }
        }
        Err(last_err)
    }

    async fn rpc_once(&self, cmd: &Command, ms: u64) -> Result<Response, Error> {
        let nonce = random_nonce();
        let (tx, rx) = oneshot::channel::<Response>();
        self.state.write().await.waiters.insert(nonce, tx);

        let pkt = self.build_pkt(cmd, &nonce)?;
        self.sock.send_to(&pkt, self.loom_p1).await?;

        match timeout(Duration::from_millis(ms), rx).await {
            Ok(Ok(r)) => Ok(r),
            _ => {
                self.state.write().await.waiters.remove(&nonce);
                Err(Error::Timeout)
            }
        }
    }

    // ── Packet building ─────────────────────────────────────────────

    fn build_pkt_with_ts(
        &self,
        cmd: &Command,
        nonce: &[u8; NONCE_LEN],
        ts: u64,
    ) -> Result<Vec<u8>, Error> {
        let hdr = PlainHeader {
            timestamp: ts,
            validity_secs: PKT_VALIDITY,
        };
        let mut body = Vec::new();
        hdr.encode_into(&mut body);
        body.extend_from_slice(&cmd.encode());
        seal(&self.keypair, &self.loom_pub, nonce, &body)
    }

    fn build_pkt(&self, cmd: &Command, nonce: &[u8; NONCE_LEN]) -> Result<Vec<u8>, Error> {
        self.build_pkt_with_ts(cmd, nonce, unix_now())
    }

    // ── Helper to send fire‑and‑forget with retries ──────────────

    async fn send_with_retries(&self, cmd: &Command, to: SocketAddr) -> Result<(), Error> {
        let nonce = random_nonce();
        let pkt = self.build_pkt(cmd, &nonce)?;
        let mut last_err = Error::Timeout;
        for attempt in 0..RPC_RETRIES {
            if attempt > 0 {
                sleep(Duration::from_millis(
                    RPC_RETRY_DELAY_MS * (1 << (attempt - 1)),
                ))
                .await;
            }
            match self.sock.send_to(&pkt, to).await {
                Ok(_) => return Ok(()),
                Err(e) => last_err = e.into(),
            }
        }
        Err(last_err)
    }

    // ── PUBLIC API ─────────────────────────────────────────────────

    pub async fn nat(&self) -> Result<PeerInfo, Error> {
        let mut last_error = Error::Timeout;
        for attempt in 0..NAT_RETRIES {
            if attempt > 0 {
                let delay = Duration::from_millis(NAT_RETRY_DELAY_MS * (1 << (attempt - 1)));
                sleep(delay).await;
                info!("NAT retry attempt {}", attempt + 1);
            }
            match self.nat_once().await {
                Ok(info) => return Ok(info),
                Err(e) => {
                    last_error = e;
                    if !matches!(last_error, Error::Timeout) {
                        break;
                    }
                }
            }
        }
        Err(last_error)
    }

    async fn nat_once(&self) -> Result<PeerInfo, Error> {
        let local = self
            .local_addr()
            .await
            .unwrap_or_else(|| "0.0.0.0:0".parse().unwrap());

        let cmd1 = Command::Nat { local };
        let cmd2 = Command::Conat { local };
        let ts = unix_now();

        let n1 = random_nonce();
        let n2 = random_nonce();

        let (tx1, rx1) = oneshot::channel();
        let (tx2, rx2) = oneshot::channel();
        {
            let mut s = self.state.write().await;
            s.waiters.insert(n1, tx1);
            s.waiters.insert(n2, tx2);
        }

        let pkt1 = self.build_pkt_with_ts(&cmd1, &n1, ts)?;
        let pkt2 = self.build_pkt_with_ts(&cmd2, &n2, ts)?;

        info!(
            "Sending NAT to {} (pubkey={:?})",
            self.loom_p1,
            hex_encode(&self.keypair.public[..4])
        );
        info!(
            "Sending CONAT to {} (pubkey={:?})",
            self.loom_p2,
            hex_encode(&self.keypair.public[..4])
        );

        self.sock.send_to(&pkt1, self.loom_p1).await?;
        self.sock.send_to(&pkt2, self.loom_p2).await?;

        let timeout_dur = Duration::from_millis(RPC_TIMEOUT_MS);
        let resp = tokio::select! {
            r = rx1 => r.ok(),
            r = rx2 => r.ok(),
            _ = tokio::time::sleep(timeout_dur) => None,
        };
        {
            let mut s = self.state.write().await;
            s.waiters.remove(&n1);
            s.waiters.remove(&n2);
        }

        match resp {
            Some(Response::PeerInfo(info)) => {
                let mut s = self.state.write().await;
                s.my_info = Some(info.clone());
                s.nat_type = info.nat;
                s.local_addr = Some(local);
                Ok(info)
            }
            Some(Response::Err(e)) => Err(loom_err(e)),
            _ => Err(Error::Timeout),
        }
    }

    pub async fn login(&self, info: PeerInfo) -> Result<(), Error> {
        {
            let mut s = self.state.write().await;
            s.nat_type = info.nat;
            s.my_info = Some(info.clone());
        }
        match self.rpc(Command::Login { info }, RPC_TIMEOUT_MS).await? {
            Response::Ok => Ok(()),
            Response::Err(e) => Err(loom_err(e)),
            _ => Err(Error::Proto("unexpected Login response".into())),
        }
    }

    pub async fn register(&self) -> Result<PeerInfo, Error> {
        let info = self.nat().await?;
        self.login(info.clone()).await?;
        Ok(info)
    }

    pub async fn tangle(&self) -> Result<(), Error> {
        match self.rpc(Command::Tangle, RPC_TIMEOUT_MS).await? {
            Response::Ok => Ok(()),
            Response::Err(e) => Err(loom_err(e)),
            _ => Err(Error::Proto("unexpected Tangle response".into())),
        }
    }

    pub async fn set_filter(&self, mode: FilterMode) -> Result<(), Error> {
        match self
            .rpc(Command::SetFilter { mode }, RPC_TIMEOUT_MS)
            .await?
        {
            Response::Ok => Ok(()),
            Response::Err(e) => Err(loom_err(e)),
            _ => Err(Error::Proto("unexpected SetFilter response".into())),
        }
    }

    pub async fn filter_info(&self) -> Result<crate::proto::FilterInfo, Error> {
        match self.rpc(Command::FilterInfo, RPC_TIMEOUT_MS).await? {
            Response::FilterInfo(f) => Ok(f),
            Response::Err(e) => Err(loom_err(e)),
            _ => Err(Error::Proto("unexpected FilterInfo response".into())),
        }
    }

    pub async fn add_peer_filter(&self, key: [u8; 32]) -> Result<(), Error> {
        match self
            .rpc(Command::AddPeerFilter { key }, RPC_TIMEOUT_MS)
            .await?
        {
            Response::Ok => Ok(()),
            Response::Err(e) => Err(loom_err(e)),
            _ => Err(Error::Proto("unexpected AddPeerFilter response".into())),
        }
    }

    pub async fn remove_peer_filter(&self, key: [u8; 32]) -> Result<(), Error> {
        match self
            .rpc(Command::RemovePeerFilter { key }, RPC_TIMEOUT_MS)
            .await?
        {
            Response::Ok => Ok(()),
            Response::Err(e) => Err(loom_err(e)),
            _ => Err(Error::Proto("unexpected RemovePeerFilter response".into())),
        }
    }

    pub async fn register_network(&self, id: [u8; 32], kind: NetworkKind) -> Result<(), Error> {
        match self
            .rpc(Command::RegisterNetwork { id, kind }, RPC_TIMEOUT_MS)
            .await?
        {
            Response::Ok => Ok(()),
            Response::Err(e) => Err(loom_err(e)),
            _ => Err(Error::Proto("unexpected RegisterNetwork response".into())),
        }
    }

    pub async fn network_info(&self, id: [u8; 32]) -> Result<crate::proto::NetworkInfo, Error> {
        match self
            .rpc(Command::NetworkInfo { id }, RPC_TIMEOUT_MS)
            .await?
        {
            Response::NetworkInfo(n) => Ok(n),
            Response::Err(e) => Err(loom_err(e)),
            _ => Err(Error::Proto("unexpected NetworkInfo response".into())),
        }
    }

    pub async fn get_net_peer(&self, net_id: [u8; 32], idx: u32) -> Result<PeerInfo, Error> {
        match self
            .rpc(Command::GetNetPeer { net_id, idx }, RPC_TIMEOUT_MS)
            .await?
        {
            Response::PeerInfo(p) => Ok(p),
            Response::Err(e) => Err(loom_err(e)),
            _ => Err(Error::Proto("unexpected GetNetPeer response".into())),
        }
    }

    pub async fn tangle_network(&self, id: [u8; 32]) -> Result<(), Error> {
        match self
            .rpc(Command::TangleNetwork { id }, RPC_TIMEOUT_MS)
            .await?
        {
            Response::Ok => Ok(()),
            Response::Err(e) => Err(loom_err(e)),
            _ => Err(Error::Proto("unexpected TangleNetwork response".into())),
        }
    }

    pub async fn join_network(&self, id: [u8; 32]) -> Result<(), Error> {
        match self
            .rpc(Command::JoinNetwork { id }, RPC_TIMEOUT_MS + 6_000)
            .await?
        {
            Response::Ok => Ok(()),
            Response::Err(e) => Err(loom_err(e)),
            _ => Err(Error::Proto("unexpected JoinNetwork response".into())),
        }
    }

    pub async fn spin(&self, target_key: [u8; 32]) -> Result<Arc<Silk>, Error> {
        match self
            .rpc(Command::Spin { target_key }, RPC_TIMEOUT_MS)
            .await?
        {
            Response::PeerInfo(remote) => self.make_silk(remote).await,
            Response::Err(code) if code == ERR_BLOCKED => Err(Error::Blocked),
            Response::Err(code) if code == ERR_NOT_FOUND => Err(Error::NotFound),
            Response::Err(e) => Err(loom_err(e)),
            _ => Err(Error::Proto("unexpected Spin response".into())),
        }
    }

    pub async fn next_spin(&self) -> Option<PeerInfo> {
        self.state.write().await.spin_inbox.pop()
    }

    pub async fn accept(&self, caller: PeerInfo) -> Result<Arc<Silk>, Error> {
        self.make_silk(caller).await
    }

    pub async fn next_host_join_request(&self) -> Option<([u8; 32], PeerInfo)> {
        self.state.write().await.host_join_inbox.pop()
    }

    pub async fn reply_join_request(
        &self,
        net_id: [u8; 32],
        joiner_key: [u8; 32],
        approved: bool,
    ) -> Result<(), Error> {
        let cmd = Command::HostJoinResp {
            net_id,
            joiner_key,
            approved,
        };
        self.send_with_retries(&cmd, self.loom_p1).await
    }

    // ── Auto-accept methods ──────────────────────────────────────

    /// Enable auto-accept: all incoming spins are automatically accepted,
    /// and the resulting Silks are sent to the returned receiver channel.
    pub async fn enable_auto_accept(&self) -> mpsc::Receiver<Arc<Silk>> {
        let (tx, rx) = mpsc::channel(64);
        let mut state = self.state.write().await;
        state.auto_silk_tx = Some(tx);
        state.auto_accept = true;

        // Spawn a task to poll and accept spins
        let peer = self.clone();
        let task = tokio::spawn(async move {
            loop {
                // Check if auto-accept is still enabled
                {
                    let s = peer.state.read().await;
                    if !s.auto_accept {
                        break;
                    }
                }
                if let Some(caller) = peer.next_spin().await {
                    match peer.accept(caller).await {
                        Ok(silk) => {
                            let tx = {
                                let s = peer.state.read().await;
                                s.auto_silk_tx.clone()
                            };
                            if let Some(tx) = tx {
                                let _ = tx.send(silk).await;
                            }
                        }
                        Err(e) => {
                            warn!("auto-accept failed: {}", e);
                        }
                    }
                }
                // Small delay to avoid busy-looping
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        });
        state.auto_accept_task = Some(task);
        drop(state); // release lock
        rx
    }

    /// Disable auto-accept.
    pub async fn disable_auto_accept(&self) {
        let mut state = self.state.write().await;
        state.auto_accept = false;
        if let Some(task) = state.auto_accept_task.take() {
            task.abort();
        }
        state.auto_silk_tx = None;
    }

    // ─────────────────────────────────────────────────────────────
    // SILK HOLE PUNCH (with retries)
    // ─────────────────────────────────────────────────────────────

    pub async fn make_silk(&self, remote: PeerInfo) -> Result<Arc<Silk>, Error> {
        let mut last_err = Error::SilkFailed;
        for attempt in 0..PUNCH_RETRIES {
            if attempt > 0 {
                let delay = Duration::from_millis(PUNCH_RETRY_DELAY_MS * (1 << (attempt - 1)));
                sleep(delay).await;
                info!("Hole punch retry attempt {}", attempt + 1);
            }
            match self.make_silk_once(&remote).await {
                Ok(silk) => return Ok(silk),
                Err(e) => {
                    last_err = e;
                    if !matches!(last_err, Error::Timeout | Error::SilkFailed) {
                        break;
                    }
                }
            }
        }
        Err(last_err)
    }

    async fn make_silk_once(&self, remote: &PeerInfo) -> Result<Arc<Silk>, Error> {
        let my_nat = self.state.read().await.nat_type;
        let remote_nat = remote.nat;
        let my_global = self
            .state
            .read()
            .await
            .my_info
            .as_ref()
            .map(|i| i.global.to_socket());
        let remote_global = remote.global.to_socket();
        let remote_local = remote.local.to_socket();

        // ── Same‑router optimisation: try local and global concurrently ──
        if let Some(mg) = my_global {
            // if mg.ip() == remote_global.ip() {
            //     info!("same router detected — trying local and global concurrently");
            //     let local_fut = self.punch_direct(remote_local, remote);
            //     let global_fut = self.punch_direct(remote_global, remote);
            //     tokio::select! {
            //         Ok(silk) = local_fut => {
            //             info!("local punch succeeded");
            //             return Ok(silk);
            //         }
            //         Ok(silk) = global_fut => {
            //             info!("global punch succeeded (local failed)");
            //             return Ok(silk);
            //         }
            //         _ = tokio::time::sleep(Duration::from_secs(PUNCH_DIRECT_TIMEOUT_SECS)) => {
            //             // Both timed out
            //             info!("local and global direct punches timed out");
            //             return Err(Error::SilkFailed);
            //         }
            //     }
            // }
            if mg.ip() == remote_global.ip() {
                info!("same router detected — trying local addr");
                return self.punch_direct(remote_local, remote).await;
            }
        }

        // ── Standard strategies (global) ────────────────────────────
        match (my_nat, remote_nat) {
            (NatType::Fixed, NatType::Fixed) => self.punch_fixed_fixed(remote_global, remote).await,
            (NatType::Fixed, NatType::Variable) => {
                self.punch_fixed_side(remote_global, remote).await
            }
            (NatType::Variable, NatType::Fixed) => {
                self.punch_variable_side(remote_global, remote).await
            }
            (NatType::Variable, NatType::Variable) => {
                self.punch_variable_variable(remote_global, remote).await
            }
        }
    }

    // ── Punch implementations ───────────────────────────────────────

    fn make_entangle_pkt() -> Vec<u8> {
        vec![0xEB]
    }

    fn make_silk_obj(
        sock: Arc<UdpSocket>,
        remote_addr: SocketAddr,
        remote: PeerInfo,
        rx: mpsc::Receiver<Vec<u8>>,
    ) -> Silk {
        Silk {
            remote_addr,
            remote_info: remote,
            sock,
            rx: Mutex::new(rx),
            last_activity: Mutex::new(Instant::now()),
        }
    }

    async fn finish_silk(
        &self,
        remote_addr: SocketAddr,
        remote: PeerInfo,
        sock: Arc<UdpSocket>,
    ) -> Arc<Silk> {
        let (data_tx, data_rx) = mpsc::channel::<Vec<u8>>(256);
        let silk = Arc::new(Self::make_silk_obj(
            Arc::clone(&sock),
            remote_addr,
            remote,
            data_rx,
        ));
        self.silks.insert(Arc::clone(&silk), data_tx).await;

        let sock_b = Arc::clone(&sock);
        let pkt = Self::make_entangle_pkt();
        tokio::spawn(async move {
            let deadline = Instant::now() + Duration::from_millis(POST_PUNCH_BLAST_MS);
            while Instant::now() < deadline {
                sock_b.send_to(&pkt, remote_addr).await.ok();
                sleep(Duration::from_millis(50)).await;
            }
        });

        let sock_ka = Arc::clone(&sock);
        let silks_ka = Arc::clone(&self.silks);
        tokio::spawn(async move {
            loop {
                sleep(Duration::from_secs(ENTANGLE_IDLE_SECS)).await;
                let alive = silks_ka.get(remote_addr).await.is_some();
                if !alive {
                    break;
                }
                if let Some(s) = silks_ka.get(remote_addr).await {
                    if s.idle_secs().await >= ENTANGLE_IDLE_SECS
                        && sock_ka
                            .send_to(&Self::make_entangle_pkt(), remote_addr)
                            .await
                            .is_err()
                    {
                        break;
                    }
                }
            }
        });

        silk
    }

    async fn punch_direct(&self, addr: SocketAddr, remote: &PeerInfo) -> Result<Arc<Silk>, Error> {
        let pkt = Self::make_entangle_pkt();
        let deadline = Instant::now() + Duration::from_secs(PUNCH_DIRECT_TIMEOUT_SECS);
        let mut buf = [0u8; MAX_DGRAM];
        loop {
            self.sock.send_to(&pkt, addr).await.ok();
            if let Ok(Ok((_, from))) =
                timeout(Duration::from_millis(200), self.sock.recv_from(&mut buf)).await
            {
                if from == addr {
                    return Ok(self
                        .finish_silk(addr, remote.clone(), Arc::clone(&self.sock))
                        .await);
                }
            }
            if Instant::now() >= deadline {
                break;
            }
        }
        Err(Error::SilkFailed)
    }

    async fn punch_fixed_fixed(
        &self,
        remote: SocketAddr,
        remote_info: &PeerInfo,
    ) -> Result<Arc<Silk>, Error> {
        info!("punch Fixed↔Fixed → {}", remote);
        let pkt = Self::make_entangle_pkt();
        let deadline = Instant::now() + Duration::from_secs(SILK_TIMEOUT_SECS);
        let mut buf = [0u8; MAX_DGRAM];
        loop {
            self.sock.send_to(&pkt, remote).await.ok();
            if let Ok(Ok((_, from))) =
                timeout(Duration::from_millis(50), self.sock.recv_from(&mut buf)).await
            {
                if from.ip() == remote.ip() {
                    return Ok(self
                        .finish_silk(from, remote_info.clone(), Arc::clone(&self.sock))
                        .await);
                }
            }
            if Instant::now() >= deadline {
                return Err(Error::SilkFailed);
            }
        }
    }

    async fn punch_fixed_side(
        &self,
        remote: SocketAddr,
        remote_info: &PeerInfo,
    ) -> Result<Arc<Silk>, Error> {
        info!(
            "punch Fixed→Variable: spray ±{} ports around {}",
            VAR_PORT_RANGE, remote
        );
        let pkt = Self::make_entangle_pkt();
        let base = remote.port() as i32;
        let deadline = Instant::now() + Duration::from_secs(SILK_TIMEOUT_SECS);
        let mut buf = [0u8; MAX_DGRAM];

        loop {
            for delta in -(VAR_PORT_RANGE as i32)..=(VAR_PORT_RANGE as i32) {
                let port = (base + delta).clamp(1024, 65535) as u16;
                self.sock
                    .send_to(&pkt, SocketAddr::new(remote.ip(), port))
                    .await
                    .ok();
            }
            if let Ok(Ok((_, from))) =
                timeout(Duration::from_millis(100), self.sock.recv_from(&mut buf)).await
            {
                if from.ip() == remote.ip() {
                    return Ok(self
                        .finish_silk(from, remote_info.clone(), Arc::clone(&self.sock))
                        .await);
                }
            }
            if Instant::now() >= deadline {
                return Err(Error::SilkFailed);
            }
        }
    }

    async fn punch_variable_side(
        &self,
        remote: SocketAddr,
        remote_info: &PeerInfo,
    ) -> Result<Arc<Silk>, Error> {
        info!(
            "punch Variable→Fixed: open {} sockets → {}",
            VAR_EXTRA_SOCKS, remote
        );
        let pkt = Self::make_entangle_pkt();

        let mut extras: Vec<Arc<UdpSocket>> = Vec::new();
        for _ in 0..VAR_EXTRA_SOCKS {
            if let Ok(s) = UdpSocket::bind("0.0.0.0:0").await {
                extras.push(Arc::new(s));
            }
        }

        let deadline = Instant::now() + Duration::from_secs(SILK_TIMEOUT_SECS);
        let mut buf = [0u8; MAX_DGRAM];

        loop {
            for s in &extras {
                s.send_to(&pkt, remote).await.ok();
            }
            self.sock.send_to(&pkt, remote).await.ok();

            if let Ok(Ok((_, from))) =
                timeout(Duration::from_millis(100), self.sock.recv_from(&mut buf)).await
            {
                if from.ip() == remote.ip() {
                    return Ok(self
                        .finish_silk(from, remote_info.clone(), Arc::clone(&self.sock))
                        .await);
                }
            }

            for s in &extras {
                let mut b2 = [0u8; MAX_DGRAM];
                if let Ok(Ok((_, from))) =
                    timeout(Duration::from_millis(10), s.recv_from(&mut b2)).await
                {
                    if from.ip() == remote.ip() {
                        let arc_s = Arc::clone(s);
                        return Ok(self.finish_silk(from, remote_info.clone(), arc_s).await);
                    }
                }
            }

            if Instant::now() >= deadline {
                return Err(Error::SilkFailed);
            }
        }
    }

    async fn punch_variable_variable(
        &self,
        remote: SocketAddr,
        remote_info: &PeerInfo,
    ) -> Result<Arc<Silk>, Error> {
        info!(
            "punch Variable↔Variable: {} sockets × ±{} ports",
            VAR_EXTRA_SOCKS, VAR_PORT_RANGE
        );
        let pkt = Self::make_entangle_pkt();
        let base = remote.port() as i32;

        let mut extras: Vec<Arc<UdpSocket>> = Vec::new();
        for _ in 0..VAR_EXTRA_SOCKS {
            if let Ok(s) = UdpSocket::bind("0.0.0.0:0").await {
                extras.push(Arc::new(s));
            }
        }

        let deadline = Instant::now() + Duration::from_secs(SILK_TIMEOUT_SECS);
        let mut buf = [0u8; MAX_DGRAM];

        loop {
            for delta in -(VAR_PORT_RANGE as i32)..=(VAR_PORT_RANGE as i32) {
                let port = (base + delta).clamp(1024, 65535) as u16;
                let addr = SocketAddr::new(remote.ip(), port);
                for s in &extras {
                    s.send_to(&pkt, addr).await.ok();
                }
                self.sock.send_to(&pkt, addr).await.ok();
            }

            if let Ok(Ok((_, from))) =
                timeout(Duration::from_millis(50), self.sock.recv_from(&mut buf)).await
            {
                if from.ip() == remote.ip() {
                    return Ok(self
                        .finish_silk(from, remote_info.clone(), Arc::clone(&self.sock))
                        .await);
                }
            }

            for s in &extras {
                let mut b2 = [0u8; MAX_DGRAM];
                if let Ok(Ok((_, from))) =
                    timeout(Duration::from_millis(5), s.recv_from(&mut b2)).await
                {
                    if from.ip() == remote.ip() {
                        let arc_s = Arc::clone(s);
                        return Ok(self.finish_silk(from, remote_info.clone(), arc_s).await);
                    }
                }
            }

            if Instant::now() >= deadline {
                return Err(Error::SilkFailed);
            }
        }
    }

    // ── Utilities ────────────────────────────────────────────────

    async fn local_addr(&self) -> Option<SocketAddr> {
        let interface_ip = tokio::task::spawn_blocking(|| -> Option<IpAddr> {
            let sock = std::net::UdpSocket::bind("0.0.0.0:0").ok()?;
            sock.connect("8.8.8.8:80").ok()?;
            sock.local_addr().ok().map(|a| a.ip())
        })
        .await
        .ok()
        .flatten()?;
        let port = self.sock.local_addr().ok()?.port();
        Some(SocketAddr::new(interface_ip, port))
    }

    pub fn sock_local_addr(&self) -> Option<SocketAddr> {
        self.sock.local_addr().ok()
    }
}

// ── Error mapping ────────────────────────────────────────────────

fn loom_err(code: u8) -> Error {
    use crate::proto::*;
    match code {
        ERR_NOT_FOUND => Error::NotFound,
        ERR_ALREADY_REG => Error::AlreadyRegistered,
        ERR_ALREADY_FILTER => Error::AlreadyInFilter,
        ERR_NOT_FILTER => Error::NotInFilter,
        ERR_NO_FILTER => Error::FilterNotSet,
        ERR_BLOCKED => Error::Blocked,
        ERR_NET_NOT_FOUND => Error::NetworkNotFound,
        ERR_NET_EXISTS => Error::NetworkExists,
        ERR_NOT_IN_NET => Error::NotInNetwork,
        ERR_JOIN_REFUSED => Error::JoinRefused,
        ERR_HOST_TIMEOUT => Error::HostTimeout,
        _ => Error::Proto(format!("loom error 0x{:02x}", code)),
    }
}

fn hex_encode(b: &[u8]) -> String {
    b.iter().map(|x| format!("{:02x}", x)).collect()
}
