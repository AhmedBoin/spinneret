use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::sync::{oneshot, RwLock};
use tokio::time::{sleep, timeout};
use tracing::{debug, error, info, warn};

use crate::crypto::{open, random_nonce, seal, KeyPair, NONCE_LEN};
use crate::db::{FilterRecord, NetworkRecord, PeerRecord, StateDb};
use crate::error::Error;
use crate::proto::{
    unix_now, Command, FilterMode, NetworkKind, PeerInfo, PlainHeader, Response, StoredAddr,
    ERR_ALREADY_FILTER, ERR_BLOCKED, ERR_HOST_TIMEOUT, ERR_JOIN_REFUSED, ERR_NET_EXISTS,
    ERR_NET_NOT_FOUND, ERR_NOT_FILTER, ERR_NOT_FOUND, ERR_NOT_IN_NET, ERR_NOT_REG, ERR_NO_FILTER,
};
use crate::NatType;

pub const LOOM_PORT_1: u16 = 27531;
pub const LOOM_PORT_2: u16 = 27532;
const MAX_DGRAM: usize = 1400;
const HOST_JOIN_TIMEOUT_MS: u64 = 5_000;
const NAT_TIMEOUT_MS: u64 = 5_000;
const SEND_RETRIES: usize = 3;
const SEND_RETRY_DELAY_MS: u64 = 500;

// ── Config ─────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoomConfig {
    pub loom: LoomSection,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoomSection {
    #[serde(default = "dp1")]
    pub port1: u16,
    #[serde(default = "dp2")]
    pub port2: u16,
    #[serde(default = "ddb")]
    pub db_path: String,
    pub private_key: Option<String>,
}

fn dp1() -> u16 {
    LOOM_PORT_1
}
fn dp2() -> u16 {
    LOOM_PORT_2
}
fn ddb() -> String {
    "./spinneret.db".into()
}

impl LoomConfig {
    pub fn load() -> Result<Self, Error> {
        let path = Self::find()?;
        let s = std::fs::read_to_string(&path)
            .map_err(|e| Error::Config(format!("read {}: {}", path.display(), e)))?;
        toml::from_str(&s).map_err(|e| Error::Config(e.to_string()))
    }
    pub fn from_file(p: &str) -> Result<Self, Error> {
        let s =
            std::fs::read_to_string(p).map_err(|e| Error::Config(format!("read {}: {}", p, e)))?;
        toml::from_str(&s).map_err(|e| Error::Config(e.to_string()))
    }
    fn find() -> Result<std::path::PathBuf, Error> {
        if let Some(d) = std::env::current_exe()
            .ok()
            .and_then(|p| p.parent().map(|d| d.to_path_buf()))
        {
            let c = d.join("loom.toml");
            if c.exists() {
                return Ok(c);
            }
        }
        let c = std::env::current_dir()
            .map_err(|e| Error::Config(e.to_string()))?
            .join("loom.toml");
        if c.exists() {
            return Ok(c);
        }
        Err(Error::Config("loom.toml not found".into()))
    }
    pub fn resolved_db_path(&self) -> String {
        let p = std::path::Path::new(&self.loom.db_path);
        if p.is_absolute() {
            return self.loom.db_path.clone();
        }
        std::env::current_exe()
            .ok()
            .and_then(|e| e.parent().map(|d| d.join(p)))
            .map(|f| f.to_string_lossy().into_owned())
            .unwrap_or_else(|| self.loom.db_path.clone())
    }
}

// ── Pending requests ──────────────────────────────────────────────
type JoinKey = ([u8; 32], [u8; 32]);
type RegKey = ([u8; 32], u64); // (pubkey, timestamp)

#[derive(Debug)]
struct RegObs {
    port1: Option<u16>,
    port2: Option<u16>,
    nonce1: Option<[u8; NONCE_LEN]>,
    created: Instant,
    reply_sent: bool,
    cancel_tx: Option<oneshot::Sender<()>>,
}

pub struct LoomCtx {
    pub config: LoomConfig,
    pub db: Arc<StateDb>,
    pub keypair: KeyPair,
    pub pending_joins: Arc<RwLock<HashMap<JoinKey, oneshot::Sender<bool>>>>,
    #[allow(private_interfaces)]
    pub(crate) pending_regs: Arc<RwLock<HashMap<RegKey, RegObs>>>,
}

impl LoomCtx {
    pub fn new(config: LoomConfig) -> Result<Self, Error> {
        let db = Arc::new(StateDb::open(&config.resolved_db_path())?);
        let keypair = match &config.loom.private_key {
            Some(hex) => {
                let bytes =
                    hex_decode_32(hex).map_err(|_| Error::Config("bad private_key hex".into()))?;
                KeyPair::from_private(bytes)
            }
            None => {
                warn!("No private_key in loom.toml — generating ephemeral key");
                KeyPair::generate()
            }
        };
        info!("Loom public key: {}", hex_encode(&keypair.public));
        Ok(Self {
            config,
            db,
            keypair,
            pending_joins: Arc::new(RwLock::new(HashMap::new())),
            pending_regs: Arc::new(RwLock::new(HashMap::new())),
        })
    }
}

// ── Entry point ────────────────────────────────────────────────────

pub async fn run(ctx: Arc<LoomCtx>) -> Result<(), Error> {
    let p1 = ctx.config.loom.port1;
    let p2 = ctx.config.loom.port2;

    let sock1 = Arc::new(UdpSocket::bind(format!("0.0.0.0:{}", p1)).await?);
    let sock2 = Arc::new(UdpSocket::bind(format!("0.0.0.0:{}", p2)).await?);
    info!(
        "Loom up: port1={} port2={} db={} B",
        p1,
        p2,
        ctx.db.size_bytes()
    );

    // GC
    let db_gc = Arc::clone(&ctx.db);
    tokio::spawn(async move {
        loop {
            sleep(Duration::from_secs(60)).await;
            match db_gc.gc() {
                Ok(n) if n > 0 => info!("gc: removed {} expired records", n),
                Err(e) => error!("gc: {}", e),
                _ => {}
            }
        }
    });

    // Cleanup stale registration observations
    let regs_cleanup = ctx.pending_regs.clone();
    tokio::spawn(async move {
        loop {
            sleep(Duration::from_secs(2)).await;
            let mut to_remove = Vec::new();
            {
                let mut map = regs_cleanup.write().await;
                for (key, obs) in map.iter_mut() {
                    if obs.reply_sent || obs.created.elapsed() > Duration::from_secs(10) {
                        to_remove.push(key.clone());
                    }
                }
                for key in to_remove {
                    map.remove(&key);
                }
            }
        }
    });

    let s1a = Arc::clone(&sock1);
    let s1b = Arc::clone(&sock1);
    let s2a = Arc::clone(&sock2);
    let c1 = Arc::clone(&ctx);
    let c2 = Arc::clone(&ctx);

    let t1 = tokio::spawn(rx_loop(s1a, Arc::clone(&s2a), 1, c1));
    let t2 = tokio::spawn(rx_loop(s2a, s1b, 2, c2));
    let _ = tokio::try_join!(t1, t2);
    Ok(())
}

async fn rx_loop(sock: Arc<UdpSocket>, _aux: Arc<UdpSocket>, port_id: u8, ctx: Arc<LoomCtx>) {
    let mut buf = [0u8; MAX_DGRAM];
    loop {
        match sock.recv_from(&mut buf).await {
            Err(e) => error!("recv: {}", e),
            Ok((len, from)) => {
                debug!("RX: len={} from={} port_id={}", len, from, port_id);
                let raw = buf[..len].to_vec();
                let ctx = Arc::clone(&ctx);
                let sock = Arc::clone(&sock);
                tokio::spawn(async move {
                    if let Err(e) = handle_packet(&sock, from, raw, &ctx, port_id).await {
                        warn!("handle from {}: {}", from, e);
                    }
                });
            }
        }
    }
}

// ── Helper: send a packet with retries ────────────────────────────

async fn send_with_retries(
    sock: &UdpSocket,
    to: SocketAddr,
    data: &[u8],
    retries: usize,
    delay_ms: u64,
) -> Result<(), Error> {
    let mut last_err = Error::Timeout;
    for attempt in 0..retries {
        if attempt > 0 {
            sleep(Duration::from_millis(delay_ms * (1 << (attempt - 1)))).await;
        }
        match sock.send_to(data, to).await {
            Ok(_) => return Ok(()),
            Err(e) => last_err = e.into(),
        }
    }
    Err(last_err)
}

// ── Main packet handler ────────────────────────────────────────────

async fn handle_packet(
    sock: &Arc<UdpSocket>,
    from: SocketAddr,
    mut raw: Vec<u8>,
    ctx: &Arc<LoomCtx>,
    port_id: u8,
) -> Result<(), Error> {
    let (sender_pub, nonce, plaintext) = open(&ctx.keypair, &mut raw)?;
    let (hdr, hdr_len) = PlainHeader::decode(plaintext)?;
    hdr.check_freshness()?;

    let body = &plaintext[hdr_len..];
    if body.is_empty() {
        return Err(Error::Proto("empty body".into()));
    }

    let cmd = Command::parse(body)?;
    debug!("CMD from {}: {:?} (port {})", from, cmd, port_id);

    match cmd {
        // ── NAT detection ──────────────────────────────────────────
        Command::Nat { local } | Command::Conat { local } => {
            let is_nat = matches!(cmd, Command::Nat { .. });
            let key = (sender_pub, hdr.timestamp);
            let observed_port = from.port();

            let mut regs = ctx.pending_regs.write().await;
            let obs = regs.entry(key).or_insert_with(|| RegObs {
                port1: None,
                port2: None,
                nonce1: None,
                created: Instant::now(),
                reply_sent: false,
                cancel_tx: None,
            });

            if is_nat {
                obs.port1 = Some(observed_port);
                if obs.nonce1.is_none() {
                    obs.nonce1 = Some(nonce);
                }
                debug!(
                    "NAT: pk={:?} port1={} from {}",
                    hex_encode(&sender_pub[..4]),
                    observed_port,
                    from
                );
            } else {
                obs.port2 = Some(observed_port);
                debug!(
                    "CONAT: pk={:?} port2={} from {}",
                    hex_encode(&sender_pub[..4]),
                    observed_port,
                    from
                );
            }

            if obs.port1.is_some() && obs.port2.is_some() && !obs.reply_sent {
                obs.reply_sent = true;
                if let Some(tx) = obs.cancel_tx.take() {
                    let _ = tx.send(());
                }
                let p1 = obs.port1.unwrap();
                let p2 = obs.port2.unwrap();
                let nat = if p1 == p2 {
                    NatType::Fixed
                } else {
                    NatType::Variable
                };
                info!(
                    "NAT detected: pk={:?} p1={} p2={} => {:?}",
                    hex_encode(&sender_pub[..4]),
                    p1,
                    p2,
                    nat
                );
                let global = StoredAddr::from_socket(from);
                let info = PeerInfo {
                    pubkey: sender_pub,
                    global,
                    local: StoredAddr::from_socket(local),
                    nat,
                };
                ctx.db.save_peer(&PeerRecord::new(info.clone()))?;
                let resp_nonce = obs.nonce1.unwrap_or(nonce);
                send_resp(
                    sock,
                    from,
                    &ctx.keypair,
                    &sender_pub,
                    &resp_nonce,
                    Response::PeerInfo(info),
                )
                .await?;
                regs.remove(&key);
                return Ok(());
            }

            if !obs.reply_sent && obs.cancel_tx.is_none() {
                let (cancel_tx, cancel_rx) = oneshot::channel();
                obs.cancel_tx = Some(cancel_tx);

                let ctx_clone = Arc::clone(ctx);
                let sock_clone = Arc::clone(sock);
                let pk = sender_pub;
                let ts = hdr.timestamp;
                let local_addr = local;
                let src = from;
                let nonce_clone = nonce;

                tokio::spawn(async move {
                    let timeout_fut = sleep(Duration::from_millis(NAT_TIMEOUT_MS));
                    tokio::select! {
                        _ = timeout_fut => {
                            let mut regs = ctx_clone.pending_regs.write().await;
                            if let Some(obs) = regs.get_mut(&(pk, ts)) {
                                if !obs.reply_sent {
                                    obs.reply_sent = true;
                                    let nat = NatType::Variable;
                                    info!(
                                        "NAT timeout: pk={:?} p1={:?} p2={:?} => Variable",
                                        hex_encode(&pk[..4]), obs.port1, obs.port2
                                    );
                                    let global = StoredAddr::from_socket(src);
                                    let info = PeerInfo {
                                        pubkey: pk,
                                        global,
                                        local: StoredAddr::from_socket(local_addr),
                                        nat,
                                    };
                                    let _ = ctx_clone.db.save_peer(&PeerRecord::new(info.clone()));
                                    let resp_nonce = obs.nonce1.unwrap_or(nonce_clone);
                                    let _ = send_resp(&sock_clone, src, &ctx_clone.keypair, &pk, &resp_nonce, Response::PeerInfo(info)).await;
                                    regs.remove(&(pk, ts));
                                }
                            }
                        }
                        _ = cancel_rx => {}
                    }
                });
            }
            Ok(())
        }

        // ── Login ──────────────────────────────────────────────────
        Command::Login { mut info } => {
            info.pubkey = sender_pub;
            info.global = StoredAddr::from_socket(from);
            let rec = PeerRecord::new(info.clone());
            ctx.db.save_peer(&rec)?;
            info!("login: {}", hex_encode(&sender_pub[..4]));
            send_resp(sock, from, &ctx.keypair, &sender_pub, &nonce, Response::Ok).await?;
            Ok(())
        }

        // ── Tangle ─────────────────────────────────────────────────
        Command::Tangle => {
            // Check if sender is registered.
            if ctx.db.get_live_peer(&sender_pub)?.is_some() {
                ctx.db.touch_peer(&sender_pub)?;
                send_ok(sock, from, &ctx.keypair, &sender_pub, &nonce).await?;
            } else {
                send_err(sock, from, &ctx.keypair, &sender_pub, &nonce, ERR_NOT_REG).await?;
            }
            Ok(())
        }

        // ── SetFilter ──────────────────────────────────────────────
        Command::SetFilter { mode } => {
            if ctx.db.get_live_peer(&sender_pub)?.is_none() {
                return send_err(sock, from, &ctx.keypair, &sender_pub, &nonce, ERR_NOT_REG).await;
            }
            let current = ctx.db.load_filter(&sender_pub)?;
            if let Some(ref f) = current {
                if f.mode == mode {
                    return send_err(
                        sock,
                        from,
                        &ctx.keypair,
                        &sender_pub,
                        &nonce,
                        ERR_ALREADY_FILTER,
                    )
                    .await;
                }
            }
            if mode == FilterMode::Off {
                ctx.db.del_filter(&sender_pub)?;
            } else {
                let rec = current
                    .map(|mut f| {
                        f.mode = mode;
                        f
                    })
                    .unwrap_or_else(|| FilterRecord::new(sender_pub, mode));
                ctx.db.save_filter(&rec)?;
            }
            send_ok(sock, from, &ctx.keypair, &sender_pub, &nonce).await?;
            Ok(())
        }

        // ── FilterInfo ─────────────────────────────────────────────
        Command::FilterInfo => match ctx.db.load_filter(&sender_pub)? {
            None => send_err(sock, from, &ctx.keypair, &sender_pub, &nonce, ERR_NO_FILTER).await,
            Some(f) => {
                let fi = crate::proto::FilterInfo {
                    mode: f.mode,
                    count: f.keys.len() as u32,
                };
                send_resp(
                    sock,
                    from,
                    &ctx.keypair,
                    &sender_pub,
                    &nonce,
                    Response::FilterInfo(fi),
                )
                .await
            }
        },

        // ── AddPeerFilter ──────────────────────────────────────────
        Command::AddPeerFilter { key } => match ctx.db.load_filter(&sender_pub)? {
            None => send_err(sock, from, &ctx.keypair, &sender_pub, &nonce, ERR_NO_FILTER).await,
            Some(mut f) => {
                if !f.keys.insert(key) {
                    return send_err(
                        sock,
                        from,
                        &ctx.keypair,
                        &sender_pub,
                        &nonce,
                        ERR_ALREADY_FILTER,
                    )
                    .await;
                }
                ctx.db.save_filter(&f)?;
                send_ok(sock, from, &ctx.keypair, &sender_pub, &nonce).await
            }
        },

        // ── RemovePeerFilter ───────────────────────────────────────
        Command::RemovePeerFilter { key } => match ctx.db.load_filter(&sender_pub)? {
            None => send_err(sock, from, &ctx.keypair, &sender_pub, &nonce, ERR_NO_FILTER).await,
            Some(mut f) => {
                if !f.keys.remove(&key) {
                    return send_err(
                        sock,
                        from,
                        &ctx.keypair,
                        &sender_pub,
                        &nonce,
                        ERR_NOT_FILTER,
                    )
                    .await;
                }
                ctx.db.save_filter(&f)?;
                send_ok(sock, from, &ctx.keypair, &sender_pub, &nonce).await
            }
        },

        // ── RegisterNetwork ────────────────────────────────────────
        Command::RegisterNetwork { id, kind } => {
            if ctx.db.get_live_peer(&sender_pub)?.is_none() {
                return send_err(sock, from, &ctx.keypair, &sender_pub, &nonce, ERR_NOT_REG).await;
            }
            if ctx.db.get_live_net(&id)?.is_some() {
                return send_err(
                    sock,
                    from,
                    &ctx.keypair,
                    &sender_pub,
                    &nonce,
                    ERR_NET_EXISTS,
                )
                .await;
            }
            let host = if kind == NetworkKind::Private {
                Some(sender_pub)
            } else {
                None
            };
            let rec = NetworkRecord::new(id, kind, host, sender_pub);
            ctx.db.save_net(&rec)?;
            info!("network created: {} ({:?})", hex_encode(&id[..4]), kind);
            send_ok(sock, from, &ctx.keypair, &sender_pub, &nonce).await?;
            Ok(())
        }

        // ── NetworkInfo ────────────────────────────────────────────
        Command::NetworkInfo { id } => match ctx.db.get_live_net(&id)? {
            None => {
                send_err(
                    sock,
                    from,
                    &ctx.keypair,
                    &sender_pub,
                    &nonce,
                    ERR_NET_NOT_FOUND,
                )
                .await
            }
            Some(r) => {
                send_resp(
                    sock,
                    from,
                    &ctx.keypair,
                    &sender_pub,
                    &nonce,
                    Response::NetworkInfo(r.to_proto_info()),
                )
                .await
            }
        },

        // ── GetNetPeer ─────────────────────────────────────────────
        Command::GetNetPeer { net_id, idx } => {
            let net = match ctx.db.get_live_net(&net_id)? {
                None => {
                    return send_err(
                        sock,
                        from,
                        &ctx.keypair,
                        &sender_pub,
                        &nonce,
                        ERR_NET_NOT_FOUND,
                    )
                    .await
                }
                Some(r) => r,
            };
            if !net.contains(&sender_pub) {
                return send_err(
                    sock,
                    from,
                    &ctx.keypair,
                    &sender_pub,
                    &nonce,
                    ERR_NOT_IN_NET,
                )
                .await;
            }
            let member = match net.member_at(idx) {
                None => {
                    return send_err(sock, from, &ctx.keypair, &sender_pub, &nonce, ERR_NOT_FOUND)
                        .await
                }
                Some(m) => m.pubkey,
            };
            match ctx.db.get_live_peer(&member)? {
                None => {
                    send_err(sock, from, &ctx.keypair, &sender_pub, &nonce, ERR_NOT_FOUND).await?
                }
                Some(r) => {
                    send_resp(
                        sock,
                        from,
                        &ctx.keypair,
                        &sender_pub,
                        &nonce,
                        Response::PeerInfo(r.info),
                    )
                    .await?
                }
            }
            Ok(())
        }

        // ── TangleNetwork ──────────────────────────────────────────
        Command::TangleNetwork { id } => {
            let net = match ctx.db.get_live_net(&id)? {
                None => {
                    return send_err(
                        sock,
                        from,
                        &ctx.keypair,
                        &sender_pub,
                        &nonce,
                        ERR_NET_NOT_FOUND,
                    )
                    .await;
                }
                Some(r) => r,
            };
            if net.kind == NetworkKind::Private {
                if net.host_pubkey != Some(sender_pub) {
                    return send_err(
                        sock,
                        from,
                        &ctx.keypair,
                        &sender_pub,
                        &nonce,
                        ERR_NOT_IN_NET,
                    )
                    .await;
                }
            } else if !net.contains(&sender_pub) {
                return send_err(
                    sock,
                    from,
                    &ctx.keypair,
                    &sender_pub,
                    &nonce,
                    ERR_NOT_IN_NET,
                )
                .await;
            }
            let members = ctx.db.touch_net(&id)?;
            // Ping all members with retries
            let ping_data = build_resp(&ctx.keypair, &sender_pub, &random_nonce(), Response::Ok)?;
            for mkey in &members {
                if mkey == &sender_pub {
                    continue;
                }
                if let Ok(Some(peer)) = ctx.db.get_live_peer(mkey) {
                    let _ = send_with_retries(
                        sock,
                        peer.info.global.to_socket(),
                        &ping_data,
                        SEND_RETRIES,
                        SEND_RETRY_DELAY_MS,
                    )
                    .await;
                }
            }
            send_ok(sock, from, &ctx.keypair, &sender_pub, &nonce).await?;
            Ok(())
        }

        // ── JoinNetwork ────────────────────────────────────────────
        Command::JoinNetwork { id } => {
            if ctx.db.get_live_peer(&sender_pub)?.is_none() {
                return send_err(sock, from, &ctx.keypair, &sender_pub, &nonce, ERR_NOT_REG).await;
            }
            let mut net = match ctx.db.get_live_net(&id)? {
                None => {
                    return send_err(
                        sock,
                        from,
                        &ctx.keypair,
                        &sender_pub,
                        &nonce,
                        ERR_NET_NOT_FOUND,
                    )
                    .await
                }
                Some(r) => r,
            };
            let joiner_info = ctx.db.get_live_peer(&sender_pub)?.unwrap().info;

            match net.kind {
                NetworkKind::Public => {
                    net.add_member(sender_pub);
                    ctx.db.save_net(&net)?;
                    send_ok(sock, from, &ctx.keypair, &sender_pub, &nonce).await?;
                }
                NetworkKind::Private => {
                    let host_key = match net.host_pubkey {
                        None => {
                            return send_err(
                                sock,
                                from,
                                &ctx.keypair,
                                &sender_pub,
                                &nonce,
                                ERR_NET_NOT_FOUND,
                            )
                            .await
                        }
                        Some(k) => k,
                    };
                    let host_rec = match ctx.db.get_live_peer(&host_key)? {
                        None => {
                            return send_err(
                                sock,
                                from,
                                &ctx.keypair,
                                &sender_pub,
                                &nonce,
                                ERR_HOST_TIMEOUT,
                            )
                            .await
                        }
                        Some(r) => r,
                    };

                    let (tx, rx) = oneshot::channel::<bool>();
                    {
                        let mut pj = ctx.pending_joins.write().await;
                        pj.insert((id, sender_pub), tx);
                    }

                    // Send AskHostJoin to host with retries
                    let ask_data = build_resp(
                        &ctx.keypair,
                        &host_key,
                        &random_nonce(),
                        Response::AskHostJoin {
                            net_id: id,
                            joiner: joiner_info.clone(),
                        },
                    )?;
                    let _ = send_with_retries(
                        sock,
                        host_rec.info.global.to_socket(),
                        &ask_data,
                        SEND_RETRIES,
                        SEND_RETRY_DELAY_MS,
                    )
                    .await;

                    match timeout(Duration::from_millis(HOST_JOIN_TIMEOUT_MS), rx).await {
                        Ok(Ok(true)) => {
                            net.add_member(sender_pub);
                            ctx.db.save_net(&net)?;
                            send_ok(sock, from, &ctx.keypair, &sender_pub, &nonce).await?;
                        }
                        Ok(Ok(false)) => {
                            send_err(
                                sock,
                                from,
                                &ctx.keypair,
                                &sender_pub,
                                &nonce,
                                ERR_JOIN_REFUSED,
                            )
                            .await?;
                        }
                        _ => {
                            ctx.pending_joins.write().await.remove(&(id, sender_pub));
                            send_err(
                                sock,
                                from,
                                &ctx.keypair,
                                &sender_pub,
                                &nonce,
                                ERR_HOST_TIMEOUT,
                            )
                            .await?;
                        }
                    }
                }
            }
            Ok(())
        }

        // ── HostJoinResp ───────────────────────────────────────────
        Command::HostJoinResp {
            net_id,
            joiner_key,
            approved,
        } => {
            let mut pj = ctx.pending_joins.write().await;
            if let Some(tx) = pj.remove(&(net_id, joiner_key)) {
                let _ = tx.send(approved);
            }
            Ok(())
        }

        // ── Spin ────────────────────────────────────────────────────
        Command::Spin { target_key } => {
            let caller_rec = match ctx.db.get_live_peer(&sender_pub)? {
                None => {
                    return send_err(sock, from, &ctx.keypair, &sender_pub, &nonce, ERR_NOT_REG)
                        .await
                }
                Some(r) => r,
            };
            let target_rec = match ctx.db.get_live_peer(&target_key)? {
                None => {
                    return send_err(sock, from, &ctx.keypair, &sender_pub, &nonce, ERR_NOT_FOUND)
                        .await
                }
                Some(r) => r,
            };
            if !ctx.db.spin_allowed(&target_key, &sender_pub)? {
                return send_err(sock, from, &ctx.keypair, &sender_pub, &nonce, ERR_BLOCKED).await;
            }

            // Send SpinNotify to target with retries
            let notify_data = build_resp(
                &ctx.keypair,
                &target_key,
                &random_nonce(),
                Response::SpinNotify {
                    caller: caller_rec.info.clone(),
                },
            )?;
            let _ = send_with_retries(
                sock,
                target_rec.info.global.to_socket(),
                &notify_data,
                SEND_RETRIES,
                SEND_RETRY_DELAY_MS,
            )
            .await;

            send_resp(
                sock,
                from,
                &ctx.keypair,
                &sender_pub,
                &nonce,
                Response::PeerInfo(target_rec.info),
            )
            .await?;
            Ok(())
        }
    }
}

// ── Send helpers ──────────────────────────────────────────────────

fn build_resp(
    our_key: &KeyPair,
    their_pub: &[u8; 32],
    nonce: &[u8; NONCE_LEN],
    resp: Response,
) -> Result<Vec<u8>, Error> {
    let hdr = PlainHeader {
        timestamp: unix_now(),
        validity_secs: 5,
    };
    let mut body = Vec::new();
    hdr.encode_into(&mut body);
    body.extend_from_slice(&resp.encode());
    seal(our_key, their_pub, nonce, &body)
}

async fn send_resp(
    sock: &UdpSocket,
    to: SocketAddr,
    our_key: &KeyPair,
    their_pub: &[u8; 32],
    nonce: &[u8; NONCE_LEN],
    resp: Response,
) -> Result<(), Error> {
    let pkt = build_resp(our_key, their_pub, nonce, resp)?;
    sock.send_to(&pkt, to).await?;
    Ok(())
}

async fn send_ok(
    sock: &UdpSocket,
    to: SocketAddr,
    our_key: &KeyPair,
    their_pub: &[u8; 32],
    nonce: &[u8; NONCE_LEN],
) -> Result<(), Error> {
    send_resp(sock, to, our_key, their_pub, nonce, Response::Ok).await
}

async fn send_err(
    sock: &UdpSocket,
    to: SocketAddr,
    our_key: &KeyPair,
    their_pub: &[u8; 32],
    nonce: &[u8; NONCE_LEN],
    code: u8,
) -> Result<(), Error> {
    send_resp(sock, to, our_key, their_pub, nonce, Response::Err(code)).await
}

// ── Hex helpers ───────────────────────────────────────────────────

pub fn hex_encode(b: &[u8]) -> String {
    b.iter().map(|x| format!("{:02x}", x)).collect()
}

pub fn hex_decode_32(s: &str) -> Result<[u8; 32], ()> {
    let s = s.trim();
    if s.len() != 64 {
        return Err(());
    }
    let mut out = [0u8; 32];
    for i in 0..32 {
        out[i] = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).map_err(|_| ())?;
    }
    Ok(out)
}
