//! Two peers in the same process demonstrate networks:
//!   - Host creates a public network.
//!   - Member joins it, lists members, and connects to the host.

use rand::RngExt;
use spinneret::{KeyPair, NetworkKind, Peer};
use std::net::IpAddr;
use tokio::time::{sleep, Duration};
use tracing::info;

const LOOM_IP: &str = "129.80.223.49";
const LOOM_PUB_HEX: &str = "7f0d4a53e547d3ed980869c8cf6ca4c9065af1313553717b6eb2b4cd3ac6744f";

fn parse_hex_32(s: &str) -> [u8; 32] {
    let s = s.trim();
    assert_eq!(s.len(), 64, "hex key must be 64 hex chars");
    let mut out = [0u8; 32];
    for i in 0..32 {
        out[i] = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).expect("invalid hex");
    }
    out
}

fn hex_encode(b: &[u8]) -> String {
    b.iter().map(|x| format!("{:02x}", x)).collect()
}

fn random_net_id() -> [u8; 32] {
    let mut id = [0u8; 32];
    rand::rng().fill(&mut id[..]);
    id
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let loom_ip: IpAddr = LOOM_IP.parse()?;
    let loom_pub = parse_hex_32(LOOM_PUB_HEX);

    let net_id = random_net_id();
    info!("Network ID: {}", hex_encode(&net_id));

    // ─── Host (Alice) ─────────────────────────────────────────────
    let alice_key = KeyPair::generate();
    info!("Alice (host) public key: {}", hex_encode(&alice_key.public));

    let alice = Peer::new(alice_key, loom_ip, loom_pub).await?;
    let alice_info = alice.register().await?;
    info!("Alice registered: global={}", alice_info.global.to_socket());

    // Alice enables auto‑accept – this is optional but makes the example simpler.
    let mut alice_silk_rx = alice.enable_auto_accept().await;

    // Create public network
    alice.register_network(net_id, NetworkKind::Public).await?;
    info!("Alice created public network");

    // ─── Member (Bob) ─────────────────────────────────────────────
    let bob_key = KeyPair::generate();
    info!("Bob (member) public key: {}", hex_encode(&bob_key.public));

    let bob = Peer::new(bob_key, loom_ip, loom_pub).await?;
    let bob_info = bob.register().await?;
    info!("Bob registered: global={}", bob_info.global.to_socket());

    // Join the network
    bob.join_network(net_id).await?;
    info!("Bob joined network");

    // Wait for the network to be updated (loom sync)
    sleep(Duration::from_millis(500)).await;

    // ─── List members ─────────────────────────────────────────────
    let net_info = bob.network_info(net_id).await?;
    info!("Network info: members={}", net_info.member_count);

    // Get the host's PeerInfo (index 0 is the creator)
    let host_info = bob.get_net_peer(net_id, 0).await?;
    info!("Host (Alice) is at {}", host_info.global.to_socket());

    // ─── Connect from Bob to Alice ────────────────────────────────
    info!("Bob spinning Alice...");
    let bob_silk = bob.spin(host_info.pubkey).await?;
    info!("Bob: silk established to {}", bob_silk.remote_addr);

    // Alice automatically accepts the spin; retrieve her Silk
    let alice_silk = alice_silk_rx.recv().await.unwrap();
    info!("Alice: silk established to {}", alice_silk.remote_addr);

    // ─── Exchange a message ───────────────────────────────────────
    bob_silk.send(b"Hello from Bob!").await?;
    info!("Bob sent message");

    let msg = alice_silk.recv().await?;
    info!("Alice received: {}", String::from_utf8_lossy(&msg));

    alice_silk.send(b"Hello from Alice!").await?;
    info!("Alice sent reply");

    let reply = bob_silk.recv().await?;
    info!("Bob received: {}", String::from_utf8_lossy(&reply));

    info!("Network test completed successfully.");
    Ok(())
}
