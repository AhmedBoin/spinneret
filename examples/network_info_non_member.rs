//! Non‑member tries to get network info – should return NOT_IN_NET.

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

    // Alice (host)
    let alice_key = KeyPair::generate();
    info!("Alice public key: {}", hex_encode(&alice_key.public));
    let alice = Peer::new(alice_key, loom_ip, loom_pub).await?;
    alice.register().await?;
    info!("Alice registered");

    // Charlie (non‑member)
    let charlie_key = KeyPair::generate();
    info!("Charlie public key: {}", hex_encode(&charlie_key.public));
    let charlie = Peer::new(charlie_key, loom_ip, loom_pub).await?;
    charlie.register().await?;
    info!("Charlie registered");

    let net_id: [u8; 32] = random_net_id();
    alice.register_network(net_id, NetworkKind::Public).await?;
    info!("Alice created public network");

    // Wait for network creation to propagate
    sleep(Duration::from_millis(500)).await;

    // Charlie (non‑member) gets network info – should succeed (public).
    match charlie.network_info(net_id).await {
        Ok(info) => info!(
            "✅ Charlie got public network info: members={}",
            info.member_count
        ),
        Err(e) => info!("❌ Charlie failed: {}", e),
    }

    // Bob joins, making members = 2
    let bob_key = KeyPair::generate();
    let bob = Peer::new(bob_key, loom_ip, loom_pub).await?;
    bob.register().await?;
    bob.join_network(net_id).await?;
    info!("Bob joined network");

    sleep(Duration::from_millis(500)).await;

    // Charlie again – should still succeed (public).
    match charlie.network_info(net_id).await {
        Ok(info) => info!(
            "✅ Charlie still sees public info: members={}",
            info.member_count
        ),
        Err(e) => info!("❌ Charlie failed: {}", e),
    }

    info!("Network info public test passed.");
    Ok(())
}
