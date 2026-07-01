//! Multi‑peer network: 3 peers join a public network and connect to each other.

use rand::RngExt;
use spinneret::{KeyPair, NetworkKind, Peer};
use std::net::IpAddr;
use tokio::time::{sleep, Duration};
use tracing::info;

const LOOM_IP: &str = "129.80.223.49";
const LOOM_PUB_HEX: &str = "35c45b4c21e6140ce0ebf584232539ae232770880bd0acd70af3cdb18a54870a";

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

    // ─── Alice ─────────────────────────────────────────────────────
    let alice_key = KeyPair::generate();
    info!("Alice public key: {}", hex_encode(&alice_key.public));
    let alice = Peer::new(alice_key, loom_ip, loom_pub).await?;
    alice.register().await?;
    info!("Alice registered");

    // ─── Bob ───────────────────────────────────────────────────────
    let bob_key = KeyPair::generate();
    info!("Bob public key: {}", hex_encode(&bob_key.public));
    let bob = Peer::new(bob_key, loom_ip, loom_pub).await?;
    bob.register().await?;
    info!("Bob registered");
    let mut bob_silk_rx = bob.enable_auto_accept().await;

    // ─── Charlie ──────────────────────────────────────────────────
    let charlie_key = KeyPair::generate();
    info!("Charlie public key: {}", hex_encode(&charlie_key.public));
    let charlie = Peer::new(charlie_key, loom_ip, loom_pub).await?;
    charlie.register().await?;
    info!("Charlie registered");
    let mut charlie_silk_rx = charlie.enable_auto_accept().await;

    sleep(Duration::from_millis(500)).await;

    // ─── Create public network ────────────────────────────────────
    let net_id: [u8; 32] = random_net_id();
    alice.register_network(net_id, NetworkKind::Public).await?;
    info!("Alice created public network");

    bob.join_network(net_id).await?;
    info!("Bob joined network");
    charlie.join_network(net_id).await?;
    info!("Charlie joined network");

    sleep(Duration::from_millis(500)).await;

    // ─── Get network members ──────────────────────────────────────
    let net_info = alice.network_info(net_id).await?;
    info!("Network members: {}", net_info.member_count);

    for i in 0..net_info.member_count {
        let peer_info = alice.get_net_peer(net_id, i).await?;
        info!("Member {}: {}", i, peer_info.global.to_socket());
    }

    // ─── Alice spins Bob ──────────────────────────────────────────
    info!("Alice spinning Bob...");
    let silk_ab = alice.spin(*bob.public_key()).await?;
    info!("Alice -> Bob connected to {}", silk_ab.remote_addr);
    // Bob auto-accepts; retrieve his Silk
    let silk_ba = bob_silk_rx.recv().await.unwrap();
    info!("Bob -> Alice connected to {}", silk_ba.remote_addr);
    silk_ba.send(b"Hello from Bob").await?;
    silk_ab.send(b"Hello from Alice").await?;
    info!("Alice -> Bob sent");

    // ─── Alice spins Charlie ──────────────────────────────────────
    info!("Alice spinning Charlie...");
    let silk_ac = alice.spin(*charlie.public_key()).await?;
    info!("Alice -> Charlie connected to {}", silk_ac.remote_addr);
    let silk_ca = charlie_silk_rx.recv().await.unwrap();
    info!("Charlie -> Alice connected to {}", silk_ca.remote_addr);
    silk_ca.send(b"Hello from Charlie").await?;
    silk_ac.send(b"Hello from Alice to Charlie").await?;
    info!("Alice -> Charlie sent");

    // ─── Bob spins Charlie ────────────────────────────────────────
    info!("Bob spinning Charlie...");
    let silk_bc = bob.spin(*charlie.public_key()).await?;
    info!("Bob -> Charlie connected to {}", silk_bc.remote_addr);
    let silk_cb = charlie_silk_rx.recv().await.unwrap();
    info!("Charlie -> Bob connected to {}", silk_cb.remote_addr);
    silk_cb.send(b"Hello from Charlie to Bob").await?;
    silk_bc.send(b"Hello from Bob to Charlie").await?;
    info!("Bob -> Charlie sent");

    // ─── Receive messages ──────────────────────────────────────────
    sleep(Duration::from_millis(500)).await;

    if let Some(msg) = silk_ab.try_recv().await {
        info!("Alice received from Bob: {}", String::from_utf8_lossy(&msg));
    }
    if let Some(msg) = silk_ac.try_recv().await {
        info!(
            "Alice received from Charlie: {}",
            String::from_utf8_lossy(&msg)
        );
    }
    if let Some(msg) = silk_bc.try_recv().await {
        info!(
            "Bob received from Charlie: {}",
            String::from_utf8_lossy(&msg)
        );
    }

    info!("Multi‑peer network test completed successfully.");
    Ok(())
}
