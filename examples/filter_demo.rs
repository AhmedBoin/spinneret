//! Filter demo with 3 peers
//! Tests whitelist, blacklist, and filter info.

use spinneret::{FilterMode, KeyPair, Peer, Silk};
use std::net::IpAddr;
use std::sync::Arc;
use tokio::sync::mpsc;
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

    sleep(Duration::from_millis(500)).await;

    // Helper: spin and wait for Bob to accept
    async fn spin_and_check(
        peer: &Peer,
        target_key: [u8; 32],
        rx: &mut mpsc::Receiver<Arc<Silk>>,
    ) -> Result<(), String> {
        match peer.spin(target_key).await {
            Ok(silk) => {
                // Wait for Bob to accept and send the Silk back
                let _bob_silk = rx.recv().await.unwrap();
                // Send a dummy message to confirm connection
                silk.send(b"ping").await.map_err(|e| e.to_string())?;
                Ok(())
            }
            Err(e) => Err(e.to_string()),
        }
    }

    // ─── Test 1: Bob sets whitelist allowing Alice only ──────────
    info!("--- Test 1: Bob sets whitelist allowing Alice only ---");
    bob.set_filter(FilterMode::Whitelist).await.unwrap();
    bob.add_peer_filter(*alice.public_key()).await.unwrap();

    // Charlie tries to spin Bob (should fail)
    match spin_and_check(&charlie, *bob.public_key(), &mut bob_silk_rx).await {
        Err(e) => info!("✅ Charlie blocked: {}", e),
        Ok(_) => info!("❌ Charlie spun Bob (unexpected)"),
    }

    // Alice spins Bob (should succeed)
    match spin_and_check(&alice, *bob.public_key(), &mut bob_silk_rx).await {
        Ok(_) => info!("✅ Alice spun Bob successfully"),
        Err(e) => info!("❌ Alice failed: {}", e),
    }

    // ─── Test 2: Bob removes Alice from whitelist ─────────────────
    info!("--- Test 2: Bob removes Alice from whitelist ---");
    bob.remove_peer_filter(*alice.public_key()).await.unwrap();

    // Alice tries again (should fail)
    match spin_and_check(&alice, *bob.public_key(), &mut bob_silk_rx).await {
        Err(e) => info!("✅ Alice blocked after removal: {}", e),
        Ok(_) => info!("❌ Alice spun Bob (unexpected)"),
    }

    // ─── Test 3: Bob sets blacklist blocking Charlie ─────────────
    info!("--- Test 3: Bob sets blacklist blocking Charlie ---");
    bob.set_filter(FilterMode::Blacklist).await.unwrap();
    bob.add_peer_filter(*charlie.public_key()).await.unwrap();

    // Charlie tries again (should fail)
    match spin_and_check(&charlie, *bob.public_key(), &mut bob_silk_rx).await {
        Err(e) => info!("✅ Charlie blocked by blacklist: {}", e),
        Ok(_) => info!("❌ Charlie spun Bob (unexpected)"),
    }

    // Alice tries (should succeed because blacklist only blocks Charlie)
    match spin_and_check(&alice, *bob.public_key(), &mut bob_silk_rx).await {
        Ok(_) => info!("✅ Alice spun Bob (allowed)"),
        Err(e) => info!("❌ Alice failed: {}", e),
    }

    // ─── Test 4: Filter info ──────────────────────────────────────
    info!("--- Test 4: Filter info ---");
    let info = bob.filter_info().await.unwrap();
    info!("Bob filter: mode={:?}, count={}", info.mode, info.count);

    info!("All filter tests completed successfully.");
    Ok(())
}
