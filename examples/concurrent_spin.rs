//! Two peers spin each other simultaneously to test race conditions.
//! Both peers will spin each other concurrently and establish silks.

use spinneret::{KeyPair, Peer};
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
    let mut alice_silk_rx = alice.enable_auto_accept().await;

    // ─── Bob ───────────────────────────────────────────────────────
    let bob_key = KeyPair::generate();
    info!("Bob public key: {}", hex_encode(&bob_key.public));
    let bob = Peer::new(bob_key, loom_ip, loom_pub).await?;
    bob.register().await?;
    info!("Bob registered");
    let mut bob_silk_rx = bob.enable_auto_accept().await;

    sleep(Duration::from_millis(500)).await;

    // ─── Spin concurrently: Alice → Bob and Bob → Alice ──────────
    let alice_spin = alice.spin(*bob.public_key());
    let bob_spin = bob.spin(*alice.public_key());
    let (alice_silk_res, bob_silk_res) = tokio::join!(alice_spin, bob_spin);

    let alice_silk = alice_silk_res?;
    info!("Alice → Bob (direct): {}", alice_silk.remote_addr);
    let bob_silk = bob_silk_res?;
    info!("Bob → Alice (direct): {}", bob_silk.remote_addr);

    // ─── Retrieve auto‑accepted silks ─────────────────────────────
    let alice_from_bob = alice_silk_rx.recv().await.unwrap();
    info!(
        "Alice received Bob's spin (auto): {}",
        alice_from_bob.remote_addr
    );
    let bob_from_alice = bob_silk_rx.recv().await.unwrap();
    info!(
        "Bob received Alice's spin (auto): {}",
        bob_from_alice.remote_addr
    );

    // ─── Exchange messages on both pairs ──────────────────────────
    // Pair 1: alice_silk (Alice→Bob) ↔ bob_from_alice (Bob→Alice)
    alice_silk.send(b"Hello from Alice (Pair 1)").await?;
    let msg = bob_from_alice.recv().await?;
    info!("Bob received (Pair 1): {}", String::from_utf8_lossy(&msg));

    // Pair 2: bob_silk (Bob→Alice) ↔ alice_from_bob (Alice→Bob)
    bob_silk.send(b"Hello from Bob (Pair 2)").await?;
    let msg2 = alice_from_bob.recv().await?;
    info!(
        "Alice received (Pair 2): {}",
        String::from_utf8_lossy(&msg2)
    );

    info!("Concurrent spin test completed successfully.");
    Ok(())
}
