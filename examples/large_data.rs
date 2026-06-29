//! Send a large (1 KB) message over a silk.

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

    // Alice
    let alice_key = KeyPair::generate();
    info!("Alice public key: {}", hex_encode(&alice_key.public));
    let alice = Peer::new(alice_key, loom_ip, loom_pub).await?;
    alice.register().await?;
    info!("Alice registered");

    // Bob
    let bob_key = KeyPair::generate();
    info!("Bob public key: {}", hex_encode(&bob_key.public));
    let bob = Peer::new(bob_key, loom_ip, loom_pub).await?;
    bob.register().await?;
    info!("Bob registered");

    // Enable auto-accept on Bob
    let mut bob_silk_rx = bob.enable_auto_accept().await;

    sleep(Duration::from_millis(500)).await;

    // Alice spins Bob
    info!("Alice spinning Bob...");
    let alice_silk = alice.spin(*bob.public_key()).await?;
    info!("Alice silk established");

    // Bob accepts
    let bob_silk = bob_silk_rx.recv().await.unwrap();
    info!("Bob silk established");

    // Send a 1 KB message
    let large_data = vec![b'X'; 1024];
    alice_silk.send(&large_data).await?;
    info!("Alice sent 1 KB message");

    let received = bob_silk.recv().await?;
    assert_eq!(received.len(), 1024, "Message size mismatch");
    info!("Bob received 1 KB message (len={})", received.len());

    info!("Large data test passed.");
    Ok(())
}
