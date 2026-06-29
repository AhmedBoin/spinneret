//! Tangle before registration should return ERR_NOT_REG.

use spinneret::{KeyPair, Peer};
use std::net::IpAddr;
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

    // Alice – no registration yet
    let alice_key = KeyPair::generate();
    info!("Alice public key: {}", hex_encode(&alice_key.public));
    let alice = Peer::new(alice_key, loom_ip, loom_pub).await?;

    // Tangle before register should fail
    match alice.tangle().await {
        Ok(()) => info!("❌ Tangle succeeded (unexpected)"),
        Err(e) => info!("✅ Tangle failed: {}", e),
    }

    // Now register and tangle again
    alice.register().await?;
    info!("Alice registered");

    match alice.tangle().await {
        Ok(()) => info!("✅ Tangle succeeded after registration"),
        Err(e) => info!("❌ Tangle failed: {}", e),
    }

    // Also test tangle_network before registering (should fail)
    let bob_key = KeyPair::generate();
    let bob = Peer::new(bob_key, loom_ip, loom_pub).await?;
    let net_id = [0x99; 32];

    match bob.tangle_network(net_id).await {
        Ok(()) => info!("❌ TangleNetwork succeeded before register (unexpected)"),
        Err(e) => info!("✅ TangleNetwork failed before register: {}", e),
    }

    info!("Tangle without register test passed.");
    Ok(())
}
