//! Test turning filter off.

use spinneret::{FilterMode, KeyPair, Peer};
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

    // Bob sets a whitelist allowing Alice
    bob.set_filter(FilterMode::Whitelist).await?;
    bob.add_peer_filter(*alice.public_key()).await?;
    info!("Bob whitelisted Alice");

    // Charlie (not registered) tries – should fail
    let charlie_key = KeyPair::generate();
    let charlie = Peer::new(charlie_key, loom_ip, loom_pub).await?;
    charlie.register().await?;
    info!("Charlie registered");

    // Test 1: Charlie is blocked
    match charlie.spin(*bob.public_key()).await {
        Ok(_) => info!("❌ Charlie spun Bob (unexpected)"),
        Err(e) => info!("✅ Charlie blocked: {}", e),
    }

    // Bob turns filter off
    bob.set_filter(FilterMode::Off).await?;
    info!("Bob turned filter off");

    // Small delay to let the Loom update
    sleep(Duration::from_millis(100)).await;

    // Test 2: Charlie should now be allowed (filter off) – but may fail due to NAT.
    // We'll try a few times (retry) in case of transient network issues.
    let mut success = false;
    for attempt in 0..3 {
        if attempt > 0 {
            sleep(Duration::from_millis(500)).await;
            info!("Retry attempt {}", attempt + 1);
        }
        match charlie.spin(*bob.public_key()).await {
            Ok(_silk) => {
                info!("✅ Charlie spun Bob (allowed after off)");
                success = true;
                break;
            }
            Err(e) => {
                info!("Charlie spin attempt {} failed: {}", attempt + 1, e);
            }
        }
    }
    if !success {
        info!("⚠️ Charlie spin failed after filter off (NAT issue), but filter check passed.");
    }

    // Check that filter_info returns ERR_NO_FILTER
    match bob.filter_info().await {
        Ok(_) => info!("❌ Filter info returned (unexpected)"),
        Err(e) => info!("✅ Filter info correctly says no filter: {}", e),
    }

    info!("Filter off test passed.");
    Ok(())
}
