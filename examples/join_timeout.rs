//! Test private network join timeout when host doesn't respond.

use rand::RngExt;
use spinneret::{KeyPair, NetworkKind, Peer};
use std::net::IpAddr;
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

    // Host (Alice)
    let alice_key = KeyPair::generate();
    info!("Alice public key: {}", hex_encode(&alice_key.public));
    let alice = Peer::new(alice_key, loom_ip, loom_pub).await?;
    alice.register().await?;
    info!("Alice registered");

    // Alice creates a private network, but does NOT start the approval task.
    let net_id: [u8; 32] = random_net_id();
    alice.register_network(net_id, NetworkKind::Private).await?;
    info!("Alice created private network (no approval task)");

    // Member (Bob) tries to join – should timeout after 5 seconds.
    let bob_key = KeyPair::generate();
    info!("Bob public key: {}", hex_encode(&bob_key.public));
    let bob = Peer::new(bob_key, loom_ip, loom_pub).await?;
    bob.register().await?;
    info!("Bob registered");

    info!("Bob joining private network (expect timeout)...");
    let start = std::time::Instant::now();
    match bob.join_network(net_id).await {
        Ok(()) => info!("❌ Bob joined (unexpected)"),
        Err(e) => {
            let elapsed = start.elapsed();
            info!("✅ Bob got error: {}", e);
            info!("   Time elapsed: {:?}", elapsed);
            // The timeout is 5 seconds; we expect ~5s.
            assert!(
                elapsed >= std::time::Duration::from_secs(4),
                "Timeout too short"
            );
        }
    }

    info!("Join timeout test passed.");
    Ok(())
}
