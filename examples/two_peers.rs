//! Two peers in the same process: Alice spins Bob and they exchange messages.
//!
//! This is useful for local testing. No need to run two terminals.
//! For cross‑machine testing, use the `chat` example with arguments.

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
    let alice_info = alice.register().await?;
    info!("Alice registered: global={}", alice_info.global.to_socket());

    // ─── Bob ───────────────────────────────────────────────────────
    let bob_key = KeyPair::generate();
    info!("Bob public key: {}", hex_encode(&bob_key.public));

    let bob = Peer::new(bob_key, loom_ip, loom_pub).await?;
    let bob_info = bob.register().await?;
    info!("Bob registered: global={}", bob_info.global.to_socket());

    // ─── Let them discover each other ────────────────────────────
    sleep(Duration::from_millis(500)).await;

    // Alice spins Bob.
    info!("Alice spinning Bob...");
    let silk = alice.spin(*bob.public_key()).await?;
    info!("Alice: silk established to {}", silk.remote_addr);

    // Bob accepts the spin (manual accept loop – no auto‑accept).
    let bob_silk = loop {
        if let Some(caller) = bob.next_spin().await {
            info!("Bob got spin from {}", hex_encode(&caller.pubkey));
            let silk = bob.accept(caller).await?;
            break silk;
        }
        sleep(Duration::from_millis(100)).await;
    };

    info!("Bob: silk established to {}", bob_silk.remote_addr);

    // ─── Exchange messages ────────────────────────────────────────
    let msg = b"Hello Bob!";
    silk.send(msg).await?;
    info!("Alice sent: {:?}", String::from_utf8_lossy(msg));

    let received = bob_silk.recv().await?;
    info!("Bob received: {:?}", String::from_utf8_lossy(&received));

    let reply = b"Hello Alice!";
    bob_silk.send(reply).await?;
    info!("Bob sent: {:?}", String::from_utf8_lossy(reply));

    let reply_received = silk.recv().await?;
    info!(
        "Alice received: {:?}",
        String::from_utf8_lossy(&reply_received)
    );

    info!("Test completed successfully.");
    Ok(())
}
