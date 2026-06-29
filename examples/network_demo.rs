//! Network demo: public and private networks.

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

    // ─── Alice (host) ─────────────────────────────────────────────
    let alice_key = KeyPair::generate();
    info!("Alice (host) public key: {}", hex_encode(&alice_key.public));
    let alice = Peer::new(alice_key, loom_ip, loom_pub).await?;
    alice.register().await?;
    info!("Alice registered");

    // ─── Bob (member) ─────────────────────────────────────────────
    let bob_key = KeyPair::generate();
    info!("Bob (member) public key: {}", hex_encode(&bob_key.public));
    let bob = Peer::new(bob_key, loom_ip, loom_pub).await?;
    bob.register().await?;
    info!("Bob registered");

    // ─── Charlie (member) ─────────────────────────────────────────
    let charlie_key = KeyPair::generate();
    info!(
        "Charlie (member) public key: {}",
        hex_encode(&charlie_key.public)
    );
    let charlie = Peer::new(charlie_key, loom_ip, loom_pub).await?;
    charlie.register().await?;
    info!("Charlie registered");

    sleep(Duration::from_millis(500)).await;

    let net_id: [u8; 32] = random_net_id();

    // ─── Public network ────────────────────────────────────────────
    info!("--- Public network ---");
    alice.register_network(net_id, NetworkKind::Public).await?;
    info!("Alice created public network");

    bob.join_network(net_id).await?;
    info!("Bob joined public network");

    let net_info = bob.network_info(net_id).await?;
    info!("Public network members: {}", net_info.member_count);

    // ─── Private network ───────────────────────────────────────────
    info!("--- Private network ---");
    let private_id: [u8; 32] = random_net_id();
    alice
        .register_network(private_id, NetworkKind::Private)
        .await?;
    info!("Alice created private network");

    // Spawn task to handle join requests on Alice
    let alice_clone = alice.clone();
    tokio::spawn(async move {
        loop {
            if let Some((net_id_req, joiner)) = alice_clone.next_host_join_request().await {
                info!("Alice: join request from {}", hex_encode(&joiner.pubkey));
                if let Err(e) = alice_clone
                    .reply_join_request(net_id_req, joiner.pubkey, true)
                    .await
                {
                    info!("Alice: failed to approve: {}", e);
                } else {
                    info!("Alice: approved join");
                }
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    });

    info!("Charlie joining private network...");
    match charlie.join_network(private_id).await {
        Ok(()) => info!("Charlie joined private network"),
        Err(e) => info!("Charlie failed: {}", e),
    }

    let net_info_priv = charlie.network_info(private_id).await?;
    info!("Private network members: {}", net_info_priv.member_count);

    // ─── Tangle network tests ──────────────────────────────────────
    info!("--- Tangle network ---");
    alice.tangle_network(private_id).await?;
    info!("Alice tangled private network (allowed)");

    match charlie.tangle_network(private_id).await {
        Ok(()) => info!("❌ Charlie tangled private network (unexpected)"),
        Err(e) => info!("✅ Charlie tangled private network (refused): {}", e),
    }

    bob.tangle_network(net_id).await?;
    info!("Bob tangled public network (allowed)");

    info!("Network tests completed successfully.");
    Ok(())
}
