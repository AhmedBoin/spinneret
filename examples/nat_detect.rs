use spinneret::{KeyPair, Peer};
use std::net::IpAddr;
use tracing::info;

/// Replace with the hex-encoded public key printed by your Loom server.
const LOOM_PUB_HEX: &str = "7f0d4a53e547d3ed980869c8cf6ca4c9065af1313553717b6eb2b4cd3ac6744f";

/// Loom server IP address.
const LOOM_IP: &str = "129.80.223.49";

fn parse_hex_32(s: &str) -> [u8; 32] {
    let s = s.trim();
    assert_eq!(s.len(), 64, "hex key must be 64 hex chars");
    let mut out = [0u8; 32];
    for i in 0..32 {
        out[i] = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).expect("invalid hex");
    }
    out
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let loom_ip: IpAddr = LOOM_IP.parse().unwrap();
    let loom_pub = parse_hex_32(LOOM_PUB_HEX);

    // Each peer generates its own X25519 key pair
    let keypair = KeyPair::from_private(parse_hex_32(
        "929aa990dc13aaa12f05a65c23706bcb66b1000d2ea58fab3d6a9f9598157071",
    ));
    info!("public key: {}", hex_encode(&keypair.public));

    // Connect to the Loom server
    let peer = Peer::new(keypair, loom_ip, loom_pub).await?;

    // Register on the Loom (detects NAT type automatically)
    let my_info = peer.register().await?;
    info!(
        "registered: global={} nat={:?}",
        my_info.global.to_socket(),
        my_info.nat
    );

    Ok(())
}

fn hex_encode(b: &[u8]) -> String {
    b.iter().map(|x| format!("{:02x}", x)).collect()
}
