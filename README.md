# Spinneret

**UDP P2P networking with NAT traversal — encrypted, sessionless, minimal.**

```
Peer A ──── Spin ────► Loom ────► SpinNotify ────► Peer B
        ◄── PeerInfo ──              ◄── (addr)

Peer A ◄────────────────── Silk ──────────────────► Peer B
               (direct UDP, no server)
```

Spinneret is a lightweight P2P networking library that connects peers through a single coordination server (the **Loom**). Every packet is encrypted with **X25519 + ChaCha20‑Poly1305**. No sessions, no handshakes, no persistent connections to the server — just encrypted datagrams.

Once peers discover each other through the Loom, they establish a direct UDP connection (a **Silk**) using NAT hole punching. The Loom is never involved in the data path.

---

## Why the name?

In nature, a spider spins **silks** from its spinnerets to build webs. Each silk is a strong, flexible thread that connects distant anchor points. Our library does the same: it weaves direct, peer‑to‑peer **Silks** between devices, using the **Loom** server as the initial anchor point. The Loom coordinates the spinning; the peers themselves form the web.

---

## Features

- **Encrypted by default** — every packet to/from the Loom is encrypted with X25519 ECDH + ChaCha20‑Poly1305
- **NAT traversal** — 4 strategies covering Fixed/Variable NAT combinations + same‑router LAN optimisation
- **No sessions** — every packet is independently decryptable; no handshake or session state needed
- **Networks** — create public or private groups with member‑based access control
- **Filters** — whitelist/blacklist to control who can connect to you
- **Minimal** — single UDP socket per peer, ~2000 lines of Rust
- **Persistent** — Loom uses Sled embedded database (no external DB needed)

---

## Understanding NAT Types

To help Spinneret choose the right hole‑punch strategy, the Loom classifies each peer’s NAT into one of two broad categories:

- **Fixed NAT** – The NAT device maps the same external port for all outbound connections (regardless of destination).  
  This includes:
  - **Full Cone**: any external host can send to the mapped port.
  - **Restricted Cone**: only hosts that the internal peer has previously sent to can send back.
  - **Restricted Port**: same as Restricted Cone, but the destination port must also match.

- **Variable NAT** – The external port changes depending on the destination IP:port.  
  This includes **Symmetric NAT**, where each new connection uses a new port.

Spinneret detects which type you have by sending packets to both Loom ports. If the observed source port is the **same** on both, it's **Fixed**; if **different**, it's **Variable**. The library then uses the appropriate punch strategy.

---

## Quick Start

### 1. Use a public Loom server (for testing)

We provide a public Loom server at:

```
IP:         129.80.223.49
Port1:      27531
Port2:      27532
Public key: 7f0d4a53e547d3ed980869c8cf6ca4c9065af1313553717b6eb2b4cd3ac6744f
```

You can use this server for development and testing. It runs the latest version of the Spinneret Loom and automatically cleans up stale records.

### 2. Add the dependency

```toml
[dependencies]
spinneret = "1.0.0"
```

### 3. Connect two peers

```rust
use spinneret::{KeyPair, Peer};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let loom_ip = "129.80.223.49".parse()?;
    let loom_pub = hex_to_32("7f0d4a53e547d3ed980869c8cf6ca4c9065af1313553717b6eb2b4cd3ac6744f");

    let keypair = KeyPair::generate();
    let peer = Peer::new(keypair, loom_ip, loom_pub).await?;

    // Register (detects NAT type automatically)
    let my_info = peer.register().await?;
    println!("Registered: {} ({:?})", my_info.global.to_socket(), my_info.nat);

    // Spin another peer (you need their public key)
    let target_pubkey = hex_to_32("...");
    let silk = peer.spin(target_pubkey).await?;

    // Send and receive
    silk.send(b"Hello!").await?;
    let msg = silk.recv().await?;
    println!("Received: {}", String::from_utf8_lossy(&msg));

    Ok(())
}

fn hex_to_32(s: &str) -> [u8; 32] { /* ... */ }
```

For complete examples, see the [`examples/`](examples/) directory.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        Loom Server                             │
│  (UDP ports 27531 + 27532, Sled DB, X25519 key pair)          │
│                                                                 │
│  • Registers peers (10 min TTL)                                │
│  • Detects NAT type (Fixed vs Variable via dual ports)         │
│  • Manages networks (public/private)                           │
│  • Forwards Spin requests + checks filters                     │
│  • Relays private network join approvals                       │
│  • GC every 60s to remove expired records                      │
└─────────────────────────────────────────────────────────────────┘
               │                          │
          Encrypted UDP              Encrypted UDP
       (X25519+ChaCha20)         (X25519+ChaCha20)
               │                          │
     ┌─────────▼──────────┐    ┌─────────▼──────────┐
     │     Peer A         │    │     Peer B         │
     │  (X25519 keypair)  │    │  (X25519 keypair)  │
     │                    │    │                    │
     │  ┌──────────────┐  │    │  ┌──────────────┐  │
     │  │ SilkRegistry │  │    │  │ SilkRegistry │  │
     │  │ (P2P silks)  │  │    │  │ (P2P silks)  │  │
     │  └──────────────┘  │    │  └──────────────┘  │
     └────────────────────┘    └────────────────────┘
              │                          │
              └─────────── Silk ─────────┘
                   (raw UDP, app‑layer encryption optional)
```

### Wire Format (Encrypted)

Every encrypted packet:

```
sender_pubkey[32] | nonce[12] | ChaCha20-Poly1305_ciphertext[..+16]
```

After decryption:

```
timestamp[8] | validity_secs[1] | CMD[1] | payload[..N]
```

- **Key agreement**: `shared_secret = X25519(receiver_privkey, sender_pubkey)`
- **Encryption**: ChaCha20‑Poly1305 with `(shared_secret, nonce)`
- **Replay protection**: timestamp + validity window (max 10 seconds)
- **Authentication**: Poly1305 tag — tampered packets fail decryption

---

## Client API

### Creating a Peer

```rust
use spinneret::{KeyPair, Peer};

// Generate a new identity (or restore from stored private key)
let keypair = KeyPair::generate();
let peer = Peer::new(keypair, loom_ip, loom_pub).await?;
```

### Registration & Keepalive

```rust
// Register (detects NAT automatically)
let info = peer.register().await?;

// Re‑register with cached info (skip NAT detection)
peer.login(info).await?;

// Keepalive — send every < 10 minutes to stay registered
peer.tangle().await?;
```

### Connecting to a Peer (Spin)

```rust
// Spin a peer by their public key
let silk = peer.spin(target_pubkey).await?;

// Send data
silk.send(b"hello").await?;

// Receive data (blocking)
let msg = silk.recv().await?;

// Non‑blocking receive
if let Some(msg) = silk.try_recv().await { /* ... */ }
```

### Receiving Incoming Connections

```rust
// Manual accept – you can inspect the caller before accepting
if let Some(caller) = peer.next_spin().await {
    // `caller` is a PeerInfo containing:
    //   - pubkey: the caller's X25519 public key
    //   - global: their public IP:port
    //   - local:  their LAN address (if known)
    //   - nat:    their NAT type (Fixed/Variable)

    // You can inspect this data and decide whether to accept.
    if is_trusted(&caller.pubkey) {
        let silk = peer.accept(caller).await?;
        // Use silk...
    }
}

// Auto‑accept (background task)
let mut silk_rx = peer.enable_auto_accept().await;
while let Some(silk) = silk_rx.recv().await {
    // Use silk...
}
```

### Filters

```rust
use spinneret::FilterMode;

// Whitelist: only allow specific peers
peer.set_filter(FilterMode::Whitelist).await?;
peer.add_peer_filter(allowed_pubkey).await?;

// Blacklist: block specific peers
peer.set_filter(FilterMode::Blacklist).await?;
peer.add_peer_filter(blocked_pubkey).await?;

// Turn off filter
peer.set_filter(FilterMode::Off).await?;

// Get current filter info
let info = peer.filter_info().await?;
```

### Networks

```rust
use spinneret::NetworkKind;

// Create a public network
let net_id = [0x01u8; 32];
peer.register_network(net_id, NetworkKind::Public).await?;

// Create a private network (you become the host)
peer.register_network(net_id, NetworkKind::Private).await?;

// Join a network
peer.join_network(net_id).await?;

// Get network info
let info = peer.network_info(net_id).await?;
println!("Members: {}", info.member_count);

// Get a member by index
let member = peer.get_net_peer(net_id, 0).await?;

// Spin a network member
let silk = peer.spin(member.pubkey).await?;

// Network keepalive (host only for private networks)
peer.tangle_network(net_id).await?;

// Private network: host approves join requests
if let Some((net_id, joiner)) = peer.next_host_join_request().await {
    peer.reply_join_request(net_id, joiner.pubkey, true).await?; // approve
}
```

---

## Running Your Own Loom Server

### 1. Build the binary

```bash
cargo build --release --bin loom
```

### 2. Create `loom.toml`

```toml
# ── Spinneret Loom Server Config ──────────────────────────────────
# Place this file next to the spinneret-loom binary.
# The server finds it automatically on startup.

[loom]
# Primary port — all commands come here
port1 = 27531

# Secondary port — used only to observe the external port
# for NAT type detection (Fixed vs Variable)
port2 = 27532

# Database path (relative to binary location)
db_path = "./spinneret.db"

# Hex‑encoded 32‑byte X25519 private key.
# If omitted, an ephemeral key is generated on each restart.
# Generate one with:  python3 -c "import os; print(os.urandom(32).hex())"
# private_key = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
```

### 3. Open firewall ports

```
27531/udp
27532/udp
```

### 4. Run the Loom

```bash
RUST_LOG=info ./loom
```

On first run, the server prints its public key:

```
Loom public key: 7f0d4a53e547d3ed980869c8cf6ca4c9065af1313553717b6eb2b4cd3ac6744f
```

Share this key with all peers that connect to your Loom.

### 5. Point peers at your server

```rust
let loom_ip = "your.server.ip".parse()?;
let loom_pub = hex_to_32("...");
let peer = Peer::new(keypair, loom_ip, loom_pub).await?;
```

---

## Protocol Summary

For the full wire specification, see [`PROTOCOL.md`](PROTOCOL.md).

### Peer → Loom

| CMD | Name | Description | Reply |
|-----|------|-------------|-------|
| 0x00 | NAT | Send to port1 for NAT detection | PeerInfo |
| 0x01 | CONAT | Send to port2 for NAT detection | PeerInfo |
| 0x02 | Login | Re‑register with cached PeerInfo | Ok |
| 0x03 | Tangle | Keepalive (request‑response) | Ok |
| 0x04 | SetFilter | Set whitelist/blacklist/off | Ok |
| 0x05 | FilterInfo | Get current filter | FilterInfo |
| 0x06 | AddPeerFilter | Add key to filter | Ok |
| 0x08 | RemovePeerFilter | Remove key from filter | Ok |
| 0x09 | RegisterNetwork | Create a network | Ok |
| 0x0A | NetworkInfo | Get network metadata | NetworkInfo |
| 0x0B | GetNetPeer | Get member by index | PeerInfo |
| 0x0C | TangleNetwork | Network keepalive | Ok |
| 0x0D | JoinNetwork | Join a network | Ok |
| 0x0E | Spin | Signal a peer to connect | PeerInfo |
| 0xF7 | HostJoinResp | Host approves/refuses join | (delivered to joiner) |

### Loom → Peer

| CMD | Name | Description |
|-----|------|-------------|
| 0xF0 | Ok | Success |
| 0xF1 | Err(code) | Error with code |
| 0xF2 | PeerInfo | Peer information |
| 0xF3 | NetworkInfo | Network information |
| 0xF4 | FilterInfo | Filter information |
| 0xF5 | SpinNotify | Incoming spin notification |
| 0xF6 | AskHostJoin | Host join request |
| 0xF7 | HostJoinResp | Host join response |

### Peer ↔ Peer (raw UDP)

| Byte | Name | Description |
|------|------|-------------|
| 0xEB | Entangle | Hole punch / keepalive |
| 0xEC | EntangleAck | Acknowledge entangle |
| 0xDA | SilkData | Application data |

---

## NAT Traversal Strategies

| Your NAT | Remote NAT | Strategy |
|----------|------------|----------|
| Fixed | Fixed | Both send entangle packets to each other's IP:port until connected |
| Fixed | Variable | Fixed sprays ±50 ports; Variable opens 100 sockets |
| Variable | Fixed | Variable opens 100 sockets, sprays from all to fixed target |
| Variable | Variable | Both open 100 sockets, both spray ±50 ports (10,000 combos) |

### Same‑Router Optimisation

If both peers have **Fixed** NAT and the **same global IP**, the local (LAN) address is tried first. Falls back to global if LAN fails.

### Timeouts

- **Hole punch**: 15 seconds
- **Post‑punch blast**: 3 seconds (ensures remote receives at least one packet)
- **Idle keepalive**: 30 seconds (entangle sent if no activity)

---

## TTL & Garbage Collection

| Record | TTL | GC Interval |
|--------|-----|-------------|
| Peer | 10 min from last Tangle | 60 seconds |
| Network | 10 min from last TangleNetwork | 60 seconds |
| Filter | Persistent (no TTL) | — |

---

## Security

1. **Identity**: X25519 public key (32 bytes). Private key possession proven by successful decryption.
2. **Encryption**: ChaCha20‑Poly1305 with per‑packet X25519 shared secret. Every packet independently decryptable.
3. **Replay protection**: timestamp + validity window (max 10s) inside encrypted payload.
4. **Authentication**: Poly1305 AEAD tag. Tampered packets fail decryption.
5. **Filters**: enforced at Loom level. Blocked peers never learn you exist.
6. **Silk data**: not encrypted by protocol. Application should layer its own encryption (e.g., Noise, TLS 1.3 DTLS).

---

## Use Cases

- **Serverless chat** – Groups allow real‑time messaging without a central server.
- **Multiplayer games** – Host creates a network, players join and connect directly.
- **Distributed file sharing** – Peers register with an ID, others connect and exchange data.
- **IoT device mesh** – Each device registers, hub connects to registered devices.
- **P2P voice/video** – Exchange SDP/ICE‑like data over the Silk connection.

---

## License

MIT

---

## Contributions & Support

Contributions are welcome! Please open issues and pull requests on [GitHub](https://github.com/spinneret-rs/spinneret).

For questions or discussions, use the [Discussions](https://github.com/spinneret-rs/spinneret/discussions) board.