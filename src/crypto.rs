//! Cryptography layer — Spinneret packet encryption.
//!
//! Every packet on the wire:
//!   sender_pubkey[32] | nonce[12] | ciphertext[..] | poly1305_tag[16]
//!
//! The ciphertext decrypts to: CMD[1] | payload[..]
//!
//! Key derivation: shared_secret = X25519(receiver_privkey, sender_pubkey)
//! Encryption:     ChaCha20-Poly1305(key=shared_secret, nonce=nonce, msg=[cmd|payload])
//!
//! The nonce is also used as a deduplification id to drop duplicate UDP packets.

use curve25519_dalek::constants::X25519_BASEPOINT;
use curve25519_dalek::montgomery::MontgomeryPoint;
use curve25519_dalek::scalar::Scalar;
use rand::Rng;
use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, CHACHA20_POLY1305};

use crate::error::Error;

pub const PUBKEY_LEN: usize = 32;
pub const NONCE_LEN: usize = 12;
pub const TAG_LEN: usize = 16;
/// Overhead added per packet: pubkey + nonce + poly1305 tag
pub const PACKET_OVERHEAD: usize = PUBKEY_LEN + NONCE_LEN + TAG_LEN;
/// Maximum payload before encryption (MTU 1400 - overhead)
pub const MAX_PLAINTEXT: usize = 1400 - PACKET_OVERHEAD;

// ── Key pair ──────────────────────────────────────────────────────

#[derive(Clone)]
pub struct KeyPair {
    pub private: [u8; 32], // raw scalar bytes
    pub public: [u8; 32],  // X25519 base * scalar
}

impl KeyPair {
    /// Generate a new random key pair.
    pub fn generate() -> Self {
        let mut private = [0u8; 32];
        rand::rng().fill_bytes(&mut private);
        // Clamp per X25519 spec
        private[0] &= 248;
        private[31] &= 127;
        private[31] |= 64;
        let public = x25519_public(&private);
        Self { private, public }
    }

    /// Restore from stored private key bytes.
    pub fn from_private(private: [u8; 32]) -> Self {
        let public = x25519_public(&private);
        Self { private, public }
    }
}

fn x25519_public(private: &[u8; 32]) -> [u8; 32] {
    let scalar = Scalar::from_bytes_mod_order(*private);
    let point: MontgomeryPoint = scalar * X25519_BASEPOINT;
    *point.as_bytes()
}

/// X25519 Diffie-Hellman: our_private * their_pubkey → shared secret.
fn x25519_dh(our_private: &[u8; 32], their_public: &[u8; 32]) -> [u8; 32] {
    let scalar = Scalar::from_bytes_mod_order(*our_private);
    let point = MontgomeryPoint(*their_public);
    *(scalar * point).as_bytes()
}

// ── Nonce ─────────────────────────────────────────────────────────

/// Generate a cryptographically random 12-byte nonce.
pub fn random_nonce() -> [u8; NONCE_LEN] {
    let mut n = [0u8; NONCE_LEN];
    rand::rng().fill_bytes(&mut n);
    n
}

// ── Encrypt / Decrypt ────────────────────────────────────────────

/// Build a sealed packet:
///   sender_pubkey[32] | nonce[12] | ChaCha20-Poly1305(plaintext)[..+16]
///
/// `plaintext` = CMD[1] | payload[..]
/// `our_key`   = sender's key pair (pubkey goes into packet header)
/// `their_pub` = receiver's public key (used for DH)
/// `nonce`     = fresh random 12 bytes (also serves as dedup id)
pub fn seal(
    our_key: &KeyPair,
    their_pub: &[u8; PUBKEY_LEN],
    nonce: &[u8; NONCE_LEN],
    plaintext: &[u8],
) -> Result<Vec<u8>, Error> {
    let shared = x25519_dh(&our_key.private, their_pub);
    let ring_key = make_ring_key(&shared)?;

    let mut ciphertext = plaintext.to_vec();

    let nonce_obj = Nonce::assume_unique_for_key(*nonce);
    // seal_in_place appends the 16-byte Poly1305 tag
    ring_key
        .seal_in_place_append_tag(nonce_obj, Aad::empty(), &mut ciphertext)
        .map_err(|e| Error::Crypto(e.to_string()))?;

    let mut buf = Vec::with_capacity(PUBKEY_LEN + NONCE_LEN + ciphertext.len());
    buf.extend_from_slice(&our_key.public);
    buf.extend_from_slice(nonce);
    buf.extend_from_slice(&ciphertext);

    Ok(buf)
}

/// Open a received packet. Returns the plaintext (CMD[1] | payload[..]).
///
/// `raw`       = full UDP datagram
/// `our_key`   = receiver's key pair
/// Returns also the sender's public key extracted from the header.
#[allow(clippy::type_complexity)]
pub fn open<'a>(
    our_key: &KeyPair,
    raw: &'a mut [u8],
) -> Result<([u8; PUBKEY_LEN], [u8; NONCE_LEN], &'a [u8]), Error> {
    if raw.len() < PUBKEY_LEN + NONCE_LEN + TAG_LEN {
        return Err(Error::Proto("packet too short".into()));
    }

    let mut sender_pub = [0u8; PUBKEY_LEN];
    sender_pub.copy_from_slice(&raw[..PUBKEY_LEN]);

    let mut nonce = [0u8; NONCE_LEN];
    nonce.copy_from_slice(&raw[PUBKEY_LEN..PUBKEY_LEN + NONCE_LEN]);

    let shared = x25519_dh(&our_key.private, &sender_pub);
    let ring_key = make_ring_key(&shared)?;
    let nonce_obj = Nonce::assume_unique_for_key(nonce);

    let ct_and_tag = &mut raw[PUBKEY_LEN + NONCE_LEN..];
    let plaintext = ring_key
        .open_in_place(nonce_obj, Aad::empty(), ct_and_tag)
        .map_err(|_| Error::Crypto("decryption failed (wrong key or tampered)".into()))?;

    Ok((sender_pub, nonce, plaintext))
}

fn make_ring_key(shared_secret: &[u8; 32]) -> Result<LessSafeKey, Error> {
    let unbound = UnboundKey::new(&CHACHA20_POLY1305, shared_secret)
        .map_err(|e| Error::Crypto(e.to_string()))?;
    Ok(LessSafeKey::new(unbound))
}
