//! Small, easy end-to-end encryption.
//!
//! `e2ee-kit` provides the core cryptographic building blocks for encrypting
//! data end-to-end between two parties:
//!
//! - [`Keypair`] / [`PublicKey`] — X25519 identity keys
//! - [`Session`] — an established two-way encrypted channel
//! - [`Message`] — raw ChaCha20-Poly1305 authenticated encryption
//! - [`SecretBox`] — password-protected encryption for data at rest
//! - [`encrypt_keypair`] / [`decrypt_keypair`] — persist a keypair under a password
//!
//! # Quick start: two parties exchanging messages
//!
//! ```
//! use e2ee_kit::{Keypair, Role, Session};
//!
//! // Each side generates a long-term keypair and shares its public key.
//! let alice = Keypair::generate();
//! let bob = Keypair::generate();
//!
//! // Both sides establish a session with the peer's public key.
//! // The roles must be opposite.
//! let alice_side = Session::establish(&alice, bob.public_key(), Role::Initiator)?;
//! let bob_side = Session::establish(&bob, alice.public_key(), Role::Responder)?;
//!
//! let envelope = alice_side.seal(b"hello bob")?;
//! // ... send `envelope` to Bob over any transport ...
//! assert_eq!(bob_side.open(&envelope)?, b"hello bob");
//! # Ok::<(), e2ee_kit::Error>(())
//! ```
//!
//! # Password-protected storage
//!
//! ```
//! use e2ee_kit::SecretBox;
//!
//! let blob = SecretBox::seal(b"a strong password", b"data at rest")?;
//! assert_eq!(SecretBox::open(&blob, b"a strong password")?, b"data at rest");
//! # Ok::<(), e2ee_kit::Error>(())
//! ```
//!
//! # Persisting a keypair
//!
//! ```
//! use e2ee_kit::{decrypt_keypair, encrypt_keypair, Keypair};
//!
//! let keypair = Keypair::generate();
//! let blob = encrypt_keypair(&keypair, b"key storage password")?;
//! // ... write `blob` to disk ...
//! let restored = decrypt_keypair(&blob, b"key storage password")?;
//! assert_eq!(restored.public_key(), keypair.public_key());
//! # Ok::<(), e2ee_kit::Error>(())
//! ```
//!
//! # Wire formats
//!
//! Message envelope ([`Session::seal`] / [`Message::seal`]):
//!
//! ```text
//! version (1, = 0x01) | nonce (12, random) | ciphertext | Poly1305 tag (16)
//! ```
//!
//! SecretBox blob ([`SecretBox::seal`] / [`encrypt_keypair`]):
//!
//! ```text
//! version (1, = 0x01) | m_cost (4, BE) | t_cost (4, BE) | p_cost (1)
//!                     | salt (16, random) | nonce (12, random) | ciphertext + tag
//! ```
//!
//! # Security model
//!
//! This crate provides:
//!
//! - confidentiality, integrity, and authenticity of messages between two
//!   key holders (X25519 key agreement + HKDF-SHA256 + ChaCha20-Poly1305);
//! - password-protected boxes for data at rest (Argon2id + ChaCha20-Poly1305);
//! - zeroization of key material on drop.
//!
//! This crate deliberately does **not** provide:
//!
//! - **Forward secrecy.** Sessions use static-static X25519. If a long-term
//!   secret key leaks, every session that used it — past and future — is
//!   exposed. Rotate keypairs if a leak is suspected.
//! - **Key authentication.** You must authenticate a peer's [`PublicKey`] out
//!   of band (compare in person, trusted directory, etc.). This crate cannot
//!   detect a man-in-the-middle who substitutes their own public key.
//! - ratcheting, group messaging, message ordering, deduplication, or any
//!   transport.
//!
//! Limits:
//!
//! - a single session key must not seal more than roughly 2^32 messages
//!   (birthday bound on random 96-bit nonces); re-establish sessions well
//!   before that;
//! - passwords shorter than 8 bytes are rejected;
//! - Argon2id cost parameters are fixed in v0.1 (19 MiB memory, 2 passes).
//!
//! **Status: v0.1. This crate has not been independently audited.**
//!
//! # Panics
//!
//! Functions that draw randomness panic only if the OS CSPRNG is unavailable
//! on the current platform.

pub use error::Error;
pub use keys::{Keypair, PublicKey};
pub use message::Message;
pub use secretbox::SecretBox;
pub use session::{Role, Session};
pub use storage::{decrypt_keypair, encrypt_keypair};

mod error;
mod kdf;
mod keys;
mod message;
mod secretbox;
mod session;
mod storage;
