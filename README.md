English | [한국어](README.ko.md)

# e2ee-kit

Small, easy end-to-end encryption for Rust.

`e2ee-kit` provides the core cryptographic building blocks for encrypting data
end-to-end between two parties: X25519 keypairs, authenticated sessions,
ChaCha20-Poly1305 messages, and Argon2id password boxes. No server, no
runtime configuration, minimal dependencies.

> **Status: v0.1 — not independently audited.** Read the
> [security model](#security-model) before shipping anything real.

## Features

- X25519 keypairs: generate, serialize, restore from bytes
- Two-way sessions from a single key exchange (HKDF-SHA256 key derivation)
- Authenticated encryption with random nonces — envelopes are self-contained
  byte arrays, safe on any transport
- Password-protected secret boxes and encrypted keypair storage (Argon2id)

## Quick start

```sh
cargo add e2ee-kit
```

### Two parties exchanging messages

```rust
use e2ee_kit::{Keypair, Role, Session};

fn main() -> Result<(), e2ee_kit::Error> {
    // Each side generates a long-term keypair and shares its public key.
    let alice = Keypair::generate();
    let bob = Keypair::generate();

    // Both sides establish a session with the peer's public key.
    // The roles must be opposite.
    let alice_side = Session::establish(&alice, bob.public_key(), Role::Initiator)?;
    let bob_side = Session::establish(&bob, alice.public_key(), Role::Responder)?;

    let envelope = alice_side.seal(b"hello bob")?;
    // ... send `envelope` to Bob over any transport ...
    assert_eq!(bob_side.open(&envelope)?, b"hello bob");
    Ok(())
}
```

### Password-protected storage

```rust
use e2ee_kit::SecretBox;

fn main() -> Result<(), e2ee_kit::Error> {
    let blob = SecretBox::seal(b"a strong password", b"data at rest")?;
    assert_eq!(SecretBox::open(&blob, b"a strong password")?, b"data at rest");
    Ok(())
}
```

### Persisting a keypair

```rust
use e2ee_kit::{decrypt_keypair, encrypt_keypair, Keypair};

fn main() -> Result<(), e2ee_kit::Error> {
    let keypair = Keypair::generate();
    let blob = encrypt_keypair(&keypair, b"key storage password")?;
    // ... write `blob` to disk ...
    let restored = decrypt_keypair(&blob, b"key storage password")?;
    assert_eq!(restored.public_key(), keypair.public_key());
    Ok(())
}
```

## Wire formats

Message envelope (`Session::seal` / `Message::seal`), 29 bytes overhead:

```text
version (1, = 0x01) | nonce (12, random) | ciphertext | Poly1305 tag (16)
```

SecretBox blob (`SecretBox::seal` / `encrypt_keypair`):

```text
version (1, = 0x01) | m_cost (4, BE) | t_cost (4, BE) | p_cost (1)
                    | salt (16, random) | nonce (12, random) | ciphertext + tag
```

The version byte / header is authenticated as AEAD associated data. Random
nonces are drawn from the OS CSPRNG per message.

## Security model

This crate provides:

- confidentiality, integrity, and authenticity of messages between two key
  holders (X25519 + HKDF-SHA256 + ChaCha20-Poly1305)
- password-protected boxes for data at rest (Argon2id + ChaCha20-Poly1305)
- zeroization of key material on drop

This crate deliberately does **not** provide:

- **Forward secrecy.** Sessions use static-static X25519. If a long-term
  secret key leaks, every session that used it — past and future — is
  exposed. Rotate keypairs if a leak is suspected.
- **Key authentication.** You must authenticate a peer's public key out of
  band (compare in person, trusted directory, etc.). This crate cannot detect
  a man-in-the-middle who substitutes their own public key.
- ratcheting, group messaging, message ordering, deduplication, or any
  transport.

Limits:

- a single session key must not seal more than roughly 2^32 messages
  (birthday bound on random 96-bit nonces); re-establish sessions well before
  that
- passwords shorter than 8 bytes are rejected
- Argon2id cost parameters are fixed in v0.1 (19 MiB memory, 2 passes)

## MSRV

Rust 1.85, edition 2024. std-only in v0.1; `no_std` + `alloc` may come later.

## License

MIT - [LICENSE-MIT](LICENSE-MIT)
