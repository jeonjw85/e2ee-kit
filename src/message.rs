use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};

use crate::Error;

/// Envelope format version byte. Also bound into the AEAD tag as AAD.
pub(crate) const VERSION: u8 = 0x01;
pub(crate) const NONCE_LEN: usize = 12;
pub(crate) const TAG_LEN: usize = 16;
/// Total envelope overhead: version byte + nonce + Poly1305 tag.
pub(crate) const OVERHEAD: usize = 1 + NONCE_LEN + TAG_LEN;

/// Authenticated encryption for individual messages.
///
/// This is the low-level primitive; most users should use [`crate::Session`],
/// which manages keys for them.
///
/// # Wire format
///
/// ```text
/// version (1) | nonce (12, random) | ciphertext (N) | Poly1305 tag (16)
/// ```
///
/// The version byte is authenticated as associated data. Every `seal` draws a
/// fresh random nonce from the OS CSPRNG, so a single key must not seal more
/// than about 2^32 messages (birthday bound on the 96-bit nonce).
pub struct Message;

impl Message {
    /// Encrypt and authenticate `plaintext` under `key`.
    ///
    /// Panics only if the OS CSPRNG is unavailable.
    pub fn seal(key: &[u8; 32], plaintext: &[u8]) -> Result<Vec<u8>, Error> {
        let cipher = ChaCha20Poly1305::new(&Key::from(*key));

        let mut nonce = [0u8; NONCE_LEN];
        getrandom::fill(&mut nonce).expect("OS CSPRNG failed");

        let ciphertext = cipher
            .encrypt(
                &Nonce::from(nonce),
                Payload {
                    msg: plaintext,
                    aad: &[VERSION],
                },
            )
            .map_err(|_| Error::DecryptionFailed)?;

        let mut envelope = Vec::with_capacity(OVERHEAD + plaintext.len());
        envelope.push(VERSION);
        envelope.extend_from_slice(&nonce);
        envelope.extend_from_slice(&ciphertext);
        Ok(envelope)
    }

    /// Verify and decrypt an envelope produced by [`Message::seal`].
    ///
    /// Returns [`Error::DecryptionFailed`] for any authentication failure;
    /// no partial plaintext is ever returned.
    pub fn open(key: &[u8; 32], envelope: &[u8]) -> Result<Vec<u8>, Error> {
        if envelope.len() < OVERHEAD {
            return Err(Error::CiphertextTooShort);
        }
        if envelope[0] != VERSION {
            return Err(Error::InvalidBlob);
        }

        let nonce = &envelope[1..1 + NONCE_LEN];
        let nonce: [u8; NONCE_LEN] = nonce.try_into().expect("bounds checked above");

        let cipher = ChaCha20Poly1305::new(&Key::from(*key));
        cipher
            .decrypt(
                &Nonce::from(nonce),
                Payload {
                    msg: &envelope[1 + NONCE_LEN..],
                    aad: &[VERSION],
                },
            )
            .map_err(|_| Error::DecryptionFailed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: [u8; 32] = [0xab; 32];

    #[test]
    fn seal_open_roundtrip() {
        let plaintext = b"hello, e2ee";
        let envelope = Message::seal(&KEY, plaintext).unwrap();
        assert_eq!(envelope.len(), plaintext.len() + OVERHEAD);
        assert_eq!(envelope[0], VERSION);
        let opened = Message::open(&KEY, &envelope).unwrap();
        assert_eq!(opened, plaintext);
    }

    #[test]
    fn empty_plaintext_roundtrip() {
        let envelope = Message::seal(&KEY, b"").unwrap();
        assert_eq!(envelope.len(), OVERHEAD);
        assert_eq!(Message::open(&KEY, &envelope).unwrap(), b"");
    }

    #[test]
    fn random_nonce_makes_seals_differ() {
        let a = Message::seal(&KEY, b"same").unwrap();
        let b = Message::seal(&KEY, b"same").unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn wrong_key_fails() {
        let envelope = Message::seal(&KEY, b"secret").unwrap();
        assert_eq!(
            Message::open(&[0xcd; 32], &envelope),
            Err(Error::DecryptionFailed)
        );
    }

    #[test]
    fn truncated_envelope_fails() {
        assert_eq!(Message::open(&KEY, &[]), Err(Error::CiphertextTooShort));
        assert_eq!(
            Message::open(&KEY, &[0u8; OVERHEAD - 1]),
            Err(Error::CiphertextTooShort)
        );
    }

    #[test]
    fn wrong_version_byte_fails() {
        let mut envelope = Message::seal(&KEY, b"x").unwrap();
        envelope[0] = 0x02;
        assert_eq!(Message::open(&KEY, &envelope), Err(Error::InvalidBlob));
    }

    #[test]
    fn tampering_any_bit_fails() {
        let plaintext = b"tamper me please";
        let envelope = Message::seal(&KEY, plaintext).unwrap();
        for offset in 0..envelope.len() {
            for bit in 0..8 {
                let mut tampered = envelope.clone();
                tampered[offset] ^= 1 << bit;
                let expected = if offset == 0 {
                    // Any change to the version byte is rejected before AEAD.
                    Err(Error::InvalidBlob)
                } else {
                    Err(Error::DecryptionFailed)
                };
                assert_eq!(Message::open(&KEY, &tampered), expected);
            }
        }
    }
}
