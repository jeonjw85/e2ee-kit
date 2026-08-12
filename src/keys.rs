use core::fmt;

use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};
use zeroize::Zeroizing;

use crate::Error;

/// An X25519 public key (32 bytes).
///
/// `Debug`/`Display` print the lowercase hex encoding. Public keys are safe
/// to log and to transmit, but they must be *authenticated* out of band:
/// this crate does not verify who owns a key.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct PublicKey(X25519PublicKey);

impl PublicKey {
    /// Decode a public key from its 32-byte representation.
    ///
    /// Every 32-byte value is a valid X25519 encoding, so this does not fail
    /// on the bytes themselves; the `Result` is kept for future validation.
    /// Invalid or malicious keys are rejected later, when a [`Session`]
    /// produces a degenerate shared secret.
    ///
    /// [`Session`]: crate::Session
    pub fn from_bytes(bytes: [u8; 32]) -> Result<PublicKey, Error> {
        Ok(PublicKey(X25519PublicKey::from(bytes)))
    }

    /// Encode the public key as 32 bytes.
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }

    pub(crate) fn as_inner(&self) -> &X25519PublicKey {
        &self.0
    }
}

impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PublicKey({self})")
    }
}

impl fmt::Display for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write_hex(f, &self.0.to_bytes())
    }
}

/// An X25519 keypair: a long-term secret key and its public key.
///
/// The secret key is zeroized on drop. `Debug` prints only the public key.
pub struct Keypair {
    secret: StaticSecret,
    public: PublicKey,
}

impl Keypair {
    /// Generate a fresh keypair from the OS CSPRNG.
    pub fn generate() -> Keypair {
        let secret = StaticSecret::random();
        let public = PublicKey(X25519PublicKey::from(&secret));
        Keypair { secret, public }
    }

    /// Restore a keypair from raw secret-key bytes.
    ///
    /// The same input always yields the same keypair, so keys can be stored
    /// and reloaded (see [`crate::encrypt_keypair`]).
    pub fn from_secret_bytes(secret: [u8; 32]) -> Keypair {
        let secret = Zeroizing::new(secret);
        let secret = StaticSecret::from(*secret);
        let public = PublicKey(X25519PublicKey::from(&secret));
        Keypair { secret, public }
    }

    /// The public half of this keypair.
    pub fn public_key(&self) -> PublicKey {
        self.public
    }

    /// The public key as 32 bytes, e.g. to hand to a peer or a server.
    pub fn to_public_bytes(&self) -> [u8; 32] {
        self.public.to_bytes()
    }

    /// The secret key as 32 bytes, wrapped so it is zeroized on drop.
    ///
    /// Advanced/interop only. To persist a keypair, prefer
    /// [`crate::encrypt_keypair`], which encrypts it under a password.
    pub fn to_secret_bytes(&self) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(self.secret.to_bytes())
    }

    pub(crate) fn static_secret(&self) -> &StaticSecret {
        &self.secret
    }
}

impl fmt::Debug for Keypair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Keypair")
            .field("public", &self.public)
            .finish()
    }
}

fn write_hex(f: &mut fmt::Formatter<'_>, bytes: &[u8]) -> fmt::Result {
    for byte in bytes {
        write!(f, "{byte:02x}")?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex32(s: &str) -> [u8; 32] {
        let mut out = [0u8; 32];
        for (i, byte) in out.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap();
        }
        out
    }

    #[test]
    fn public_key_roundtrip() {
        let keypair = Keypair::generate();
        let bytes = keypair.to_public_bytes();
        let decoded = PublicKey::from_bytes(bytes).unwrap();
        assert_eq!(decoded, keypair.public_key());
        assert_eq!(decoded.to_bytes(), bytes);
    }

    #[test]
    fn secret_bytes_roundtrip() {
        let keypair = Keypair::generate();
        let restored = Keypair::from_secret_bytes(*keypair.to_secret_bytes());
        assert_eq!(restored.public_key(), keypair.public_key());
        assert_eq!(&*restored.to_secret_bytes(), &*keypair.to_secret_bytes());
    }

    #[test]
    fn from_secret_bytes_is_deterministic() {
        let bytes = [42u8; 32];
        let a = Keypair::from_secret_bytes(bytes);
        let b = Keypair::from_secret_bytes(bytes);
        assert_eq!(a.public_key(), b.public_key());
    }

    #[test]
    fn rfc7748_public_key_derivation() {
        let alice_secret =
            hex32("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
        let alice_public =
            hex32("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a");
        let keypair = Keypair::from_secret_bytes(alice_secret);
        assert_eq!(keypair.to_public_bytes(), alice_public);
    }

    #[test]
    fn debug_does_not_leak_secret() {
        let keypair = Keypair::generate();
        let debug = format!("{keypair:?}");
        assert!(debug.contains(&keypair.public_key().to_string()));
        let secret_hex = {
            let bytes = keypair.to_secret_bytes();
            let mut s = String::new();
            for b in bytes.iter() {
                s.push_str(&format!("{b:02x}"));
            }
            s
        };
        assert!(!debug.contains(&secret_hex));
    }
}
