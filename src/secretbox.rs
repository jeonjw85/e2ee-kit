use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use zeroize::Zeroizing;

use crate::Error;

/// Blob format version byte. Also part of the AEAD associated data.
pub(crate) const VERSION: u8 = 0x01;
pub(crate) const SALT_LEN: usize = 16;
pub(crate) const NONCE_LEN: usize = 12;
pub(crate) const TAG_LEN: usize = 16;
pub(crate) const KEY_LEN: usize = 32;
/// version + m_cost + t_cost + p_cost + salt + nonce
pub(crate) const HEADER_LEN: usize = 1 + 4 + 4 + 1 + SALT_LEN + NONCE_LEN;
pub(crate) const MIN_BLOB_LEN: usize = HEADER_LEN + TAG_LEN;

/// Passwords shorter than this are rejected outright.
pub(crate) const MIN_PASSWORD_LEN: usize = 8;

// Fixed Argon2id parameters for v0.1 (OWASP recommended minimum).
pub(crate) const M_COST: u32 = 19456; // KiB
pub(crate) const T_COST: u32 = 2;
pub(crate) const P_COST: u8 = 1;

// Sanity bounds on stored parameters, enforced before deriving. They stop a
// malicious blob from burning unbounded CPU/memory on open.
const MAX_M_COST: u32 = 1 << 21; // 2 GiB
const MAX_T_COST: u32 = 64;
const MAX_P_COST: u8 = 16;

/// Password-protected encryption for data at rest.
///
/// # Wire format
///
/// ```text
/// version (1) | m_cost (4, BE) | t_cost (4, BE) | p_cost (1)
///             | salt (16, random) | nonce (12, random) | ciphertext + tag
/// ```
///
/// The whole header (through the nonce) is authenticated as AEAD associated
/// data. Parameters are stored in the blob and bounds-checked before any key
/// derivation happens.
pub struct SecretBox;

impl SecretBox {
    /// Encrypt `plaintext` under `password`.
    ///
    /// The password must be at least 8 bytes. Key derivation uses Argon2id
    /// with fixed v0.1 parameters (19 MiB memory, 2 passes).
    ///
    /// Panics only if the OS CSPRNG is unavailable.
    pub fn seal(password: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, Error> {
        if password.len() < MIN_PASSWORD_LEN {
            return Err(Error::PasswordTooShort);
        }

        let mut salt = [0u8; SALT_LEN];
        let mut nonce = [0u8; NONCE_LEN];
        getrandom::fill(&mut salt).expect("OS CSPRNG failed");
        getrandom::fill(&mut nonce).expect("OS CSPRNG failed");

        let key = derive_key(password, &salt, M_COST, T_COST, P_COST)?;

        let mut header = Vec::with_capacity(HEADER_LEN);
        header.push(VERSION);
        header.extend_from_slice(&M_COST.to_be_bytes());
        header.extend_from_slice(&T_COST.to_be_bytes());
        header.push(P_COST);
        header.extend_from_slice(&salt);
        header.extend_from_slice(&nonce);

        let cipher = ChaCha20Poly1305::new(&Key::from(*key));
        let ciphertext = cipher
            .encrypt(
                &Nonce::from(nonce),
                Payload {
                    msg: plaintext,
                    aad: &header,
                },
            )
            .map_err(|_| Error::DecryptionFailed)?;

        let mut blob = header;
        blob.extend_from_slice(&ciphertext);
        Ok(blob)
    }

    /// Verify and decrypt a blob produced by [`SecretBox::seal`].
    ///
    /// Returns [`Error::DecryptionFailed`] when the password is wrong or the
    /// blob was tampered with; the two cases are intentionally
    /// indistinguishable.
    pub fn open(blob: &[u8], password: &[u8]) -> Result<Vec<u8>, Error> {
        // All structural checks happen before any (expensive) key derivation.
        if blob.len() < MIN_BLOB_LEN {
            return Err(Error::InvalidBlob);
        }
        if blob[0] != VERSION {
            return Err(Error::InvalidBlob);
        }
        let m_cost = u32::from_be_bytes(blob[1..5].try_into().expect("bounds checked above"));
        let t_cost = u32::from_be_bytes(blob[5..9].try_into().expect("bounds checked above"));
        let p_cost = blob[9];
        if m_cost > MAX_M_COST || t_cost > MAX_T_COST || p_cost == 0 || p_cost > MAX_P_COST {
            return Err(Error::InvalidBlob);
        }
        if password.len() < MIN_PASSWORD_LEN {
            return Err(Error::PasswordTooShort);
        }

        let salt: [u8; SALT_LEN] = blob[10..10 + SALT_LEN]
            .try_into()
            .expect("bounds checked above");
        let nonce: [u8; NONCE_LEN] = blob[10 + SALT_LEN..HEADER_LEN]
            .try_into()
            .expect("bounds checked above");

        let key = derive_key(password, &salt, m_cost, t_cost, p_cost)?;

        let cipher = ChaCha20Poly1305::new(&Key::from(*key));
        cipher
            .decrypt(
                &Nonce::from(nonce),
                Payload {
                    msg: &blob[HEADER_LEN..],
                    aad: &blob[..HEADER_LEN],
                },
            )
            .map_err(|_| Error::DecryptionFailed)
    }
}

fn derive_key(
    password: &[u8],
    salt: &[u8; SALT_LEN],
    m_cost: u32,
    t_cost: u32,
    p_cost: u8,
) -> Result<Zeroizing<[u8; KEY_LEN]>, Error> {
    let params = Params::new(m_cost, t_cost, u32::from(p_cost), Some(KEY_LEN))
        .map_err(|_| Error::InvalidBlob)?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = Zeroizing::new([0u8; KEY_LEN]);
    argon
        .hash_password_into(password, salt, &mut key[..])
        .map_err(|_| Error::DecryptionFailed)?;
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    const PASSWORD: &[u8] = b"correct horse battery staple";

    #[test]
    fn seal_open_roundtrip() {
        let blob = SecretBox::seal(PASSWORD, b"at rest").unwrap();
        assert_eq!(SecretBox::open(&blob, PASSWORD).unwrap(), b"at rest");
    }

    #[test]
    fn blob_layout() {
        let blob = SecretBox::seal(PASSWORD, b"layout").unwrap();
        assert_eq!(blob[0], VERSION);
        assert_eq!(u32::from_be_bytes(blob[1..5].try_into().unwrap()), M_COST);
        assert_eq!(u32::from_be_bytes(blob[5..9].try_into().unwrap()), T_COST);
        assert_eq!(blob[9], P_COST);
        assert_eq!(blob.len(), HEADER_LEN + b"layout".len() + TAG_LEN);
    }

    #[test]
    fn wrong_password_fails() {
        let blob = SecretBox::seal(PASSWORD, b"secret").unwrap();
        assert_eq!(
            SecretBox::open(&blob, b"wrong password!!"),
            Err(Error::DecryptionFailed)
        );
    }

    #[test]
    fn short_password_rejected_on_seal_and_open() {
        assert_eq!(
            SecretBox::seal(b"short", b"x"),
            Err(Error::PasswordTooShort)
        );
        let blob = SecretBox::seal(PASSWORD, b"x").unwrap();
        assert_eq!(
            SecretBox::open(&blob, b"short"),
            Err(Error::PasswordTooShort)
        );
    }

    #[test]
    fn truncated_blob_fails() {
        let blob = SecretBox::seal(PASSWORD, b"x").unwrap();
        assert_eq!(
            SecretBox::open(&blob[..MIN_BLOB_LEN - 1], PASSWORD),
            Err(Error::InvalidBlob)
        );
        assert_eq!(SecretBox::open(&[], PASSWORD), Err(Error::InvalidBlob));
    }

    #[test]
    fn out_of_range_params_fail_before_derivation() {
        let mut blob = SecretBox::seal(PASSWORD, b"x").unwrap();

        blob[0] = 0x02; // bad version
        assert_eq!(SecretBox::open(&blob, PASSWORD), Err(Error::InvalidBlob));
        blob[0] = VERSION;

        blob[1..5].copy_from_slice(&u32::MAX.to_be_bytes()); // m_cost too large
        assert_eq!(SecretBox::open(&blob, PASSWORD), Err(Error::InvalidBlob));
        blob[1..5].copy_from_slice(&M_COST.to_be_bytes());

        blob[5..9].copy_from_slice(&u32::MAX.to_be_bytes()); // t_cost too large
        assert_eq!(SecretBox::open(&blob, PASSWORD), Err(Error::InvalidBlob));
        blob[5..9].copy_from_slice(&T_COST.to_be_bytes());

        blob[9] = 0; // p_cost too small
        assert_eq!(SecretBox::open(&blob, PASSWORD), Err(Error::InvalidBlob));
        blob[9] = MAX_P_COST + 1; // p_cost too large
        assert_eq!(SecretBox::open(&blob, PASSWORD), Err(Error::InvalidBlob));
    }

    #[test]
    fn tampered_salt_fails() {
        let mut blob = SecretBox::seal(PASSWORD, b"x").unwrap();
        blob[10] ^= 1;
        assert_eq!(
            SecretBox::open(&blob, PASSWORD),
            Err(Error::DecryptionFailed)
        );
    }

    #[test]
    fn tampered_nonce_fails() {
        let mut blob = SecretBox::seal(PASSWORD, b"x").unwrap();
        blob[HEADER_LEN - 1] ^= 1;
        assert_eq!(
            SecretBox::open(&blob, PASSWORD),
            Err(Error::DecryptionFailed)
        );
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let mut blob = SecretBox::seal(PASSWORD, b"payload").unwrap();
        let last = blob.len() - 1;
        blob[last] ^= 1;
        assert_eq!(
            SecretBox::open(&blob, PASSWORD),
            Err(Error::DecryptionFailed)
        );
    }
}
