use zeroize::Zeroizing;

use crate::Error;
use crate::keys::Keypair;
use crate::secretbox::SecretBox;

/// Encrypt a keypair's secret key under a password, for storage at rest.
///
/// The returned blob can be written to disk and later restored with
/// [`decrypt_keypair`]. The password must be at least 8 bytes.
pub fn encrypt_keypair(keypair: &Keypair, password: &[u8]) -> Result<Vec<u8>, Error> {
    let secret = keypair.to_secret_bytes();
    SecretBox::seal(password, &*secret)
}

/// Restore a keypair from a blob produced by [`encrypt_keypair`].
///
/// Fails with [`Error::DecryptionFailed`] if the password is wrong or the
/// blob was tampered with.
pub fn decrypt_keypair(blob: &[u8], password: &[u8]) -> Result<Keypair, Error> {
    let secret = Zeroizing::new(SecretBox::open(blob, password)?);
    let secret: [u8; 32] = secret
        .as_slice()
        .try_into()
        .map_err(|_| Error::InvalidBlob)?;
    Ok(Keypair::from_secret_bytes(secret))
}

#[cfg(test)]
mod tests {
    use super::*;

    const PASSWORD: &[u8] = b"keypair storage password";

    #[test]
    fn keypair_storage_roundtrip() {
        let keypair = Keypair::generate();
        let blob = encrypt_keypair(&keypair, PASSWORD).unwrap();
        let restored = decrypt_keypair(&blob, PASSWORD).unwrap();

        assert_eq!(restored.public_key(), keypair.public_key());
        assert_eq!(&*restored.to_secret_bytes(), &*keypair.to_secret_bytes());
    }

    #[test]
    fn wrong_password_fails() {
        let keypair = Keypair::generate();
        let blob = encrypt_keypair(&keypair, PASSWORD).unwrap();
        let result = decrypt_keypair(&blob, b"wrong password!!");
        assert!(matches!(result, Err(Error::DecryptionFailed)));
    }

    #[test]
    fn tampered_blob_fails() {
        let keypair = Keypair::generate();
        let mut blob = encrypt_keypair(&keypair, PASSWORD).unwrap();
        let last = blob.len() - 1;
        blob[last] ^= 1;
        let result = decrypt_keypair(&blob, PASSWORD);
        assert!(matches!(result, Err(Error::DecryptionFailed)));
    }

    #[test]
    fn short_password_rejected() {
        let keypair = Keypair::generate();
        assert_eq!(
            encrypt_keypair(&keypair, b"short"),
            Err(Error::PasswordTooShort)
        );
    }
}
