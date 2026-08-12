use core::fmt;

/// All errors returned by this crate.
///
/// Messages are deliberately generic: error details can leak information
/// about secrets, so this crate never reports *why* a decryption failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// Authentication failed: the ciphertext, nonce, version byte, or key is
    /// wrong. No plaintext is returned.
    DecryptionFailed,
    /// The envelope is too short to contain the minimum fields.
    CiphertextTooShort,
    /// The bytes do not encode a valid X25519 public key.
    InvalidPublicKey,
    /// The blob has a bad version, length, or out-of-range parameters.
    InvalidBlob,
    /// The password is shorter than the 8-byte minimum.
    PasswordTooShort,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let msg = match self {
            Error::DecryptionFailed => "decryption failed",
            Error::CiphertextTooShort => "ciphertext too short",
            Error::InvalidPublicKey => "invalid public key",
            Error::InvalidBlob => "invalid blob",
            Error::PasswordTooShort => "password too short",
        };
        f.write_str(msg)
    }
}

impl std::error::Error for Error {}
