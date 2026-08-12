use hkdf::Hkdf;
use sha2::Sha256;

pub(crate) const INFO_INITIATOR_TO_RESPONDER: &[u8] = b"e2ee-kit v1 initiator to responder";
pub(crate) const INFO_RESPONDER_TO_INITIATOR: &[u8] = b"e2ee-kit v1 responder to initiator";

/// Derive the two directional session keys from a shared secret.
///
/// `salt` binds the keys to the identity pair: it is always
/// `initiator public key || responder public key`, so both peers compute the
/// same salt without coordinating. The two info strings domain-separate the
/// directions; each peer encrypts with one key and decrypts with the other.
pub(crate) fn derive_session_keys(
    shared_secret: &[u8; 32],
    initiator_pub: &[u8; 32],
    responder_pub: &[u8; 32],
) -> ([u8; 32], [u8; 32]) {
    let mut salt = [0u8; 64];
    salt[..32].copy_from_slice(initiator_pub);
    salt[32..].copy_from_slice(responder_pub);

    let hk = Hkdf::<Sha256>::new(Some(&salt[..]), shared_secret);
    let mut k_i2r = [0u8; 32];
    let mut k_r2i = [0u8; 32];
    // 32 bytes is always a valid HKDF-SHA256 expansion length (max 255 * 32).
    hk.expand(INFO_INITIATOR_TO_RESPONDER, &mut k_i2r)
        .expect("32-byte HKDF output is valid");
    hk.expand(INFO_RESPONDER_TO_INITIATOR, &mut k_r2i)
        .expect("32-byte HKDF output is valid");
    (k_i2r, k_r2i)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len() / 2)
            .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn rfc5869_sha256_a1() {
        // RFC 5869 appendix A.1, basic test case with SHA-256.
        let ikm = hex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
        let salt = hex("000102030405060708090a0b0c");
        let info = hex("f0f1f2f3f4f5f6f7f8f9");

        let (prk, hk) = Hkdf::<Sha256>::extract(Some(&salt[..]), &ikm);
        assert_eq!(
            hex("077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5")[..],
            prk[..]
        );

        let mut okm = [0u8; 42];
        hk.expand(&info, &mut okm).unwrap();
        assert_eq!(
            hex(
                "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
            ),
            okm
        );
    }

    #[test]
    fn golden_session_keys() {
        // Fixed inputs lock the salt construction and info strings: any
        // accidental change to them breaks this vector.
        let ss = [0x11u8; 32];
        let initiator_pub = [0x22u8; 32];
        let responder_pub = [0x33u8; 32];

        let (k_i2r, k_r2i) = derive_session_keys(&ss, &initiator_pub, &responder_pub);
        assert_eq!(k_i2r, GOLDEN_K_I2R);
        assert_eq!(k_r2i, GOLDEN_K_R2I);

        // Deterministic, and the two directions differ.
        let again = derive_session_keys(&ss, &initiator_pub, &responder_pub);
        assert_eq!(again, (k_i2r, k_r2i));
        assert_ne!(k_i2r, k_r2i);

        // Salt order matters: swapping the roles changes the keys.
        let swapped = derive_session_keys(&ss, &responder_pub, &initiator_pub);
        assert_ne!(swapped, (k_i2r, k_r2i));
    }

    const GOLDEN_K_I2R: [u8; 32] = [
        0x61, 0xda, 0xe2, 0xca, 0x54, 0x83, 0x8d, 0x8d, 0x22, 0x66, 0x91, 0x14, 0xe5, 0xdf, 0x3e,
        0x91, 0xc4, 0x98, 0x96, 0x2f, 0x84, 0x0c, 0x21, 0x57, 0x1a, 0x68, 0xf3, 0x94, 0xf2, 0x68,
        0x2c, 0xc8,
    ];
    const GOLDEN_K_R2I: [u8; 32] = [
        0x52, 0x33, 0xd9, 0x8b, 0x69, 0x1a, 0x4b, 0x2a, 0x1a, 0x77, 0x8b, 0x54, 0x23, 0x36, 0x77,
        0x11, 0xd1, 0x69, 0xb0, 0xed, 0xe8, 0xc8, 0x4a, 0x23, 0xe7, 0x0e, 0x55, 0x69, 0xc1, 0x29,
        0xbc, 0x85,
    ];
}
