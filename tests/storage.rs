//! Integration test for persisting and restoring keypairs.

use e2ee_kit::{Error, Keypair, decrypt_keypair, encrypt_keypair};

const PASSWORD: &[u8] = b"long-term storage password";

#[test]
fn keypair_roundtrip() {
    let keypair = Keypair::generate();

    let blob = encrypt_keypair(&keypair, PASSWORD).unwrap();
    let restored = decrypt_keypair(&blob, PASSWORD).unwrap();

    assert_eq!(restored.public_key(), keypair.public_key());
    assert_eq!(
        restored.to_secret_bytes().as_slice(),
        keypair.to_secret_bytes().as_slice()
    );

    let peer = Keypair::generate();
    let a = e2ee_kit::Session::establish(&keypair, peer.public_key(), e2ee_kit::Role::Initiator)
        .unwrap();
    let b = e2ee_kit::Session::establish(&restored, peer.public_key(), e2ee_kit::Role::Initiator)
        .unwrap();
    let envelope = a.seal(b"after restore").unwrap();
    let peer_side =
        e2ee_kit::Session::establish(&peer, restored.public_key(), e2ee_kit::Role::Responder)
            .unwrap();
    assert_eq!(peer_side.open(&envelope).unwrap(), b"after restore");
    let envelope2 = peer_side.seal(b"to restored").unwrap();
    assert_eq!(b.open(&envelope2).unwrap(), b"to restored");
}

#[test]
fn wrong_password_is_rejected() {
    let keypair = Keypair::generate();
    let blob = encrypt_keypair(&keypair, PASSWORD).unwrap();
    let result = decrypt_keypair(&blob, b"attacker guess!!");
    assert!(matches!(result, Err(Error::DecryptionFailed)));
}

#[test]
fn corrupted_blob_is_rejected() {
    let keypair = Keypair::generate();
    let mut blob = encrypt_keypair(&keypair, PASSWORD).unwrap();
    blob[40] ^= 0xff;
    let result = decrypt_keypair(&blob, PASSWORD);
    assert!(matches!(result, Err(Error::DecryptionFailed)));
}
