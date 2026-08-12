//! End-to-end story test for a two-party session.

use e2ee_kit::{Error, Keypair, PublicKey, Role, Session};

#[test]
fn full_exchange() {
    let alice = Keypair::generate();
    let bob = Keypair::generate();

    let alice_pub = PublicKey::from_bytes(alice.to_public_bytes()).unwrap();
    let bob_pub = PublicKey::from_bytes(bob.to_public_bytes()).unwrap();

    let alice_side = Session::establish(&alice, bob_pub, Role::Initiator).unwrap();
    let bob_side = Session::establish(&bob, alice_pub, Role::Responder).unwrap();

    let m1 = alice_side.seal(b"hello bob").unwrap();
    assert_eq!(bob_side.open(&m1).unwrap(), b"hello bob");

    let m2 = bob_side.seal(b"hi alice").unwrap();
    assert_eq!(alice_side.open(&m2).unwrap(), b"hi alice");

    let wire = alice_side.seal(b"raw bytes on the wire").unwrap();
    let as_vec: Vec<u8> = wire.to_vec();
    assert_eq!(bob_side.open(&as_vec).unwrap(), b"raw bytes on the wire");
}

#[test]
fn tampering_is_rejected() {
    let alice = Keypair::generate();
    let bob = Keypair::generate();
    let alice_side = Session::establish(&alice, bob.public_key(), Role::Initiator).unwrap();
    let bob_side = Session::establish(&bob, alice.public_key(), Role::Responder).unwrap();

    let mut envelope = alice_side.seal(b"important").unwrap();
    let last = envelope.len() - 1;
    envelope[last] ^= 1;
    assert_eq!(bob_side.open(&envelope), Err(Error::DecryptionFailed));
}

#[test]
fn wrong_role_cannot_read() {
    let alice = Keypair::generate();
    let bob = Keypair::generate();

    let alice_side = Session::establish(&alice, bob.public_key(), Role::Initiator).unwrap();
    let bob_wrong = Session::establish(&bob, alice.public_key(), Role::Initiator).unwrap();

    let envelope = alice_side.seal(b"can you read this?").unwrap();
    assert_eq!(bob_wrong.open(&envelope), Err(Error::DecryptionFailed));
}

#[test]
fn a_stranger_cannot_read() {
    let alice = Keypair::generate();
    let bob = Keypair::generate();
    let mallory = Keypair::generate();

    let alice_side = Session::establish(&alice, bob.public_key(), Role::Initiator).unwrap();
    let mallory_side = Session::establish(&mallory, bob.public_key(), Role::Responder).unwrap();

    let envelope = alice_side.seal(b"private conversation").unwrap();
    assert_eq!(mallory_side.open(&envelope), Err(Error::DecryptionFailed));
}
