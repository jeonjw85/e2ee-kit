use zeroize::Zeroize;

use crate::Error;
use crate::kdf::derive_session_keys;
use crate::keys::{Keypair, PublicKey};
use crate::message::Message;

/// Which side of a connection a peer is.
///
/// Both peers must use opposite roles: if one side calls [`Session::establish`]
/// with [`Role::Initiator`], the other must use [`Role::Responder`]. The roles
/// only decide which derived key is used for which direction.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Role {
    /// The peer that starts the exchange.
    Initiator,
    /// The peer that answers it.
    Responder,
}

/// An established two-way encrypted session between two keypairs.
///
/// Created by [`Session::establish`]; the derived keys are zeroized on drop.
/// A session does not track message order or counts: envelopes are
/// self-contained and may arrive in any order, but a given key must not seal
/// more than about 2^32 messages.
pub struct Session {
    send_key: [u8; 32],
    recv_key: [u8; 32],
}

impl Session {
    /// Establish a session with a peer.
    ///
    /// `our` is our long-term keypair, `their` is the peer's authenticated
    /// public key, and `role` must be the opposite of the peer's role.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidPublicKey`] if the peer's key is degenerate
    /// (the X25519 shared secret is all-zero, e.g. a low-order point).
    pub fn establish(our: &Keypair, their: PublicKey, role: Role) -> Result<Session, Error> {
        let shared_secret = our.static_secret().diffie_hellman(their.as_inner());

        // Reject degenerate shared secrets (RFC 8731 section 3).
        // Constant-time fold: no early exit on secret data.
        let mut acc = 0u8;
        for byte in shared_secret.as_bytes() {
            acc |= byte;
        }
        if acc == 0 {
            return Err(Error::InvalidPublicKey);
        }

        let our_pub = our.to_public_bytes();
        let their_pub = their.to_bytes();
        let (initiator_pub, responder_pub) = match role {
            Role::Initiator => (our_pub, their_pub),
            Role::Responder => (their_pub, our_pub),
        };

        let (k_i2r, k_r2i) =
            derive_session_keys(shared_secret.as_bytes(), &initiator_pub, &responder_pub);

        let (send_key, recv_key) = match role {
            Role::Initiator => (k_i2r, k_r2i),
            Role::Responder => (k_r2i, k_i2r),
        };

        Ok(Session { send_key, recv_key })
    }

    /// Encrypt and authenticate a message for the peer.
    pub fn seal(&self, plaintext: &[u8]) -> Result<Vec<u8>, Error> {
        Message::seal(&self.send_key, plaintext)
    }

    /// Verify and decrypt a message from the peer.
    pub fn open(&self, envelope: &[u8]) -> Result<Vec<u8>, Error> {
        Message::open(&self.recv_key, envelope)
    }
}

impl Zeroize for Session {
    fn zeroize(&mut self) {
        self.send_key.zeroize();
        self.recv_key.zeroize();
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        self.zeroize();
    }
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
    fn initiator_responder_cross_consistency() {
        let alice = Keypair::generate();
        let bob = Keypair::generate();

        let alice_side = Session::establish(&alice, bob.public_key(), Role::Initiator).unwrap();
        let bob_side = Session::establish(&bob, alice.public_key(), Role::Responder).unwrap();

        let m1 = alice_side.seal(b"hi bob").unwrap();
        assert_eq!(bob_side.open(&m1).unwrap(), b"hi bob");

        let m2 = bob_side.seal(b"hi alice").unwrap();
        assert_eq!(alice_side.open(&m2).unwrap(), b"hi alice");
    }

    #[test]
    fn swapped_roles_also_consistent() {
        let alice = Keypair::generate();
        let bob = Keypair::generate();

        let alice_side = Session::establish(&alice, bob.public_key(), Role::Responder).unwrap();
        let bob_side = Session::establish(&bob, alice.public_key(), Role::Initiator).unwrap();

        let m = alice_side.seal(b"role swap").unwrap();
        assert_eq!(bob_side.open(&m).unwrap(), b"role swap");
    }

    #[test]
    fn same_role_on_both_sides_cannot_communicate() {
        let alice = Keypair::generate();
        let bob = Keypair::generate();

        let alice_side = Session::establish(&alice, bob.public_key(), Role::Initiator).unwrap();
        let bob_side = Session::establish(&bob, alice.public_key(), Role::Initiator).unwrap();

        let m = alice_side.seal(b"mismatched roles").unwrap();
        assert_eq!(bob_side.open(&m), Err(Error::DecryptionFailed));
    }

    #[test]
    fn third_party_session_cannot_read_traffic() {
        let alice = Keypair::generate();
        let bob = Keypair::generate();
        let eve = Keypair::generate();

        let alice_to_bob = Session::establish(&alice, bob.public_key(), Role::Initiator).unwrap();
        // Eve pairs with Alice instead of Bob.
        let eve_side = Session::establish(&eve, alice.public_key(), Role::Responder).unwrap();

        let m = alice_to_bob.seal(b"private").unwrap();
        assert_eq!(eve_side.open(&m), Err(Error::DecryptionFailed));
    }

    #[test]
    fn all_zero_shared_secret_rejected() {
        let alice = Keypair::generate();
        // The all-zero public key is a low-order point: DH yields all-zero.
        let low_order = PublicKey::from_bytes([0u8; 32]).unwrap();
        let result = Session::establish(&alice, low_order, Role::Initiator);
        assert!(matches!(result, Err(Error::InvalidPublicKey)));
    }

    #[test]
    fn rfc7748_shared_secret() {
        // RFC 7748 section 6.1: Alice and Bob's static keys.
        let alice = Keypair::from_secret_bytes(hex32(
            "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a",
        ));
        let bob_public = PublicKey::from_bytes(hex32(
            "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f",
        ))
        .unwrap();
        let shared = alice.static_secret().diffie_hellman(bob_public.as_inner());
        assert_eq!(
            shared.as_bytes(),
            &hex32("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742")
        );
    }

    #[test]
    fn zeroize_clears_session_keys() {
        let alice = Keypair::generate();
        let bob = Keypair::generate();
        let mut session = Session::establish(&alice, bob.public_key(), Role::Initiator).unwrap();
        assert_ne!(session.send_key, [0u8; 32]);
        session.zeroize();
        assert_eq!(session.send_key, [0u8; 32]);
        assert_eq!(session.recv_key, [0u8; 32]);
    }
}
