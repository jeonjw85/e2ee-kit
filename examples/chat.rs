//! End-to-end chat demo.
//!
//! Run: `cargo run --example chat`

use e2ee_kit::{Keypair, Role, Session};

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

fn main() -> Result<(), e2ee_kit::Error> {
    let alice = Keypair::generate();
    let bob = Keypair::generate();

    println!("Alice pub: {}", hex(&alice.to_public_bytes()));
    println!("Bob   pub: {}", hex(&bob.to_public_bytes()));

    let alice_side = Session::establish(&alice, bob.public_key(), Role::Initiator)?;
    let bob_side = Session::establish(&bob, alice.public_key(), Role::Responder)?;

    let plaintext = b"hello bob, this is a secret";
    let envelope = alice_side.seal(plaintext)?;
    println!("\n[Alice -> Bob] plaintext : {}", String::from_utf8_lossy(plaintext));
    println!("[Alice -> Bob] envelope  : {} bytes", envelope.len());
    println!("[Alice -> Bob] hex       : {}", hex(&envelope));

    let opened = bob_side.open(&envelope)?;
    println!("[Bob decrypts]           : {}", String::from_utf8_lossy(&opened));

    let reply = b"hi alice, got it";
    let envelope2 = bob_side.seal(reply)?;
    let opened2 = alice_side.open(&envelope2)?;
    println!("\n[Bob -> Alice] plaintext : {}", String::from_utf8_lossy(reply));
    println!("[Alice decrypts]         : {}", String::from_utf8_lossy(&opened2));

    let mut tampered = envelope.clone();
    let last = tampered.len() - 1;
    tampered[last] ^= 0x01;
    match bob_side.open(&tampered) {
        Ok(_) => println!("\n[tamper] UNEXPECTEDLY OPENED"),
        Err(e) => println!("\n[tamper] rejected as expected: {e}"),
    }

    let eve = Keypair::generate();
    let eve_side = Session::establish(&eve, alice.public_key(), Role::Responder)?;
    match eve_side.open(&envelope) {
        Ok(_) => println!("[stranger] UNEXPECTEDLY OPENED"),
        Err(e) => println!("[stranger] cannot read: {e}"),
    }

    Ok(())
}
