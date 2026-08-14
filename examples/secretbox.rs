//! Password-based sealing demo.
//!
//! Run: `cargo run --example secretbox -- <password> <message>`
//! Defaults are used if no args are given.

use e2ee_kit::SecretBox;

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

fn main() -> Result<(), e2ee_kit::Error> {
    let mut args = std::env::args().skip(1);
    let password = args
        .next()
        .unwrap_or_else(|| "correct horse battery staple".into());
    let message = args.next().unwrap_or_else(|| "data at rest".into());

    println!("password : {password}");
    println!("message  : {message}");

    let blob = SecretBox::seal(password.as_bytes(), message.as_bytes())?;
    println!("\nsealed blob ({} bytes)", blob.len());
    println!("hex : {}", hex(&blob));

    let opened = SecretBox::open(&blob, password.as_bytes())?;
    println!("\nopened   : {}", String::from_utf8_lossy(&opened));

    match SecretBox::open(&blob, b"wrong password!!") {
        Ok(_) => println!("[wrong pw] UNEXPECTEDLY OPENED"),
        Err(e) => println!("[wrong pw] rejected: {e}"),
    }

    Ok(())
}
