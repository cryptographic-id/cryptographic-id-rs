extern crate rand;
extern crate ed25519_dalek;
use std::fs::File;
use std::io::BufReader;
use std::io::Read;
use std::io::Write;
use std::io;
use ed25519_dalek::Signer;
use ed25519_dalek::Keypair;
use ed25519_dalek::Signature;
use rand::rngs::OsRng;
use qrcode::QrCode;


fn create_keypair() -> Keypair {
    let mut csprng = OsRng{};
    let keypair: Keypair = Keypair::generate(&mut csprng);
    return keypair;
}

fn sign(keypair: Keypair, message: &[u8]) -> Signature {
    let signature = keypair.sign(message);
    return signature;
}

fn save_keypair_to_file(keypair: Keypair, filename: &str) -> io::Result<()> {
    let secret_key_bytes = keypair.to_bytes();
    let mut f = File::create(filename)?;
    f.write_all(&secret_key_bytes)?;
    return Ok(());
}

fn load_keypair_from_file(filename: &str) -> io::Result<Keypair> {
    let f = File::open(filename)?;
    let mut reader = BufReader::new(f);
    let mut buffer = Vec::new();
    reader.read_to_end(&mut buffer)?;
    let res = Keypair::from_bytes(&buffer);
    return match res {
        Ok(k) => Ok(k),
        Err(e) => Err(io::Error::new(io::ErrorKind::Other, e)),
    }
}

fn show_qrcode(message: &[u8]) {
    let code = QrCode::new(message).unwrap();
    let string = code.render::<char>()
        .quiet_zone(false)
        .module_dimensions(2, 1)
        .build();
    println!("{}", string);
}

fn main() {
    let keypair = create_keypair();
    let file = "my_key";
    match save_keypair_to_file(keypair, "my_key2") {
        Ok(()) => (),
        Err(e) => {
            println!("{}", e);
            return;
        },
    };
    let keypair2 = match load_keypair_from_file(file) {
        Ok(k) => k,
        Err(e) => {
            println!("{}", e);
            return;
        },
    };
    let signature = sign(keypair2, b"Test message");
    println!("Sig: {}", signature);
    show_qrcode(&signature.to_bytes());
}
