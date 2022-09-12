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
use prost::Message;

pub mod message {
    include!(concat!(env!("OUT_DIR"), "/_.rs"));
}

fn create_keypair() -> Keypair {
    let mut csprng = OsRng{};
    let keypair: Keypair = Keypair::generate(&mut csprng);
    return keypair;
}

fn sign(keypair: &Keypair, message: &[u8]) -> Signature {
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

fn show_qrcode(m: &message::QrData) -> Result<(), prost::EncodeError> {
    let mut buf = Vec::new();
    buf.reserve(m.encoded_len());
    m.encode(&mut buf)?;

    let code = QrCode::new(&buf).unwrap();
    let string = code.render::<char>()
        .quiet_zone(false)
        .module_dimensions(2, 1)
        .build();
    println!("{}", string);
    return Ok(());
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
    let signature = sign(&keypair2, b"Test message");
    let msg = message::QrData {
        action: message::qr_data::Action::Share as i32,
        public_key: keypair2.public.to_bytes().to_vec(),
        timestamp: 0,
        signature: signature.to_bytes().to_vec(),
        entries: Vec::new(),
    };
    match show_qrcode(&msg) {
        Ok(_) => {},
        Err(e) => {
            println!("Error while encoding qrdata: {}", e);
        },
    };
}
