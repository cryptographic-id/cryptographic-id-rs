extern crate rand;
extern crate ed25519_dalek;
use std::env;
use std::fs::File;
use std::io::BufReader;
use std::io::Read;
use std::io::Write;
use std::path::Path;
use std::path::PathBuf;
use std::io;
use ed25519_dalek::Signer;
use ed25519_dalek::Keypair;
use ed25519_dalek::Signature;
use rand::rngs::OsRng;
use qrcode::QrCode;
use prost::Message;

pub mod message {
    include!(concat!(env!("OUT_DIR"), "/qrdata.rs"));
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

fn save_keypair_to_file(keypair: Keypair, filename: PathBuf) -> io::Result<()> {
    let secret_key_bytes = keypair.to_bytes();
    let mut f = File::create(filename)?;
    f.write_all(&secret_key_bytes)?;
    return Ok(());
}

fn load_keypair_from_file(filename: PathBuf) -> io::Result<Keypair> {
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

fn sign_qrdata(data: &mut message::QrData, keypair: Keypair) {
    let to_sign_arr = [
        data.timestamp.to_be_bytes().to_vec(),
        data.public_key.clone()];
    let to_sign: Vec<u8> = to_sign_arr.iter().flat_map(
        |v| v.iter().copied()).collect();
    let signature = sign(&keypair, &to_sign);
    data.signature = signature.to_bytes().to_vec();
}

enum Action {
    CreateKey(PathBuf),
    SignWithKey(PathBuf),
}

fn parse_args(args: &Vec<String>) -> Result<Action, String> {
    if args.len() == 3 {
        let key_path = Path::new(&args[2]).to_path_buf();
        let action = &args[1];
        if action == "create_key" {
            return Ok(Action::CreateKey(key_path));
        } else if action == "sign" {
            return Ok(Action::SignWithKey(key_path));
        }
    }
    return Err("Usage: create_key|sign PATH_TO_KEY".to_string());
}

fn parse_args_and_execute(args: &Vec<String>) -> i32 {
    let action = match parse_args(&args) {
        Ok(k) => k,
        Err(t) => {
            println!("{}", t);
            return 1;
        },
    };
    match action {
        Action::CreateKey(path) => {
            let keypair = create_keypair();
            return match save_keypair_to_file(keypair, path) {
                Ok(()) => 0,
                Err(e) => {
                    println!("Error saving keypair: {}", e);
                    2
                },
            };
        },
        Action::SignWithKey(path) => {
            let keypair = match load_keypair_from_file(path) {
                Ok(k) => k,
                Err(e) => {
                    println!("Error loading keypair: {}", e);
                    return 2;
                },
            };
            let mut msg = message::QrData {
                public_key: keypair.public.to_bytes().to_vec(),
                timestamp: 0, // TODO date
                signature: Vec::new(),
                personal_information: Vec::new(),
            };
            sign_qrdata(&mut msg, keypair);
            return match show_qrcode(&msg) {
                Ok(_) => 0,
                Err(e) => {
                    println!("Error while encoding qrdata: {}", e);
                    3
                },
            };
        },
    };
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let result = parse_args_and_execute(&args);
    std::process::exit(result);
}
