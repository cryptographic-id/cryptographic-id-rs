use std::env;
use std::path::Path;
use std::path::PathBuf;
use std::time::SystemTime;

use base64;
use ed25519_dalek::Keypair;
use prost::Message;
use qrcode::QrCode;
use qrcode::types::QrError;

pub mod message {
	include!(concat!(env!("OUT_DIR"), "/cryptographic_id.rs"));
}
mod fs;
mod ed25519;
mod conv;

fn message_to_data(m: &message::CryptographicId)
		-> Result<Vec<u8>, prost::EncodeError> {
	let mut buf = Vec::new();
	buf.reserve(m.encoded_len());
	m.encode(&mut buf)?;
	return Ok(buf);
}

fn show_qrcode(buf: &Vec<u8>) -> Result<(), QrError> {
	let msg: String = base64::encode(&buf);
	let code = QrCode::new(&msg)?;
	let string = code.render::<char>()
		.quiet_zone(false)
		.module_dimensions(2, 1)
		.build();
	println!("{}", string);
	return Ok(());
}

fn id_to_sign_arr(data: &message::CryptographicId) -> Vec<Vec<u8>> {
	let to_sign_arr = [
		data.timestamp.to_be_bytes().to_vec(),
		data.public_key.clone(),
		data.msg.clone()];
	return to_sign_arr.to_vec();
}

fn sign_qrdata(data: &mut message::CryptographicId, keypair: Keypair) {
	let to_sign_arr = id_to_sign_arr(&data);
	data.signature = ed25519::sign_array(&keypair, &to_sign_arr);

	for e in &mut data.personal_information {
		let e_to_sign_arr = [
			e.timestamp.to_be_bytes().to_vec(),
			e.r#type.to_be_bytes().to_vec(),
			e.value.as_bytes().to_vec()];
		e.signature = ed25519::sign_array(
			&keypair, &e_to_sign_arr.to_vec());
	}
}

enum Action {
	CreateKey(PathBuf),
	ShowPublicKey(PathBuf),
	SignWithKey(PathBuf, String),
}

fn print_help() {
	let args: Vec<String> = env::args().collect();
	println!(
		"Command-line tool to sign cryptographic-id\n\
		\n\
		Usage: {exe} METHOD path_to_private_key [message]\n\
		\n\
		Methods:\n\
		\tcreate          Create a private key\n\
		\tsign            Sign own id with message\n\
		\tshow            Show public key in hex format\n\
		",
		exe=args[0]);
}

fn parse_args(args: &Vec<String>) -> Result<Action, ()> {
	if args.len() < 3 {
		return Err(());
	}
	let key_path = Path::new(&args[2]).to_path_buf();
	let action = &args[1];
	if args.len() == 3 {
		if action == "create" {
			return Ok(Action::CreateKey(key_path));
		} else if action == "show" {
			return Ok(Action::ShowPublicKey(key_path));
		}
	}
	if args.len() == 4 {
		if action == "sign" {
			let msg = &args[3];
			return Ok(Action::SignWithKey(key_path, msg.to_string()));
		}
	}
	return Err(());
}

fn timestamp_now() -> u64 {
	return match SystemTime::now().duration_since(SystemTime::UNIX_EPOCH) {
		Ok(k) => k.as_secs(),
		Err(_) => {
			panic!("SystemTime before UNIX EPOCH!");
		},
	};
}

fn parse_args_and_execute(args: &Vec<String>) -> i32 {
	let action = match parse_args(&args) {
		Ok(k) => k,
		Err(_t) => {
			print_help();
			return 1;
		},
	};
	match action {
		Action::CreateKey(path) => {
			let keypair = ed25519::create_keypair();
			return match ed25519::save_keypair_to_file(keypair, path) {
				Ok(()) => {
					println!("Key created");
					0
				},
				Err(e) => {
					println!("Error saving key: {}", e);
					2
				},
			};
		},
		Action::ShowPublicKey(path) => {
			let keypair = match ed25519::load_keypair_from_file(path) {
				Ok(k) => k,
				Err(e) => {
					println!("Error loading key: {}", e);
					return 2;
				},
			};
			let hex = ed25519::format_public_key(keypair.public);
			println!("Public Key:\n{}", hex);
			return 0;
		},
		Action::SignWithKey(path, msg) => {
			let keypair = match ed25519::load_keypair_from_file(path) {
				Ok(k) => k,
				Err(e) => {
					println!("Error loading key: {}", e);
					return 2;
				},
			};
			let timestamp = timestamp_now();
			let mut msg = message::CryptographicId {
				public_key: keypair.public.to_bytes().to_vec(),
				timestamp: timestamp,
				msg: msg.as_bytes().to_vec(),
				signature: Vec::new(),
				personal_information: Vec::new(),
			};
			sign_qrdata(&mut msg, keypair);
			let data = match message_to_data(&msg) {
				Ok(d) => d,
				Err(e) => {
					println!("Error while encoding \
					          message: {}", e);
					return 3;
				},
			};
			return match show_qrcode(&data) {
				Ok(_) => 0,
				Err(e) => {
					println!("Error while encoding \
					          qrcode: {}", e);
					4
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
