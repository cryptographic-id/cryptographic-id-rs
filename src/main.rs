use std::env;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};

use nix::libc;
use nix::sys::signal;

mod actions;
mod conv;
mod ed25519;
mod error;
mod fs;
mod message;
mod qrcode;
mod scan;
mod sign;
mod time;
mod tpm2;
use message::cryptographic_id::PublicKeyType;
mod prime256v1;

static RECEIVED_SIGNAL: AtomicBool = AtomicBool::new(false);

extern "C" fn handle_signal(_signal: libc::c_int) {
	RECEIVED_SIGNAL.store(true, Ordering::Relaxed);
}

enum Action {
	CreateKey(PathBuf),
	ShowPublicKey(PathBuf),
	SignWithKey(PathBuf, String),
	TPM2ScanAndMeasure,
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
		\tscan_and_measure\n\
		\t                Scans a QR-code and measures it into a PCR\n\
		\t                Environment variables:\n\
		\t                EXTEND_PCR: PCR to use\n\
		\t                VIDEO: camera to use (/dev/video0)\n\
		",
		exe = args[0]
	);
}

fn parse_args(args: &Vec<String>) -> Result<Action, ()> {
	if args.len() < 2 {
		return Err(());
	}
	let action = &args[1];
	if args.len() == 2 {
		if action == "scan_and_measure" {
			return Ok(Action::TPM2ScanAndMeasure);
		}
		return Err(());
	}
	let key_path = fs::to_path_buf(&args[2]);
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
			return Ok(Action::SignWithKey(
				key_path,
				msg.to_string(),
			));
		}
	}
	return Err(());
}

fn parse_args_and_execute(args: &Vec<String>) -> i32 {
	let action = match parse_args(&args) {
		Ok(k) => k,
		Err(_t) => {
			print_help();
			return 1;
		}
	};
	match action {
		Action::CreateKey(path) => {
			let keypair = ed25519::create_keypair();
			return match ed25519::save_keypair_to_file(
				&keypair, &path,
			) {
				Ok(()) => {
					println!("Key created");
					0
				}
				Err(e) => {
					println!("Error saving key: {}", e);
					2
				}
			};
		}
		Action::ShowPublicKey(path) => {
			let sign_config = match sign::SigningConfig::load(&path)
			{
				Ok(k) => k,
				Err(e) => {
					println!("Error loading key: {}", e);
					return 2;
				}
			};
			let hex = match sign_config.fingerprint() {
				Ok(k) => k,
				Err(e) => {
					println!("Error formatting key: {}", e);
					return 2;
				}
			};
			println!("Public Key:\n{}", hex);
			return 0;
		}
		Action::SignWithKey(path, msg) => {
			let mut sign_config =
				match sign::SigningConfig::load(&path) {
					Ok(k) => k,
					Err(e) => {
						println!(
							"Error loading key: {}",
							e
						);
						return 2;
					}
				};
			let timestamp = match time::now() {
				Ok(s) => s,
				Err(e) => {
					println!("Failed to get time: {}", e);
					return 6;
				}
			};
			let mut msg = message::CryptographicId {
				public_key: vec![],
				timestamp: timestamp,
				msg: msg.as_bytes().to_vec(),
				public_key_type: PublicKeyType::Ed25519 as i32,
				signature: Vec::new(),
				personal_information: Vec::new(),
			};
			match message::sign(&mut msg, &mut sign_config) {
				Err(e) => {
					println!("Error while signing: {}", e);
					return 2;
				}
				_ => {}
			}
			let data = match message::to_base64(&msg) {
				Ok(d) => d,
				Err(e) => {
					println!(
						"Error while encoding \
					          message: {}",
						e
					);
					return 3;
				}
			};
			return match qrcode::as_string(&data) {
				Ok(s) => {
					println!("{}", s);
					0
				}
				Err(e) => {
					println!(
						"Error while encoding \
					          qrcode: {}",
						e
					);
					4
				}
			};
		}
		Action::TPM2ScanAndMeasure => {
			let handler =
				signal::SigHandler::Handler(handle_signal);
			match unsafe {
				signal::signal(signal::Signal::SIGINT, handler)
			} {
				Ok(_) => {}
				Err(e) => {
					println!(
						"Failed to setup signal \
						handler: {}",
						e
					);
					return 6;
				}
			};

			let pcr_str = match env::var("EXTEND_PCR") {
				Ok(s) => s,
				Err(e) => {
					println!("EXTEND_PCR not set: {}", e);
					return 5;
				}
			};
			let cam = match env::var("VIDEO") {
				Ok(s) => s,
				Err(_) => "/dev/video0".to_string(),
			};
			return actions::tpm2_scan_and_measure(
				cam,
				pcr_str,
				&RECEIVED_SIGNAL,
			);
		}
	};
}

fn main() {
	let args: Vec<String> = env::args().collect();
	let result = parse_args_and_execute(&args);
	std::process::exit(result);
}
