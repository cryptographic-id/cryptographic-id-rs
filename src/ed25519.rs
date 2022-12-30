use std::io;
use std::path::PathBuf;

use ed25519_dalek::Keypair;
use ed25519_dalek::PublicKey;
use ed25519_dalek::Signature;
use ed25519_dalek::Signer;
use rand::rngs::OsRng;

use crate::fs;
use crate::conv;

pub fn create_keypair() -> Keypair {
	let mut csprng = OsRng{};
	let keypair: Keypair = Keypair::generate(&mut csprng);
	return keypair;
}

pub fn format_public_key(key: PublicKey) -> String {
	let bytes_vec = key.to_bytes().to_vec();
	let hex = conv::bytes_to_hex(bytes_vec);
	if hex.len() != 95 {
		return hex;
	}
	return vec![
		hex[0..23].to_string(),
		hex[24..47].to_string(),
		hex[48..71].to_string(),
		hex[72..95].to_string()].join("\n");
}

pub fn sign(keypair: &Keypair, message: &[u8]) -> Signature {
	let signature = keypair.sign(message);
	return signature;
}

pub fn sign_array(keypair: &Keypair, to_sign_arr: &Vec<Vec<u8>>) -> Vec<u8> {
	let to_sign = conv::flatten_binary_vec(&to_sign_arr);
	return sign(keypair, &to_sign).to_bytes().to_vec();
}

pub fn save_keypair_to_file(key: Keypair, filename: PathBuf) -> io::Result<()> {
	let secret_key_bytes = key.to_bytes();
	return fs::write_file(secret_key_bytes.to_vec(), filename);
}

pub fn load_keypair_from_file(filename: PathBuf) -> io::Result<Keypair> {
	let buffer = fs::read_file(filename)?;
	let res = Keypair::from_bytes(&buffer);
	return match res {
		Ok(k) => Ok(k),
		Err(e) => Err(io::Error::new(io::ErrorKind::Other, e)),
	}
}
