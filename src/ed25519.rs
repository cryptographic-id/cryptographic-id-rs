use std::io;
use std::path::PathBuf;

pub use ed25519_dalek::Keypair;
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

pub fn format_public_key(key: &PublicKey) -> String {
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

fn sign(keypair: &Keypair, message: &[u8]) -> Signature {
	let signature = keypair.sign(message);
	return signature;
}

pub fn sign_array(keypair: &Keypair, to_sign_arr: &Vec<Vec<u8>>) -> Vec<u8> {
	let to_sign = conv::flatten_binary_vec(&to_sign_arr);
	return sign(keypair, &to_sign).to_bytes().to_vec();
}

pub fn save_keypair_to_file(key: &Keypair, filename: &PathBuf)
		-> io::Result<()> {
	let secret_key_bytes = key.to_bytes();
	return fs::write_file(&secret_key_bytes.to_vec(), filename);
}

pub fn load_keypair_from_file(filename: &PathBuf) -> io::Result<Keypair> {
	let buffer = fs::read_file(&filename)?;
	let res = Keypair::from_bytes(&buffer);
	return match res {
		Ok(k) => Ok(k),
		Err(e) => Err(io::Error::new(io::ErrorKind::Other, e)),
	}
}

#[cfg(test)]
mod tests {
	use tempfile;

	fn load_test_key() -> super::Keypair {
		let fname = "tests/files/ed25519/test_private_key";
		return super::load_keypair_from_file(
			&super::fs::to_path_buf(fname)).unwrap();
	}

	#[test]
	fn create_keypair() {
		// a key should be able to sign a message
		let key = super::create_keypair();
		let data = vec![5, 72, 24, 82, 23, 92, 24, 38, 151, 45, 2];
		let sig = super::sign(&key, &data);
		key.verify(&data, &sig).unwrap();
	}

	#[test]
	fn format_public_key() {
		let key = load_test_key();
		assert_eq!(
			super::format_public_key(&key.public),
			"1C:36:8A:B6:D3:82:2C:B8\n\
			 BD:55:1F:38:1E:24:5B:27\n\
			 F0:14:6E:C7:5E:BA:B8:2D\n\
			 54:2B:5F:DD:F3:AA:D7:BA");
	}

	#[test]
	fn sign() {
		let key = load_test_key();
		let data = vec![72, 24, 12, 23, 22, 29, 98, 151, 45, 180];
		let signature = super::sign(&key, &data).to_bytes().to_vec();
		assert_eq!(
			signature,
			super::fs::read_file(&super::fs::to_path_buf(
				"tests/files/ed25519/signature")).unwrap());
	}

	#[test]
	fn sign_array() {
		let key = load_test_key();
		let data = vec![
			vec![72, 24],
			vec![],
			vec![12, 23, 22],
			vec![29],
			vec![98, 151, 45, 180]];
		let signature = super::sign_array(&key, &data);
		assert_eq!(
			signature,
			super::fs::read_file(&super::fs::to_path_buf(
				"tests/files/ed25519/signature")).unwrap());
	}

	#[test]
	fn load_keypair_from_file() {
		let fname = "tests/files/ed25519/test_private_key";
		let key = super::load_keypair_from_file(
			&super::fs::to_path_buf(fname)).unwrap();
		assert_eq!(
			key.public.to_bytes(),
			[28, 54, 138, 182, 211, 130, 44, 184, 189, 85, 31, 56,
			 30, 36, 91, 39, 240, 20, 110, 199, 94, 186, 184, 45,
			 84, 43, 95, 221, 243, 170, 215, 186]);
		assert_eq!(
			key.secret.to_bytes(),
			[90, 233, 113, 148, 214, 29, 87, 198, 190, 85, 201,
			 51, 148, 145, 124, 141, 196, 24, 69, 92, 212, 167,
			 118, 87, 116, 9, 244, 70, 81, 75, 4, 88]);
	}

	#[test]
	fn save_keypair_to_file() {
		let tmpdir = tempfile::tempdir().unwrap();
		let file_path = tmpdir.path().join("save_test");
		let key = super::create_keypair();
		super::save_keypair_to_file(&key, &file_path).unwrap();
		let loaded_key = super::load_keypair_from_file(
			&file_path).unwrap();
		assert_eq!(
			key.secret.to_bytes(),
			loaded_key.secret.to_bytes());
		assert_eq!(key.public, loaded_key.public);
	}
}
