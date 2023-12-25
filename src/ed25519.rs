use std::array::TryFromSliceError;
use std::io;
use std::path::PathBuf;

pub use ed25519_dalek::SigningKey;
use ed25519_dalek::{Signature, Signer, Verifier, VerifyingKey};
use rand::rngs::OsRng;
use sha2::Digest as Sha2Digest;

use crate::error::DynError;
use crate::fs;

pub fn create_keypair() -> SigningKey {
	let mut csprng = OsRng {};
	let keypair: SigningKey = SigningKey::generate(&mut csprng);
	return keypair;
}

pub fn fingerprint(verifying_key: &VerifyingKey) -> Result<Vec<u8>, DynError> {
	let mut hasher = sha2::Sha256::new();
	hasher.update(verifying_key);
	return Ok(hasher.finalize().to_vec());
}

pub fn sign(keypair: &SigningKey, message: &[u8]) -> Vec<u8> {
	let signature = keypair.sign(message);
	return signature.to_bytes().to_vec();
}

pub fn verify(
	verifying_key: &[u8],
	message: &[u8],
	signature: &[u8],
) -> Result<(), DynError> {
	let key = VerifyingKey::from_bytes(verifying_key.try_into()?)?;
	let sig = Signature::from_bytes(signature.try_into()?);
	key.verify(message, &sig)?;
	return Ok(());
}

pub fn save_keypair_to_file(
	key: &SigningKey,
	filename: &PathBuf,
) -> io::Result<()> {
	let secret_key_bytes = key.to_keypair_bytes();
	return fs::write_file(&secret_key_bytes.to_vec(), filename);
}

pub fn load_keypair_from_file(filename: &PathBuf) -> io::Result<SigningKey> {
	let buffer = fs::read_file(&filename)?;
	let res: Result<[u8; 64], TryFromSliceError> = buffer[..].try_into();
	let arr = match res {
		Ok(k) => k,
		Err(e) => {
			return Err(io::Error::new(io::ErrorKind::Other, e));
		}
	};
	return match SigningKey::from_keypair_bytes(&arr) {
		Ok(k) => Ok(k),
		Err(e) => Err(io::Error::new(io::ErrorKind::Other, e)),
	};
}

#[cfg(test)]
mod tests {
	use ed25519_dalek::Signature;
	use tempfile;

	fn load_test_key() -> super::SigningKey {
		let fname = "tests/files/ed25519/test_private_key";
		return super::load_keypair_from_file(&super::fs::to_path_buf(
			fname,
		))
		.unwrap();
	}

	#[test]
	fn create_keypair() {
		// a key should be able to sign a message
		let key = super::create_keypair();
		let data = vec![5, 72, 24, 82, 23, 92, 24, 38, 151, 45, 2];
		let sig = super::sign(&key, &data);
		let sig_arr: [u8; 64] = sig.try_into().unwrap();
		key.verify(&data, &Signature::from_bytes(&sig_arr)).unwrap();
	}

	#[test]
	fn fingerprint() {
		let key = load_test_key();
		assert_eq!(
			super::fingerprint(&key.verifying_key()).unwrap(),
			vec![
				11, 45, 192, 121, 75, 216, 66, 161, 194, 65,
				46, 224, 202, 78, 123, 254, 118, 250, 181, 249,
				84, 175, 77, 202, 182, 149, 196, 114, 76, 188,
				183, 1
			]
		);
	}

	#[test]
	fn sign() {
		let key = load_test_key();
		let data = vec![72, 24, 12, 23, 22, 29, 98, 151, 45, 180];
		let signature = super::sign(&key, &data);
		assert_eq!(
			signature,
			super::fs::read_file(&super::fs::to_path_buf(
				"tests/files/ed25519/signature"
			))
			.unwrap()
		);
	}

	#[test]
	fn verify() {
		let key = load_test_key();
		let mut data = vec![72, 24, 12, 23, 22, 29, 98, 151, 45, 180];
		let verifying_key = key.verifying_key().to_bytes().to_vec();
		let mut signature =
			super::fs::read_file(&super::fs::to_path_buf(
				"tests/files/ed25519/signature",
			))
			.unwrap();
		super::verify(&verifying_key, &data, &signature).unwrap();
		data[2] = 18;
		assert!(super::verify(&verifying_key, &data, &signature)
			.is_err());
		data[2] = 12;
		signature[17] = 4;
		assert!(super::verify(&verifying_key, &data, &signature)
			.is_err());
	}

	#[test]
	fn load_keypair_from_file() {
		let fname = "tests/files/ed25519/test_private_key";
		let key = super::load_keypair_from_file(
			&super::fs::to_path_buf(fname),
		)
		.unwrap();
		assert_eq!(
			key.verifying_key().to_bytes(),
			[
				28, 54, 138, 182, 211, 130, 44, 184, 189, 85,
				31, 56, 30, 36, 91, 39, 240, 20, 110, 199, 94,
				186, 184, 45, 84, 43, 95, 221, 243, 170, 215,
				186
			]
		);
		assert_eq!(
			key.to_bytes(),
			[
				90, 233, 113, 148, 214, 29, 87, 198, 190, 85,
				201, 51, 148, 145, 124, 141, 196, 24, 69, 92,
				212, 167, 118, 87, 116, 9, 244, 70, 81, 75, 4,
				88
			]
		);
	}

	#[test]
	fn save_keypair_to_file() {
		let tmpdir = tempfile::tempdir().unwrap();
		let file_path = tmpdir.path().join("save_test");
		let key = super::create_keypair();
		super::save_keypair_to_file(&key, &file_path).unwrap();
		let loaded_key =
			super::load_keypair_from_file(&file_path).unwrap();
		assert_eq!(key.to_bytes(), loaded_key.to_bytes());
		assert_eq!(key.verifying_key(), loaded_key.verifying_key());
	}
}
