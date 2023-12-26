use crate::error::DynError;
use ed25519_dalek::Verifier;
use p256::ecdsa::Signature;
pub use p256::ecdsa::VerifyingKey;
use sha2::Digest;

pub fn verify(
	public_key: &[u8],
	message: &[u8],
	signature: &[u8],
) -> Result<(), DynError> {
	let sig = Signature::from_der(&signature)?;
	let verifying_key = VerifyingKey::from_sec1_bytes(&public_key)?;
	verifying_key.verify(&message, &sig)?;
	return Ok(());
}

pub fn fingerprint(verifying_key: &VerifyingKey) -> Result<Vec<u8>, DynError> {
	let mut hasher = sha2::Sha256::new();
	let bytes = verifying_key.to_sec1_bytes();
	if bytes[0] != 4 && bytes.len() != 65 {
		return Err("p256 did not return unencoded sec1 bytes".into());
	}
	hasher.update(&bytes[1..]);
	return Ok(hasher.finalize().to_vec());
}

#[cfg(test)]
mod tests {
	use crate::error::DynError;
	use crate::fs;

	#[test]
	fn verify() -> Result<(), DynError> {
		let mut data = vec![72, 24, 12, 23, 22, 29, 98, 151, 45, 180];
		let verifying_key = fs::read_file(&fs::to_path_buf(
			"tests/files/prime256v1/verify/verifying_key",
		))
		.unwrap();
		let mut signature = fs::read_file(&fs::to_path_buf(
			"tests/files/prime256v1/verify/signature",
		))
		.unwrap();
		super::verify(&verifying_key, &data, &signature)?;
		data[2] = 18;
		assert!(super::verify(&verifying_key, &data, &signature)
			.is_err());
		data[2] = 12;
		signature[17] = 4;
		assert!(super::verify(&verifying_key, &data, &signature)
			.is_err());
		return Ok(());
	}

	#[test]
	fn fingerprint() -> Result<(), DynError> {
		let verifying_key = fs::read_file(&fs::to_path_buf(
			"tests/files/prime256v1/verify/verifying_key",
		))?;
		let verifying_key =
			super::VerifyingKey::from_sec1_bytes(&verifying_key)?;
		assert_eq!(
			super::fingerprint(&verifying_key)?,
			vec![
				122, 116, 222, 202, 235, 98, 118, 141, 96, 80,
				104, 139, 133, 185, 91, 61, 142, 194, 117, 159,
				190, 43, 254, 48, 169, 69, 45, 147, 198, 154,
				104, 126
			]
		);
		return Ok(());
	}
}
