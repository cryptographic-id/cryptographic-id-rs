use crate::error::DynError;
use ed25519_dalek::Verifier;
use p256::ecdsa::{Signature, VerifyingKey};

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
}
