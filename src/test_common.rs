use crate::error::DynError;
use ed25519_dalek::Verifier;
use p256::ecdsa::{Signature, VerifyingKey};

pub fn verify_p256(
	public_key: &Vec<u8>,
	message: &Vec<u8>,
	signature: &Vec<u8>,
) -> Result<(), DynError> {
	let sig = Signature::from_der(&signature)?;
	let verifying_key = VerifyingKey::from_sec1_bytes(&public_key)?;
	verifying_key.verify(&message, &sig)?;
	return Ok(());
}
