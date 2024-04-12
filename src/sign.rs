use crate::conv;
use crate::ed25519;
pub use crate::ed25519::SigningKey;
use crate::error::DynError;
use crate::message::cryptographic_id::PublicKeyType;
use crate::tpm2::Tpm2SigningConfig;
use std::io;
use std::path::PathBuf;

pub enum SigningConfig {
	Ed25519(SigningKey),
	Tpm2(Tpm2SigningConfig),
}

impl SigningConfig {
	pub fn load(
		pathbuf: &PathBuf,
		password: &str,
	) -> Result<Self, DynError> {
		let path = pathbuf.as_path();
		if path.is_file() {
			return match ed25519::load_keypair_from_file(&pathbuf)
			{
				Ok(k) => Ok(SigningConfig::Ed25519(k)),
				Err(e) => Err(Box::new(e)),
			};
		} else if path.is_dir() {
			return Ok(SigningConfig::Tpm2(
				Tpm2SigningConfig::load(&pathbuf, &password)?,
			));
		} else {
			return Err(Box::new(io::Error::new(
				io::ErrorKind::Other,
				"Key needs to be a file or directory",
			)));
		}
	}

	pub fn public_key(self: &Self) -> Result<Vec<u8>, DynError> {
		return Ok(match self {
			SigningConfig::Ed25519(s) => {
				s.verifying_key().to_bytes().to_vec()
			}
			SigningConfig::Tpm2(t) => t.public_key()?,
		});
	}

	pub fn fingerprint(self: &Self) -> Result<String, DynError> {
		let bytes = match self {
			SigningConfig::Ed25519(s) => {
				ed25519::fingerprint(&s.verifying_key())?
			}
			SigningConfig::Tpm2(t) => t.fingerprint()?,
		};
		return Ok(conv::fingerprint_to_hex(&bytes));
	}

	pub fn public_key_type(self: &Self) -> PublicKeyType {
		return match self {
			SigningConfig::Ed25519(_) => PublicKeyType::Ed25519,
			SigningConfig::Tpm2(_) => PublicKeyType::Prime256v1,
		};
	}

	pub fn sign(
		self: &mut Self,
		message: &[u8],
	) -> Result<Vec<u8>, DynError> {
		return Ok(match self {
			SigningConfig::Ed25519(s) => ed25519::sign(s, message),
			SigningConfig::Tpm2(t) => t.sign(message)?,
		});
	}
}

#[cfg(test)]
mod test {
	use crate::ed25519;
	use crate::error::DynError;
	use crate::fs;
	use crate::prime256v1;

	#[test]
	fn signing_config_tpm2() -> Result<(), DynError> {
		let dir = fs::to_path_buf("tests/files/sign/tpm2");
		let pubkey = vec![
			4, 224, 244, 0, 36, 168, 104, 223, 40, 152, 123, 50,
			152, 61, 109, 206, 248, 157, 130, 136, 112, 98, 21,
			33, 218, 143, 141, 188, 196, 165, 1, 27, 28, 135, 100,
			159, 54, 223, 117, 44, 217, 170, 120, 74, 219, 186,
			25, 55, 115, 97, 172, 72, 223, 120, 109, 61, 15, 243,
			60, 179, 165, 105, 179, 124, 234,
		];
		let mut sign_config =
			super::SigningConfig::load(&dir, "testsign")?;
		assert_eq!(sign_config.public_key()?, pubkey);
		assert_eq!(
			sign_config.fingerprint()?,
			"31:B3:24:AB:B2:37:16:F5\n\
			AF:9E:4E:41:B3:F2:77:84\n\
			18:8D:DB:2C:46:16:5A:6B\n\
			EA:12:0C:DE:7D:5C:1D:88"
		);
		assert_eq!(
			sign_config.public_key_type(),
			super::PublicKeyType::Prime256v1
		);
		let msg = b"ADifferentTestMessage".to_vec();
		let sig = sign_config.sign(&msg)?;
		prime256v1::verify(&pubkey, &msg, &sig)?;
		return Ok(());
	}

	#[test]
	fn signing_config_ed25519() -> Result<(), DynError> {
		let file = fs::to_path_buf("tests/files/sign/ed25519");
		let pubkey = vec![
			94, 183, 62, 28, 74, 112, 186, 74, 57, 152, 75, 149,
			127, 150, 26, 109, 4, 4, 7, 127, 72, 77, 143, 129,
			183, 228, 156, 146, 81, 210, 25, 249,
		];
		let mut sign_config = super::SigningConfig::load(&file, "")?;
		assert_eq!(sign_config.public_key()?, pubkey);
		assert_eq!(
			sign_config.fingerprint()?,
			"A3:94:89:7D:6A:B8:00:E1\n\
			E3:16:59:09:0A:7E:36:A4\n\
			5A:AE:C3:C6:90:66:C3:F8\n\
			A3:34:94:C3:58:74:F4:4E"
		);
		assert_eq!(
			sign_config.public_key_type(),
			super::PublicKeyType::Ed25519,
		);
		let msg = b"AnotherDifferentTestMessage".to_vec();
		let sig = sign_config.sign(&msg)?;
		ed25519::verify(&pubkey, &msg, &sig)?;
		return Ok(());
	}
}
