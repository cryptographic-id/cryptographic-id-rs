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
	pub fn load(pathbuf: &PathBuf) -> Result<Self, DynError> {
		let path = pathbuf.as_path();
		if path.is_file() {
			return match ed25519::load_keypair_from_file(&pathbuf) {
				Ok(k) => Ok(SigningConfig::Ed25519(k)),
				Err(e) => Err(Box::new(e)),
			};
		} else if path.is_dir() {
			return Ok(SigningConfig::Tpm2(
				Tpm2SigningConfig::load(&pathbuf)?,
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
		return Ok(match self {
			SigningConfig::Ed25519(s) => {
				ed25519::format_verifying_key(
					&s.verifying_key(),
				)
			}
			SigningConfig::Tpm2(t) => t.fingerprint()?,
		});
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
	use crate::test_common::verify_p256;

	#[test]
	fn signing_config_tpm2() -> Result<(), DynError> {
		let dir = fs::to_path_buf("tests/files/sign/tpm2");
		let pubkey = vec![
			4, 217, 21, 3, 90, 153, 86, 215, 109, 144, 192, 156,
			64, 17, 161, 130, 133, 168, 173, 84, 110, 163, 117, 16,
			13, 6, 189, 149, 76, 182, 117, 240, 3, 169, 114, 51,
			120, 50, 218, 26, 145, 195, 103, 201, 172, 74, 97, 252,
			241, 179, 72, 7, 207, 179, 22, 70, 170, 238, 58, 81,
			102, 16, 237, 122, 128,
		];
		let mut sign_config = super::SigningConfig::load(&dir)?;
		assert_eq!(sign_config.public_key()?, pubkey);
		assert_eq!(
			sign_config.fingerprint()?,
			"7A:74:DE:CA:EB:62:76:8D\n\
			60:50:68:8B:85:B9:5B:3D\n\
			8E:C2:75:9F:BE:2B:FE:30\n\
			A9:45:2D:93:C6:9A:68:7E"
		);
		assert_eq!(
			sign_config.public_key_type(),
			super::PublicKeyType::Prime256v1
		);
		let msg = b"ADifferentTestMessage".to_vec();
		let sig = sign_config.sign(&msg)?;
		verify_p256(&pubkey, &msg, &sig)?;
		return Ok(());
	}

	#[test]
	fn signing_config_ed25519() -> Result<(), DynError> {
		let file = fs::to_path_buf("tests/files/sign/ed25519");
		let pubkey = vec![
			94, 183, 62, 28, 74, 112, 186, 74, 57, 152, 75, 149,
			127, 150, 26, 109, 4, 4, 7, 127, 72, 77, 143, 129, 183,
			228, 156, 146, 81, 210, 25, 249,
		];
		let mut sign_config = super::SigningConfig::load(&file)?;
		assert_eq!(sign_config.public_key()?, pubkey);
		assert_eq!(
			sign_config.fingerprint()?,
			"5E:B7:3E:1C:4A:70:BA:4A\n\
			39:98:4B:95:7F:96:1A:6D\n\
			04:04:07:7F:48:4D:8F:81\n\
			B7:E4:9C:92:51:D2:19:F9"
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
