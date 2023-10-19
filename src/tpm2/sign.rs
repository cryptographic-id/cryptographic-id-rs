use asn1_rs::ToDer;
use std::path::PathBuf;
pub use tss_esapi::Error;
use tss_esapi::{
	handles::KeyHandle,
	interface_types::{
		algorithm::HashingAlgorithm, resource_handles::Hierarchy,
		session_handles::AuthSession,
	},
	structures::{
		Auth, CreatePrimaryKeyResult, Digest, EccSignature, HashScheme,
		MaxBuffer, PcrSlot, Private, Public, PublicBuffer, Signature,
		SignatureScheme,
	},
	traits::UnMarshall,
	Context, WrapperErrorKind,
};

use crate::error::DynError;
use crate::fs;
use crate::tpm2;

fn signature_to_asn1(sig: &EccSignature) -> Result<Vec<u8>, DynError> {
	let mut v = Vec::new();
	let r_arr: [u8; 32] = sig.signature_r().as_bytes().try_into()?;
	let s_arr: [u8; 32] = sig.signature_s().as_bytes().try_into()?;
	let rb = asn1_rs::Integer::from_const_array(r_arr);
	let sb = asn1_rs::Integer::from_const_array(s_arr);
	rb.write_der(&mut v)?;
	sb.write_der(&mut v)?;
	return Ok(asn1_rs::Sequence::new(v.into()).to_der_vec()?);
}

pub fn read_public_file(dir: &PathBuf) -> Result<Public, DynError> {
	let public_content = fs::read_file(&tpm2::to_public_file(&dir))?;
	let public_buf = PublicBuffer::unmarshall(&public_content)?;
	let public = Public::unmarshall(&public_buf)?;
	return Ok(public);
}

fn read_private_file(dir: &PathBuf) -> Result<Private, DynError> {
	let private_content = fs::read_file(&tpm2::to_private_file(&dir))?;
	let private = Private::unmarshall(&private_content)?;
	return Ok(private);
}

fn read_pcr_file(dir: &PathBuf) -> Result<Vec<PcrSlot>, DynError> {
	let mut result = vec![];
	let binary = match fs::read_file(&tpm2::to_pcr_file(&dir)) {
		Ok(s) => s,
		Err(_) => {
			// No file means no pcrs
			return Ok(result);
		}
	};
	let content = std::str::from_utf8(&binary)?;
	let cleared = content.replace(" ", "").replace("\n", "");
	let parts = cleared.split(",");
	for part in parts {
		result.push(tpm2::str_to_pcr(part)?);
	}
	return Ok(result);
}

pub struct Tpm2SigningConfig {
	context: Context,
	key_handle: KeyHandle,
	public: Public,
	session: AuthSession,
	pcrs: Vec<PcrSlot>,
}

fn _load_public_and_handle(
	context: &mut Context,
	primary: &CreatePrimaryKeyResult,
	pathbuf: &PathBuf,
) -> Result<(Public, KeyHandle), DynError> {
	let handle_file = tpm2::to_handle_file(&pathbuf);
	if handle_file.exists() {
		let content = fs::read_file(&tpm2::to_handle_file(&pathbuf))?;
		let key_handle: KeyHandle =
			context.tr_deserialize(&content)?.into();
		let (public, _, _) = context.read_public(key_handle)?;
		return Ok((public, key_handle));
	} else {
		let public = read_public_file(&pathbuf)?;
		let private = read_private_file(&pathbuf)?;
		let key_handle =
			context.execute_with_nullauth_session(|ctx| {
				ctx.load(
					primary.key_handle,
					private,
					public.clone(),
				)
			})?;
		return Ok((public, key_handle));
	}
}

impl Tpm2SigningConfig {
	pub fn load(pathbuf: &PathBuf) -> Result<Self, DynError> {
		let mut context = tpm2::create_context()?;
		let pcrs = read_pcr_file(&pathbuf)?;
		let session_digest = if pcrs.len() == 0 {
			Digest::try_from(vec![])?
		} else {
			let session = tpm2::start_auth_session(&mut context)?;
			tpm2::set_policy(&mut context, &pcrs, session)?;
			context.policy_get_digest(session.try_into()?)?
		};
		let primary = tpm2::create_primary(
			&mut context,
			session_digest.clone(),
		)?;
		let (public, key_handle) = _load_public_and_handle(
			&mut context,
			&primary,
			&pathbuf,
		)?;
		let save_session = if pcrs.len() == 0 {
			context.tr_set_auth(
				key_handle.into(),
				Auth::try_from(b"x".to_vec())?,
			)?;
			AuthSession::Password
		} else {
			tpm2::start_auth_session(&mut context)?
		};
		return Ok(Self {
			context: context,
			key_handle: key_handle,
			public: public,
			session: save_session,
			pcrs: pcrs,
		});
	}

	pub fn public_key(self: &Self) -> Result<Vec<u8>, DynError> {
		return tpm2::public_key(&self.public);
	}

	pub fn fingerprint(self: &Self) -> Result<String, DynError> {
		return tpm2::format_public_key(&self.public);
	}

	pub fn sign(
		self: &mut Self,
		message: &[u8],
	) -> Result<Vec<u8>, DynError> {
		if self.pcrs.len() > 0 {
			// otherwise TPM2 fails to sign on multiple runs
			self.context
				.policy_restart(self.session.try_into()?)?;
			tpm2::set_policy(
				&mut self.context,
				&self.pcrs,
				self.session.try_into()?,
			)?;
		}
		let data = MaxBuffer::try_from(message.to_vec())?;
		let (digest, ticket) =
			self.context.execute_without_session(|ctx| {
				ctx.hash(
					data,
					HashingAlgorithm::Sha256,
					Hierarchy::Endorsement,
				)
			})?;
		let sig_scheme = SignatureScheme::EcDsa {
			scheme: HashScheme::new(HashingAlgorithm::Sha256),
		};
		let signature = self.context.execute_with_session(
			Some(self.session),
			|ctx| {
				ctx.sign(
					self.key_handle,
					digest,
					sig_scheme,
					ticket,
				)
			},
		)?;
		if let Signature::EcDsa(ecc_sig) = signature {
			return Ok(signature_to_asn1(&ecc_sig)?);
		} else {
			return Err(Box::new(Error::WrapperError(
				WrapperErrorKind::InvalidParam,
			)));
		}
	}
}

#[cfg(test)]
mod test {
	use super::PcrSlot;
	use crate::test_common::verify_p256;
	use crate::tpm2::sign::DynError;
	use std::path::PathBuf;
	use tss_esapi::{
		structures::{EccParameter, Public},
		traits::UnMarshall,
	};

	#[test]
	fn signature_to_asn1() -> Result<(), DynError> {
		let s = vec![
			225, 46, 176, 134, 227, 104, 125, 27, 233, 222, 205,
			246, 131, 31, 17, 119, 74, 241, 74, 161, 57, 2, 194,
			124, 110, 196, 15, 44, 113, 118, 214, 73,
		];
		let r = vec![
			172, 188, 189, 20, 83, 126, 42, 89, 226, 6, 137, 195,
			49, 251, 210, 70, 46, 64, 64, 240, 54, 12, 210, 161,
			37, 216, 91, 70, 100, 18, 210, 213,
		];
		let sig = super::EccSignature::create(
			super::HashingAlgorithm::Sha256,
			EccParameter::try_from(s.clone())?,
			EccParameter::try_from(r.clone())?,
		)?;
		let sequence = vec![48, 70];
		let int_start = vec![2, 33, 0];
		assert_eq!(
			super::signature_to_asn1(&sig)?,
			[
				sequence.clone(),
				int_start.clone(),
				s,
				int_start.clone(),
				r
			]
			.concat()
		);
		return Ok(());
	}

	#[test]
	fn read_public_file() -> Result<(), DynError> {
		let public = super::read_public_file(&super::fs::to_path_buf(
			"tests/files/tpm2/sign/read_public_file",
		))?;
		let expected = Public::unmarshall(&vec![
			0, 35, 0, 11, 0, 4, 4, 114, 0, 0, 0, 16, 0, 16, 0, 3,
			0, 16, 0, 32, 180, 200, 124, 255, 187, 37, 107, 72,
			152, 46, 160, 146, 84, 240, 231, 138, 162, 204, 75, 93,
			222, 94, 219, 157, 8, 105, 100, 149, 177, 19, 183, 72,
			0, 32, 110, 210, 241, 200, 15, 150, 192, 118, 71, 0,
			241, 170, 65, 245, 134, 67, 152, 216, 82, 31, 114, 104,
			170, 79, 244, 183, 76, 247, 85, 63, 145, 160,
		])?;
		assert_eq!(public, expected);
		return Ok(());
	}

	#[test]
	fn read_private_file() -> Result<(), DynError> {
		let private =
			super::read_private_file(&super::fs::to_path_buf(
				"tests/files/tpm2/sign/read_private_file",
			))?;
		let cmp = super::Private::try_from(vec![
			0, 32, 227, 140, 85, 248, 217, 55, 161, 174, 38, 115,
			230, 217, 197, 164, 102, 165, 57, 69, 174, 184, 76,
			100, 210, 254, 111, 46, 136, 127, 45, 24, 60, 186, 0,
			16, 27, 3, 223, 189, 173, 114, 126, 51, 98, 56, 69, 78,
			229, 220, 29, 54, 163, 18, 102, 152, 115, 22, 113, 155,
			180, 255, 207, 237, 235, 165, 88, 151, 51, 109, 103,
			84, 93, 108, 101, 82, 222, 165, 160, 188, 106, 10, 89,
			26, 189, 9, 153, 130, 114, 13, 217, 169, 113, 98, 205,
			75, 78, 181, 66, 178, 114, 112, 201, 86, 103, 3, 202,
			60, 163, 127, 25, 113, 74, 14, 0, 175, 43, 54, 144,
			238, 33, 11, 29, 247, 8, 216,
		])?;
		assert_eq!(private, cmp);
		return Ok(());
	}

	#[test]
	fn read_pcr_file() -> Result<(), DynError> {
		assert_eq!(
			super::read_pcr_file(&super::fs::to_path_buf(
				"/my/dir/no/pcrs"
			))?,
			vec![]
		);
		assert_eq!(
			super::read_pcr_file(&super::fs::to_path_buf(
				"tests/files/tpm2/sign/read_pcr_file/seven"
			))?,
			vec![PcrSlot::Slot7]
		);
		assert_eq!(
			super::read_pcr_file(&super::fs::to_path_buf(
				"tests/files/tpm2/sign/read_pcr_file/multiple"
			))?,
			vec![PcrSlot::Slot4, PcrSlot::Slot7, PcrSlot::Slot14]
		);
		let error = super::read_pcr_file(&super::fs::to_path_buf(
			"tests/files/tpm2/sign/read_pcr_file/empty",
		))
		.unwrap_err();
		assert_eq!(
			format!("{:?}", error),
			"ParseIntError { kind: Empty }"
		);
		return Ok(());
	}

	fn test_sign(dir: &PathBuf, pubkey: &Vec<u8>) -> Result<(), DynError> {
		let mut sign_config = super::Tpm2SigningConfig::load(&dir)?;
		assert_eq!(sign_config.public_key()?, *pubkey);
		// Test signing works multiple times
		for _ in 0..5 {
			let message = b"testmessage".to_vec();
			let signature = sign_config.sign(&message)?;
			verify_p256(&pubkey, &message, &signature)?;
		}
		return Ok(());
	}

	#[test]
	fn tpm2_signing_config_plain() -> Result<(), DynError> {
		let dir = super::fs::to_path_buf(
			"tests/files/tpm2/sign/sign/plain",
		);
		let pubkey = vec![
			4, 42, 12, 170, 201, 52, 112, 214, 207, 144, 58, 167,
			96, 26, 140, 36, 229, 135, 23, 129, 235, 204, 109, 5,
			223, 117, 119, 82, 155, 95, 192, 30, 145, 128, 78, 144,
			192, 142, 163, 129, 193, 250, 32, 88, 111, 212, 170,
			246, 216, 86, 167, 174, 203, 236, 181, 164, 230, 193,
			84, 41, 136, 163, 203, 53, 122,
		];
		return test_sign(&dir, &pubkey);
	}

	#[test]
	fn tpm2_signing_config_pcr() -> Result<(), DynError> {
		let dir = super::fs::to_path_buf(
			"tests/files/tpm2/sign/sign/pcr_4_7",
		);
		let pubkey = vec![
			4, 217, 21, 3, 90, 153, 86, 215, 109, 144, 192, 156,
			64, 17, 161, 130, 133, 168, 173, 84, 110, 163, 117, 16,
			13, 6, 189, 149, 76, 182, 117, 240, 3, 169, 114, 51,
			120, 50, 218, 26, 145, 195, 103, 201, 172, 74, 97, 252,
			241, 179, 72, 7, 207, 179, 22, 70, 170, 238, 58, 81,
			102, 16, 237, 122, 128,
		];
		return test_sign(&dir, &pubkey);
	}

	#[test]
	fn tpm2_signing_config_handle() -> Result<(), DynError> {
		let dir = super::fs::to_path_buf(
			"tests/files/tpm2/sign/sign/handle",
		);
		let pubkey = vec![
			4, 88, 108, 226, 103, 251, 196, 213, 2, 237, 184, 190,
			201, 76, 85, 239, 241, 221, 192, 57, 229, 1, 74, 197,
			214, 156, 214, 238, 101, 177, 72, 63, 143, 87, 35, 95,
			211, 53, 219, 167, 132, 193, 128, 183, 7, 109, 184,
			103, 62, 66, 142, 149, 148, 25, 210, 24, 248, 146, 173,
			134, 155, 145, 211, 20, 133,
		];
		return test_sign(&dir, &pubkey);
	}

	#[test]
	fn tpm2_signing_config_handle_pcr() -> Result<(), DynError> {
		let dir = super::fs::to_path_buf(
			"tests/files/tpm2/sign/sign/handle_pcr_5_6_7",
		);
		let pubkey = vec![
			4, 119, 138, 76, 158, 24, 53, 109, 38, 216, 131, 18,
			19, 135, 249, 97, 141, 17, 208, 70, 120, 160, 254, 35,
			129, 130, 2, 207, 146, 149, 122, 81, 240, 165, 1, 242,
			135, 237, 35, 74, 75, 254, 250, 86, 167, 134, 151, 201,
			255, 115, 168, 3, 16, 183, 155, 138, 39, 5, 81, 30,
			108, 236, 24, 174, 204,
		];
		return test_sign(&dir, &pubkey);
	}

	#[test]
	fn tpm2_signing_config_fingerprint() -> Result<(), DynError> {
		let dir = super::fs::to_path_buf(
			"tests/files/tpm2/sign/sign/handle_pcr_5_6_7",
		);
		let sign_config = super::Tpm2SigningConfig::load(&dir)?;
		assert_eq!(
			sign_config.fingerprint()?,
			"25:0E:F9:F7:0F:EA:47:19\n\
			59:05:17:A6:85:1F:FE:10\n\
			0B:DB:1F:2B:4F:AA:93:07\n\
			E8:43:02:BD:A5:F6:55:85"
		);
		return Ok(());
	}
}
