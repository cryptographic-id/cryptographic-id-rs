use crate::conv;
use crate::error::DynError;
use crate::prime256v1;
use std::path::PathBuf;
use tss_esapi::{
	attributes::ObjectAttributesBuilder,
	constants::{CapabilityType, SessionType},
	interface_types::{
		algorithm::{HashingAlgorithm, PublicAlgorithm, SymmetricMode},
		ecc::EccCurve,
		key_bits::AesKeyBits,
		resource_handles::Hierarchy,
		session_handles::AuthSession,
	},
	structures::{
		CapabilityData, CreatePrimaryKeyResult, Digest, DigestValues,
		EccPoint, EccScheme, KeyDerivationFunctionScheme, MaxBuffer,
		PcrSelectionListBuilder, Public, PublicBuilder,
		PublicEccParametersBuilder, SymmetricDefinition,
		SymmetricDefinitionObject,
	},
	TctiNameConf, WrapperErrorKind,
};
pub use tss_esapi::{handles::PcrHandle, structures::PcrSlot, Context, Error};

pub fn to_private_file(dir: &PathBuf) -> PathBuf {
	let mut p = dir.clone();
	p.push("ecc.priv");
	return p;
}

pub fn to_public_file(dir: &PathBuf) -> PathBuf {
	let mut p = dir.clone();
	p.push("ecc.pub");
	return p;
}

pub fn to_pcr_file(dir: &PathBuf) -> PathBuf {
	let mut p = dir.clone();
	p.push("pcrs");
	return p;
}

pub fn to_handle_file(dir: &PathBuf) -> PathBuf {
	let mut p = dir.clone();
	p.push("handle");
	return p;
}

pub fn str_to_pcr(s: &str) -> Result<PcrSlot, DynError> {
	let num: u32 = s.parse()?;
	return Ok(PcrSlot::try_from(1 << num)?);
}

pub fn str_to_pcrhandle(s: &str) -> Result<PcrHandle, DynError> {
	let num: u32 = s.parse()?;
	return Ok(PcrHandle::try_from(num)?);
}

pub fn create_context() -> Result<Context, Error> {
	let device = TctiNameConf::from_environment_variable()?;
	return Ok(Context::new(device)?);
}

pub fn start_auth_session(context: &mut Context) -> Result<AuthSession, Error> {
	let session = context.start_auth_session(
		None,
		None,
		None,
		SessionType::Policy,
		SymmetricDefinition::AES_256_CFB,
		HashingAlgorithm::Sha256,
	)?;
	return match session {
		Some(s) => Ok(s),
		None => Err(Error::WrapperError(
			WrapperErrorKind::WrongValueFromTpm,
		)),
	};
}

pub fn create_public_for_primary(policy: Digest) -> Result<Public, Error> {
	let ecc_params = PublicEccParametersBuilder::new()
		.with_ecc_scheme(EccScheme::Null)
		.with_curve(EccCurve::NistP256)
		.with_is_decryption_key(true)
		.with_restricted(true)
		.with_symmetric(SymmetricDefinitionObject::Aes {
			key_bits: AesKeyBits::Aes128,
			mode: SymmetricMode::Cfb,
		})
		.with_key_derivation_function_scheme(
			KeyDerivationFunctionScheme::Null,
		)
		.build()?;
	let primary_object_attributes = ObjectAttributesBuilder::new()
		.with_fixed_tpm(true)
		.with_fixed_parent(true)
		.with_sensitive_data_origin(true)
		// TODO remove with_user_with_auth in a v2
		// the key is already protected by the policy, this will also
		// protect the primary key with it.
		.with_user_with_auth(true)
		.with_restricted(true)
		.with_decrypt(true)
		.build()?;
	let primary_public = PublicBuilder::new()
		.with_public_algorithm(PublicAlgorithm::Ecc)
		.with_name_hashing_algorithm(HashingAlgorithm::Sha256)
		.with_object_attributes(primary_object_attributes)
		.with_ecc_parameters(ecc_params)
		.with_ecc_unique_identifier(EccPoint::default())
		.with_auth_policy(policy)
		.build()?;
	return Ok(primary_public);
}

pub fn create_primary(
	context: &mut Context,
	policy: Digest,
) -> Result<CreatePrimaryKeyResult, Error> {
	let primary_public = create_public_for_primary(policy)?;
	return context.execute_with_nullauth_session(|ctx| {
		ctx.create_primary(
			Hierarchy::Endorsement,
			primary_public.clone(),
			None,
			None,
			None,
			None,
		)
	});
}

pub fn set_policy(
	context: &mut Context,
	pcrs: &Vec<PcrSlot>,
	session: AuthSession,
) -> Result<(), DynError> {
	let pcr_selection_list = PcrSelectionListBuilder::new()
		.with_selection(HashingAlgorithm::Sha256, pcrs.as_slice())
		.build()?;

	let (_update_counter, pcr_sel, pcr_data) = context
		.execute_without_session(|ctx| {
			ctx.pcr_read(pcr_selection_list)
		})?;
	let concatenated_pcr_values = pcr_data
		.value()
		.iter()
		.map(|x| x.as_bytes())
		.collect::<Vec<&[u8]>>()
		.concat();
	let concatenated_pcr_values =
		MaxBuffer::try_from(concatenated_pcr_values)?;
	let (hashed_data, _ticket) =
		context.execute_without_session(|ctx| {
			ctx.hash(
				concatenated_pcr_values,
				HashingAlgorithm::Sha256,
				Hierarchy::Endorsement,
			)
		})?;
	context.policy_pcr(
		session.try_into()?,
		hashed_data.clone(),
		pcr_sel.clone(),
	)?;
	return Ok(());
}

pub fn public_key(public: &Public) -> Result<Vec<u8>, DynError> {
	let Public::Ecc { unique, .. } = public else {
		return Err(Box::new(Error::WrapperError(
			WrapperErrorKind::InvalidParam,
		)));
	};
	let uncompressed: u8 = 4;
	// TODO: compress it for smaller qr-codes
	let key = conv::flatten_binary_vec(&vec![
		vec![uncompressed],
		unique.x().as_bytes().to_vec(),
		unique.y().as_bytes().to_vec(),
	]);
	if key.len() != 65 {
		return Err("TPM2 did not return uncompressed key".into());
	}
	return Ok(key);
}

pub fn fingerprint(public: &Public) -> Result<Vec<u8>, DynError> {
	let key = public_key(&public)?;
	let verifying_key = prime256v1::VerifyingKey::from_sec1_bytes(&key)?;
	return Ok(prime256v1::fingerprint(&verifying_key)?);
}

fn get_supported_hash_algorithms(
	ctx: &mut Context,
) -> Result<Vec<HashingAlgorithm>, Error> {
	let (cap, _more) =
		ctx.get_capability(CapabilityType::AssignedPcr, 0, 255)?;
	if let CapabilityData::AssignedPcr(selections) = cap {
		return Ok(selections
			.get_selections()
			.iter()
			.filter(|s| !s.is_empty())
			.map(|s| s.hashing_algorithm())
			.collect());
	}
	return Err(Error::WrapperError(WrapperErrorKind::WrongValueFromTpm));
}

pub fn pcr_extend(
	ctx: &mut Context,
	pcr: PcrHandle,
	data: Vec<u8>,
) -> Result<(), Error> {
	let mut digest_values = DigestValues::new();
	let buffer = MaxBuffer::try_from(data.to_vec())?;
	let hash_algs = get_supported_hash_algorithms(ctx)?;
	for hash_alg in hash_algs {
		let (digest, _ticket) = ctx.execute_without_session(|c| {
			c.hash(buffer.clone(), hash_alg, Hierarchy::Endorsement)
		})?;
		digest_values.set(hash_alg, digest.clone());
	}

	ctx.execute_with_nullauth_session(|c| {
		return c.pcr_extend(pcr, digest_values);
	})?;
	return Ok(());
}

#[cfg(test)]
pub mod tests {
	use crate::error::DynError;
	use crate::fs;
	use crate::tpm2;
	use tss_esapi::{
		constants::{SessionType, StructureTag::Creation},
		interface_types::{
			resource_handles::Hierarchy,
			session_handles::PolicySession,
		},
		structures::{Digest, PcrSlot, Ticket},
		traits::Marshall,
		Context,
	};

	#[test]
	fn to_private_file() {
		let path = fs::to_path_buf("/my/dir/to");
		assert_eq!(
			super::to_private_file(&path),
			fs::to_path_buf("/my/dir/to/ecc.priv")
		);
	}

	#[test]
	fn to_public_file() {
		let path = fs::to_path_buf("/my/dir/to");
		assert_eq!(
			super::to_public_file(&path),
			fs::to_path_buf("/my/dir/to/ecc.pub")
		);
	}

	#[test]
	fn to_pcr_file() {
		let path = fs::to_path_buf("/my/dir/to");
		assert_eq!(
			super::to_pcr_file(&path),
			fs::to_path_buf("/my/dir/to/pcrs")
		);
	}

	#[test]
	fn to_handle_file() {
		let path = fs::to_path_buf("/my/dir/to");
		assert_eq!(
			super::to_handle_file(&path),
			fs::to_path_buf("/my/dir/to/handle")
		);
	}

	#[test]
	fn str_to_pcr() -> Result<(), DynError> {
		assert_eq!(super::str_to_pcr("4")?, super::PcrSlot::Slot4);
		assert_eq!(super::str_to_pcr("6")?, super::PcrSlot::Slot6);
		assert_eq!(super::str_to_pcr("7")?, super::PcrSlot::Slot7);
		assert_eq!(super::str_to_pcr("14")?, super::PcrSlot::Slot14);
		return Ok(());
	}

	#[test]
	fn str_to_pcrhandle() -> Result<(), DynError> {
		assert_eq!(
			super::str_to_pcrhandle("4")?,
			super::PcrHandle::Pcr4
		);
		assert_eq!(
			super::str_to_pcrhandle("6")?,
			super::PcrHandle::Pcr6
		);
		assert_eq!(
			super::str_to_pcrhandle("13")?,
			super::PcrHandle::Pcr13
		);
		assert_eq!(
			super::str_to_pcrhandle("14")?,
			super::PcrHandle::Pcr14
		);
		return Ok(());
	}

	#[test]
	fn create_context() -> Result<(), DynError> {
		let mut context = super::create_context()?;
		// test it can be used
		super::start_auth_session(&mut context)?;
		return Ok(());
	}

	#[test]
	fn start_auth_session() -> Result<(), DynError> {
		let mut context = super::create_context()?;
		let session = super::start_auth_session(&mut context)?;
		let super::AuthSession::PolicySession(policy) = session else {
			return Err("Wrong AuthSession".into());
		};
		match policy {
			PolicySession::PolicySession {
				hashing_algorithm: h,
				session_handle: _,
				session_type: t,
			} => {
				assert_eq!(h, super::HashingAlgorithm::Sha256);
				assert_eq!(t, SessionType::Policy);
			}
		}
		return Ok(());
	}

	#[test]
	fn create_public_for_primary() -> Result<(), DynError> {
		let digest = Digest::try_from([
			139, 67, 252, 206, 35, 178, 254, 86, 130, 216, 27, 41,
			104, 74, 93, 8, 215, 146, 120, 21, 6, 17, 220, 126, 89,
			9, 87, 123, 64, 19, 10, 139,
		])?;
		let public = super::create_public_for_primary(digest)?;
		assert_eq!(
			public.marshall()?,
			[
				0, 35, 0, 11, 0, 3, 0, 114, 0, 32, 139, 67,
				252, 206, 35, 178, 254, 86, 130, 216, 27, 41,
				104, 74, 93, 8, 215, 146, 120, 21, 6, 17, 220,
				126, 89, 9, 87, 123, 64, 19, 10, 139, 0, 6, 0,
				128, 0, 67, 0, 16, 0, 3, 0, 16, 0, 0, 0, 0
			]
		);
		return Ok(());
	}

	#[test]
	fn create_primary() -> Result<(), DynError> {
		let mut context = super::create_context()?;
		let digest = Digest::try_from([
			104, 74, 93, 8, 215, 146, 120, 21, 6, 17, 220, 126, 89,
			139, 67, 52, 206, 35, 18, 254, 86, 130, 216, 27, 41, 9,
			87, 123, 64, 19, 10, 139,
		])?;
		let res = super::create_primary(&mut context, digest)?;
		assert_eq!(
			res.out_public.marshall()?,
			[
				0, 35, 0, 11, 0, 3, 0, 114, 0, 32, 104, 74, 93,
				8, 215, 146, 120, 21, 6, 17, 220, 126, 89, 139,
				67, 52, 206, 35, 18, 254, 86, 130, 216, 27, 41,
				9, 87, 123, 64, 19, 10, 139, 0, 6, 0, 128, 0,
				67, 0, 16, 0, 3, 0, 16, 0, 32, 105, 12, 58,
				253, 147, 216, 247, 79, 148, 3, 44, 208, 244,
				192, 186, 234, 219, 53, 56, 84, 188, 205, 205,
				22, 147, 159, 235, 53, 236, 249, 111, 124, 0,
				32, 31, 210, 253, 103, 241, 70, 178, 220, 114,
				202, 16, 210, 251, 241, 36, 71, 240, 1, 9, 59,
				51, 61, 100, 213, 139, 98, 160, 149, 171, 215,
				207, 129
			]
		);
		assert_eq!(
			res.creation_hash,
			Digest::try_from([
				40, 208, 38, 250, 253, 116, 145, 6, 116, 62,
				39, 196, 40, 5, 81, 88, 94, 93, 23, 102, 142,
				181, 33, 131, 94, 214, 1, 39, 239, 252, 5, 212
			])?
		);

		assert_eq!(res.creation_ticket.tag(), Creation.into());
		assert_eq!(
			res.creation_ticket.hierarchy(),
			Hierarchy::Endorsement
		);
		assert_eq!(
			res.creation_ticket.digest(),
			[
				105, 20, 22, 135, 177, 254, 247, 189, 215, 111,
				187, 249, 34, 106, 163, 35, 15, 253, 167, 88,
				209, 72, 18, 5, 252, 114, 160, 193, 99, 229,
				174, 162, 114, 83, 7, 227, 173, 69, 165, 111,
				74, 245, 44, 61, 104, 154, 58, 18, 139, 221,
				37, 83, 62, 109, 139, 249, 123, 135, 137, 18,
				102, 10, 22, 85
			]
		);
		return Ok(());
	}

	#[test]
	fn set_policy() -> Result<(), DynError> {
		let mut context = super::create_context()?;
		let session = super::start_auth_session(&mut context)?;
		let pcrs = vec![super::PcrSlot::Slot4, super::PcrSlot::Slot7];
		super::set_policy(&mut context, &pcrs, session)?;
		let session_digest =
			context.policy_get_digest(session.try_into()?)?;
		assert_eq!(
			session_digest,
			Digest::try_from([
				244, 176, 153, 60, 161, 122, 79, 97, 227, 67,
				167, 86, 204, 57, 187, 62, 229, 184, 18, 180,
				79, 42, 235, 172, 74, 189, 195, 190, 237, 177,
				202, 65
			])?
		);

		context.policy_restart(session.try_into()?)?;
		super::set_policy(&mut context, &vec![], session)?;
		let session_digest2 =
			context.policy_get_digest(session.try_into()?)?;
		assert_eq!(
			session_digest2,
			Digest::try_from([
				125, 240, 82, 243, 104, 54, 228, 33, 118, 170,
				160, 184, 0, 165, 110, 243, 94, 215, 40, 244,
				108, 108, 180, 204, 131, 213, 96, 89, 73, 11,
				163, 97
			])?
		);
		return Ok(());
	}

	#[test]
	fn public_key() -> Result<(), DynError> {
		let public = tpm2::read_public_file(&fs::to_path_buf(
			"tests/files/tpm2/common/public",
		))?;
		assert_eq!(
			super::public_key(&public)?,
			vec![
				4, 4, 184, 250, 128, 44, 227, 198, 40, 4, 13,
				255, 100, 208, 40, 139, 26, 77, 51, 5, 196,
				245, 215, 14, 43, 193, 154, 79, 84, 35, 95, 45,
				46, 68, 53, 131, 217, 26, 43, 11, 114, 75, 128,
				75, 238, 184, 205, 132, 170, 167, 213, 26, 75,
				140, 87, 135, 88, 130, 248, 206, 4, 234, 53,
				158, 200
			]
		);
		return Ok(());
	}

	#[test]
	fn fingerprint() -> Result<(), DynError> {
		let public = tpm2::read_public_file(&fs::to_path_buf(
			"tests/files/tpm2/common/public",
		))?;
		assert_eq!(
			super::fingerprint(&public)?,
			vec![
				234, 226, 162, 228, 164, 14, 134, 142, 35, 96,
				203, 220, 2, 187, 123, 235, 66, 135, 37, 135,
				29, 140, 64, 239, 115, 128, 241, 116, 58, 172,
				69, 201
			]
		);
		return Ok(());
	}

	#[test]
	fn get_supported_hash_algorithms() -> Result<(), DynError> {
		let mut ctx = super::create_context()?;
		let res = super::get_supported_hash_algorithms(&mut ctx)?;
		assert_eq!(
			res,
			vec![
				super::HashingAlgorithm::Sha1,
				super::HashingAlgorithm::Sha256
			]
		);
		return Ok(());
	}

	pub fn assert_pcr_bank(
		context: &mut Context,
		slot: PcrSlot,
		exp_res: Vec<Digest>,
	) -> Result<(), DynError> {
		let pcrs = vec![slot];
		let pcr_selection_list = super::PcrSelectionListBuilder::new()
			.with_selection(
				super::HashingAlgorithm::Sha1,
				pcrs.as_slice(),
			)
			.with_selection(
				super::HashingAlgorithm::Sha256,
				pcrs.as_slice(),
			)
			.build()?;
		let (_, _, pcr_digests) =
			context.pcr_read(pcr_selection_list)?;
		// pcr_read returns sha1 and sha256 in random order
		let mut res = pcr_digests
			.value()
			.iter()
			.map(|d| {
				Digest::try_from(d.as_bytes().to_vec()).unwrap()
			})
			.collect::<Vec<Digest>>();
		res.sort_by_key(|d| d.as_bytes().len());
		assert_eq!(exp_res, res);
		return Ok(());
	}

	#[test]
	fn pcr_extend() -> Result<(), DynError> {
		let mut ctx = super::create_context()?;
		super::pcr_extend(
			&mut ctx,
			super::PcrHandle::Pcr13,
			vec![
				14, 43, 193, 154, 79, 84, 184, 205, 132, 170,
				14, 43, 193, 154, 79, 84, 184, 205, 132, 170,
				14, 43, 193, 154, 79, 84, 184, 205, 132,
			],
		)?;
		let sha1 = Digest::try_from(vec![
			31, 177, 22, 2, 220, 185, 80, 137, 124, 110, 47, 180,
			186, 160, 61, 195, 183, 246, 215, 174,
		])?;
		let sha256 = Digest::try_from(vec![
			75, 255, 0, 102, 197, 203, 33, 135, 238, 244, 54, 88,
			218, 180, 151, 159, 110, 225, 93, 2, 91, 17, 95, 147,
			17, 39, 44, 240, 149, 99, 246, 105,
		])?;
		assert_pcr_bank(&mut ctx, PcrSlot::Slot13, vec![sha1, sha256])?;
		return Ok(());
	}
}
