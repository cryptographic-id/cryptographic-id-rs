use tss_esapi::{
	abstraction::{ak, ek, AsymmetricAlgorithmSelection, DefaultKey},
	attributes::SessionAttributesBuilder,
	constants::SessionType,
	handles::{AuthHandle, KeyHandle},
	interface_types::{
		algorithm::{HashingAlgorithm, SignatureSchemeAlgorithm},
		ecc::EccCurve,
		reserved_handles::Hierarchy,
		session_handles::PolicySession,
	},
	structures::{
		Attest, AttestInfo, Data, DigestList, PcrSelectionList,
		PcrSelectionListBuilder, PcrSlot, Public, QuoteInfo,
		Signature, SignatureScheme, SymmetricDefinition,
	},
	traits::Marshall,
	traits::UnMarshall,
	Context, TctiNameConf,
};

use crate::conv;
use crate::error::DynError;
use crate::fs;
use crate::tpm2;
use sha2::Digest;

#[derive(Clone, Debug)]
pub struct AKResult {
	pub key_handle: KeyHandle,
	pub public: Public,
	pub private: tss_esapi::structures::Private,
	pub name: tss_esapi::structures::Name,
}

#[derive(Clone, Debug)]
pub struct EKResult {
	pub key_handle: KeyHandle,
	pub ek_cert: Option<Vec<u8>>,
	pub public: Public,
	pub name: tss_esapi::structures::Name,
}

pub fn create_ek(context: &mut Context) -> Result<EKResult, DynError> {
	let alg = AsymmetricAlgorithmSelection::Ecc(EccCurve::NistP256);
	// let alg = AsymmetricAlgorithmSelection::Rsa(RsaKeyBits::Rsa2048);
	let key_handle = ek::create_ek_object(context, alg, DefaultKey)?;
	let cert = match ek::retrieve_ek_pubcert(context, alg.into()) {
		Ok(v) => {
			fs::write_file(&v, &fs::to_path_buf("out/ek_cert"))?;
			Some(v)
		}
		Err(_) => {
			println!("No pubcert found");
			None
		}
	};
	let (tpm_pub, tpm_name, _) = context.read_public(key_handle)?;
	fs::write_file(
		&tpm_pub.marshall()?,
		&fs::to_path_buf("out/ek_public"),
	)?;
	fs::write_file(
		&tpm_name.value().to_vec(),
		&fs::to_path_buf("out/ek_name"),
	)?;
	let res = EKResult {
		key_handle,
		ek_cert: cert,
		public: tpm_pub,
		name: tpm_name,
	};
	return Ok(res);
}

pub fn create_ak(
	context: &mut Context,
	ek_handle: KeyHandle,
) -> Result<AKResult, DynError> {
	println!("Create ak");
	let ak = ak::create_ak(
		context,
		ek_handle,
		HashingAlgorithm::Sha256,
		AsymmetricAlgorithmSelection::Ecc(EccCurve::NistP256),
		SignatureSchemeAlgorithm::EcDsa,
		None,
		DefaultKey,
	)?;

	println!("load ak");
	let key_handle = ak::load_ak(
		context,
		ek_handle,
		None,
		ak.out_private.clone(),
		ak.out_public.clone(),
	)?;
	let (_, tpm_name, _) = context.read_public(key_handle)?;
	fs::write_file(
		&ak.out_public.marshall()?,
		&fs::to_path_buf("out/ak_public"),
	)?;
	fs::write_file(
		&tpm_name.value().to_vec(),
		&fs::to_path_buf("out/ak_name"),
	)?;

	Ok(AKResult {
		public: ak.out_public,
		private: ak.out_private,
		key_handle: key_handle,
		name: tpm_name,
	})
}

pub fn checkquote_pcr_digests(
	quote: &QuoteInfo,
	selections: &PcrSelectionList,
	digests: &DigestList,
) -> Result<bool, DynError> {
	if selections != quote.pcr_selection() {
		return Ok(false);
	}
	let digests_val = digests.value();
	let mut digest_pos = 0;
	let mut hasher = sha2::Sha256::new();

	for selection in selections.get_selections() {
		let sel_count = selection.selected().len();
		if digest_pos + sel_count > digests.len() {
			return Err("Not enough digests provided".into());
		}
		for _ in 0..sel_count {
			hasher.update(&digests_val[digest_pos]);
			digest_pos += 1;
		}
	}
	if digest_pos != digests.len() {
		return Err("Too many digests provided".into());
	}
	let digest = hasher.finalize().to_vec();
	if digest != quote.pcr_digest().as_bytes() {
		return Ok(false);
	}
	return Ok(true);
}

pub fn checkquote(
	attest: &Attest,
	signature: &Signature,
	public: &Public,
	pcr_data: &Option<(PcrSelectionList, DigestList)>,
	nonce: &Option<Vec<u8>>,
) -> Result<bool, DynError> {
	let quote = match attest.attested() {
		AttestInfo::Quote { info } => info,
		_ => {
			return Err("Not a tpm2 quote".into());
		}
	};
	let bytes = attest.marshall()?;
	let pubkey = tpm2::public_key(public).unwrap();
	match signature {
		Signature::EcDsa(sig) => {
			let sig = tpm2::signature_to_asn1(sig).unwrap();
			crate::prime256v1::verify(&pubkey, &bytes, &sig)
				.unwrap();
		}
		_ => {
			return Err("Only EcDsa supported".into());
		}
	};

	match nonce {
		Some(n) => {
			if n != attest.extra_data().as_bytes() {
				return Ok(false);
			}
		}
		None => {}
	}
	match pcr_data {
		Some((selections, digests)) => {
			if !checkquote_pcr_digests(
				&quote,
				&selections,
				&digests,
			)? {
				return Ok(false);
			}
		}
		None => {}
	}
	return Ok(true);
}

pub fn pcr_quote(
	context: &mut Context,
	handle: KeyHandle,
	nonce: &String,
) -> Result<(), DynError> {
	let pcr_selection_list = PcrSelectionListBuilder::new()
		.with_selection(HashingAlgorithm::Sha256, &[PcrSlot::Slot0])
		.with_selection(HashingAlgorithm::Sha256, &[PcrSlot::Slot4])
		.with_selection(HashingAlgorithm::Sha256, &[PcrSlot::Slot7])
		.with_selection(HashingAlgorithm::Sha1, &[PcrSlot::Slot7])
		.build()?;
	let nonce_bytes = nonce.as_bytes().to_vec();
	fs::write_file(&nonce_bytes, &fs::to_path_buf("out/nonce"))?;

	let (attest, signature) =
		context.execute_with_nullauth_session(|ctx| {
			ctx.quote(
				handle,
				Data::try_from(nonce_bytes.clone())?,
				SignatureScheme::Null,
				pcr_selection_list.clone(),
			)
		})?;
	let (_, _, pcr_data) = context.pcr_read(pcr_selection_list.clone())?;
	let (tpm_pub, _, _) = context.read_public(handle)?;
	checkquote(
		&attest,
		&signature,
		&tpm_pub,
		&Some((pcr_selection_list.clone(), pcr_data)),
		&Some(nonce_bytes),
	)
	.unwrap();
	fs::write_file(&attest.marshall()?, &fs::to_path_buf("out/attest"))?;
	fs::write_file(&signature.marshall()?, &fs::to_path_buf("out/sig"))?;
	return Ok(());
}

pub fn activate_credential(
	context: &mut Context,
	ek_handle: KeyHandle,
	ak: &AKResult,
) -> Result<(), DynError> {
	println!("activate_credential");

	let cred = vec![1, 2, 3, 4, 5];
	let (session_aastributes, session_attributes_mask) =
		SessionAttributesBuilder::new().build();
	let session_1 = context
		.start_auth_session(
			None,
			None,
			None,
			SessionType::Hmac,
			SymmetricDefinition::AES_256_CFB,
			HashingAlgorithm::Sha256,
		)?
		.expect("Failed invalid session value");
	context.tr_sess_set_attributes(
		session_1,
		session_aastributes,
		session_attributes_mask,
	)?;
	let session_2 = context
		.start_auth_session(
			None,
			None,
			None,
			SessionType::Policy,
			SymmetricDefinition::AES_256_CFB,
			HashingAlgorithm::Sha256,
		)?
		.expect("Failed invalid session value");
	context.tr_sess_set_attributes(
		session_2,
		session_aastributes,
		session_attributes_mask,
	)?;

	let (credential_blob, secret) =
		context.execute_without_session(|ctx| {
			ctx.make_credential(
				ek_handle,
				cred.try_into()?,
				ak.name.clone(),
			)
		})?;

	let _ = context.execute_with_session(Some(session_1), |ctx| {
		ctx.policy_secret(
			PolicySession::try_from(session_2)?,
			AuthHandle::Endorsement,
			Default::default(),
			Default::default(),
			Default::default(),
			None,
		)
	})?;

	let decrypted = context.execute_with_sessions(
		(Some(session_1), Some(session_2), None),
		|ctx| {
			ctx.activate_credential(
				ak.key_handle,
				ek_handle,
				credential_blob,
				secret,
			)
		},
	)?;
	println!("Decrypted: {:?}", decrypted);

	return Ok(());
}

pub fn make_credential(
	context: &mut Context,
	ek: &EKResult,
	ak: &AKResult,
) -> Result<(), DynError> {
	println!("make_credential");
	let cred = vec![1, 2, 3, 4, 5];

	let ek_handle = context.load_external_public(
		ek.public.clone(),
		Hierarchy::Endorsement,
	)?;

	let (credential_blob, _secret) =
		context.execute_without_session(|ctx| {
			ctx.make_credential(
				ek_handle,
				cred.try_into()?,
				ak.name.clone(),
			)
		})?;
	return Ok(());
}



pub fn show_fingerprint(public: &Public) -> Result<(), DynError> {
	let fp = tpm2::fingerprint(&public)?;
	println!("{}", conv::fingerprint_to_hex(&fp));
	return Ok(());
}

pub fn create_none_context() -> Result<Context, DynError> {
	let device = TctiNameConf::from_str("none")?;
	return Ok(Context::new(device)?);
}

pub fn attestation(nonce: String) -> Result<(), DynError> {
	let mut none_context = tpm2::create_none_context()?;
	let mut context = tpm2::create_context()?;
	let ek = create_ek(&mut context)?;
	println!("EK fingerprint:");
	show_fingerprint(&ek.public)?;
	let ak = create_ak(&mut context, ek.key_handle)?;
	println!("AK fingerprint:");
	show_fingerprint(&ak.public)?;
	// make_credential(&mut none_context, &ek, &ak)?;
	activate_credential(&mut context, ek.key_handle, &ak)?;
	pcr_quote(&mut context, ak.key_handle, &nonce)?;
	return Ok(());
}

// Mobile needs:
// a load initial data and save it (cert, publics)
// b make credential
// c check quote, get pcrs, verify tpm2 cert

// PC needs:
// a share initial data (cert, publics)
// b activate credential and create quote

pub fn show_attest() -> Result<(), DynError> {
	let ek_public_content =
		fs::read_file(&fs::to_path_buf("out/ek_public"))?;
	let ek_public = Public::unmarshall(&ek_public_content)?;

	let ak_public_content =
		fs::read_file(&fs::to_path_buf("out/ak_public"))?;
	let ak_public = Public::unmarshall(&ak_public_content)?;

	println!("EK fingerprint:");
	show_fingerprint(&ek_public)?;
	println!("AK fingerprint:");
	show_fingerprint(&ak_public)?;

	let sig_content = fs::read_file(&fs::to_path_buf("out/sig"))?;
	let sig = Signature::unmarshall(&sig_content)?;
	let attest_content = fs::read_file(&fs::to_path_buf("out/attest"))?;
	let attest = Attest::unmarshall(&attest_content)?;
	println!("Attest:\n{:?}", attest);

	return Ok(());
}


// create:
// cargo run attest priv_nonce_2024
// tpm2_pcrread sha256:0,4,7 --pcrs_format serialized -o out/pcrs

// verify:
// tpm2_checkquote --public out/ak_public --message out/attest --signature out/sig --qualification out/nonce --pcr out/pcrs
// cargo run show-attest
