use crate::conv;
use crate::ed25519;
use crate::error::DynError;
use crate::prime256v1;
use crate::sign::SigningConfig;
use crate::time;

use base64::Engine;
use prost::Message;

include!(concat!(env!("OUT_DIR"), "/cryptographic_id.rs"));
use cryptographic_id::PublicKeyType;

pub fn to_binary(m: &CryptographicId) -> Result<Vec<u8>, prost::EncodeError> {
	let mut buf = Vec::new();
	buf.reserve(m.encoded_len());
	m.encode(&mut buf)?;
	return Ok(buf);
}

pub fn from_binary(
	data: Vec<u8>,
) -> Result<CryptographicId, prost::DecodeError> {
	return CryptographicId::decode(&*data);
}

pub fn to_base64(m: &CryptographicId) -> Result<String, prost::EncodeError> {
	return Ok(base64::engine::general_purpose::STANDARD
		.encode(to_binary(&m)?));
}

#[derive(Debug)]
pub enum DecodeError {
	ProtobufError(prost::DecodeError),
	Base64Error(base64::DecodeError),
}

impl From<base64::DecodeError> for DecodeError {
	fn from(i: base64::DecodeError) -> DecodeError {
		return DecodeError::Base64Error(i);
	}
}

impl From<prost::DecodeError> for DecodeError {
	fn from(i: prost::DecodeError) -> DecodeError {
		return DecodeError::ProtobufError(i);
	}
}

pub fn from_base64(msg: String) -> Result<CryptographicId, DecodeError> {
	let b = base64::engine::general_purpose::STANDARD.decode(msg)?;
	return Ok(from_binary(b)?);
}

pub fn to_public_key_type(s: i32) -> Result<PublicKeyType, DynError> {
	return match s {
		0 => Ok(PublicKeyType::Ed25519),
		1 => Ok(PublicKeyType::Prime256v1),
		_ => Err("Unknown public key type".into()),
	};
}

pub fn to_sign_arr(data: &CryptographicId) -> Vec<Vec<u8>> {
	let to_sign_arr = [
		data.timestamp.to_be_bytes().to_vec(),
		data.public_key.clone(),
		data.msg.clone(),
	];
	return to_sign_arr.to_vec();
}

fn personal_info_to_sign_arr(
	info: &cryptographic_id::PersonalInformation,
) -> Vec<Vec<u8>> {
	return [
		info.timestamp.to_be_bytes().to_vec(),
		info.r#type.to_be_bytes().to_vec(),
		info.value.clone(),
	]
	.to_vec();
}

pub fn sign(
	data: &mut CryptographicId,
	sign_config: &mut SigningConfig,
) -> Result<(), Box<dyn std::error::Error>> {
	data.public_key = sign_config.public_key()?;
	data.public_key_type = sign_config.public_key_type().into();
	let to_sign_arr = to_sign_arr(&data);
	let sign_data = conv::flatten_binary_vec(&to_sign_arr);
	data.signature = sign_config.sign(&sign_data)?;

	for e in &mut data.personal_information {
		let e_to_sign_arr = personal_info_to_sign_arr(&e);
		let e_sign_data = conv::flatten_binary_vec(&e_to_sign_arr);
		e.signature = sign_config.sign(&e_sign_data)?;
	}
	return Ok(());
}

pub fn fingerprint(data: &CryptographicId) -> Result<Vec<u8>, DynError> {
	match to_public_key_type(data.public_key_type)? {
		PublicKeyType::Ed25519 => {
			let bytes = data.public_key.as_slice().try_into()?;
			let key = ed25519::VerifyingKey::from_bytes(&bytes)?;
			return Ok(ed25519::fingerprint(&key)?);
		}
		PublicKeyType::Prime256v1 => {
			let key = prime256v1::VerifyingKey::from_sec1_bytes(
				&data.public_key,
			)?;
			return Ok(prime256v1::fingerprint(&key)?);
		}
	}
}

pub fn verify(data: &CryptographicId) -> Result<(), DynError> {
	let to_sign_arr = to_sign_arr(&data);
	let sign_data = conv::flatten_binary_vec(&to_sign_arr);
	let verifier = match to_public_key_type(data.public_key_type)? {
		PublicKeyType::Ed25519 => ed25519::verify,
		PublicKeyType::Prime256v1 => prime256v1::verify,
	};
	verifier(&data.public_key, &sign_data, &data.signature)?;

	for e in &data.personal_information {
		let e_to_sign_arr = personal_info_to_sign_arr(&e);
		let e_sign_data = conv::flatten_binary_vec(&e_to_sign_arr);
		verifier(&data.public_key, &e_sign_data, &e.signature)?;
	}
	return Ok(());
}

pub fn verify_current_with_msg(
	data: &CryptographicId,
	msg: &String,
) -> Result<(), String> {
	if data.msg != msg.as_bytes().to_vec() {
		return Err(format!("Wrong message, please share {}", msg));
	}
	let now = time::now();
	if data.timestamp > now + 5 {
		return Err(format!("Signature in the future"));
	}
	if data.timestamp < now - time::ONE_MINUTE_IN_SEC {
		return Err(format!("Signature older than 1m"));
	}
	return match verify(&data) {
		Ok(()) => Ok(()),
		Err(e) => Err(format!("Wrong signature: {}", e)),
	};
}

#[cfg(test)]
mod tests {
	use crate::error::DynError;
	use crate::fs;
	use crate::message;
	use message::cryptographic_id::PersonalInformation;
	use message::cryptographic_id::PersonalInformationType;
	use message::cryptographic_id::PublicKeyType;
	use prost::Message;
	const TESTKEY_PATH: &str = "tests/files/message/sign/key_ed25519";

	fn example_id() -> message::CryptographicId {
		let first_name_type = PersonalInformationType::FirstName;
		let phone_number_type = PersonalInformationType::PhoneNumber;
		let phone_number = "+123456789".as_bytes().to_vec();
		return message::CryptographicId {
			public_key: b"012345".to_vec(),
			timestamp: 821,
			msg: b"myMessage".to_vec(),
			public_key_type: PublicKeyType::Ed25519 as i32,
			signature: Vec::new(),
			personal_information: vec![
				PersonalInformation {
					r#type: first_name_type as i32,
					value: "Peter".as_bytes().to_vec(),
					timestamp: 821,
					signature: vec![],
				},
				PersonalInformation {
					r#type: phone_number_type as i32,
					value: phone_number,
					timestamp: 821,
					signature: vec![],
				},
			],
		};
	}

	fn example_id_binary() -> Vec<u8> {
		return [
			10, 6, 48, 49, 50, 51, 52, 53, 16, 181, 6, 26, 9, 109,
			121, 77, 101, 115, 115, 97, 103, 101, 82, 10, 18, 5,
			80, 101, 116, 101, 114, 24, 181, 6, 82, 17, 8, 7, 18,
			10, 43, 49, 50, 51, 52, 53, 54, 55, 56, 57, 24, 181, 6,
		]
		.to_vec();
	}

	fn example_id_base64() -> String {
		return format!(
			"{}{}",
			"CgYwMTIzNDUQtQYaCW15TWVzc2FnZVIKEgVQZXRlchi1B",
			"lIRCAcSCisxMjM0NTY3ODkYtQY="
		);
	}

	fn signed_example_id_ed25519() -> message::CryptographicId {
		let mut key = super::SigningConfig::load(&fs::to_path_buf(
			TESTKEY_PATH,
		))
		.unwrap();
		let mut msg = example_id();
		msg.public_key = key.public_key().unwrap();
		message::sign(&mut msg, &mut key).unwrap();
		return msg;
	}

	#[test]
	fn to_sign_arr() {
		let msg = example_id();
		assert_eq!(
			super::to_sign_arr(&msg),
			vec![
				821_i64.to_be_bytes().to_vec(),
				b"012345".to_vec(),
				b"myMessage".to_vec()
			]
		);
	}

	#[test]
	fn personal_info_to_sign_arr() {
		let info = PersonalInformation {
			r#type: PersonalInformationType::PhoneNumber as i32,
			value: "+123456789".as_bytes().to_vec(),
			timestamp: 10251251,
			signature: vec![],
		};
		let pn_type = PersonalInformationType::PhoneNumber as i32;
		assert_eq!(
			super::personal_info_to_sign_arr(&info),
			vec![
				10251251_i64.to_be_bytes().to_vec(),
				pn_type.to_be_bytes().to_vec(),
				b"+123456789".to_vec()
			]
		);
	}

	#[test]
	fn to_binary() {
		let msg = example_id();
		assert_eq!(
			super::to_binary(&msg).unwrap(),
			example_id_binary()
		);
	}

	#[test]
	fn from_binary() {
		let msg = super::from_binary(example_id_binary()).unwrap();
		assert_eq!(msg, example_id());
	}

	#[test]
	fn to_base64() {
		let s = super::to_base64(&example_id());
		assert_eq!(s, Ok(example_id_base64()));
	}

	#[test]
	fn from_base64() {
		let msg = super::from_base64(example_id_base64()).unwrap();
		assert_eq!(msg, example_id());
	}

	#[test]
	fn to_public_key_type() -> Result<(), DynError> {
		assert_eq!(
			super::to_public_key_type(0)?,
			PublicKeyType::Ed25519
		);
		assert_eq!(
			super::to_public_key_type(1)?,
			PublicKeyType::Prime256v1
		);
		for i in 2..257 {
			assert_eq!(
				format!("{:?}", super::to_public_key_type(i)),
				"Err(\"Unknown public key type\")"
			);
		}
		return Ok(());
	}

	#[test]
	fn sign_ed25519() {
		let mut key = super::SigningConfig::load(&fs::to_path_buf(
			"tests/files/message/sign/key_ed25519",
		))
		.unwrap();
		let mut msg = example_id();
		message::sign(&mut msg, &mut key).unwrap();
		let exp_result = fs::read_file(&fs::to_path_buf(
			"tests/files/message/sign/result_ed25519",
		))
		.unwrap();
		assert_eq!(super::to_binary(&msg).unwrap(), exp_result);
	}

	#[test]
	fn sign_tpm2() -> Result<(), DynError> {
		let mut key = super::SigningConfig::load(&fs::to_path_buf(
			"tests/files/message/sign/tpm2",
		))?;
		let mut msg = example_id();
		message::sign(&mut msg, &mut key)?;
		message::verify(&msg)?;
		assert_eq!(msg.public_key, key.public_key()?);
		assert_eq!(msg.public_key_type, key.public_key_type() as i32);
		// verify only signature and public key changed
		msg.signature = example_id().signature;
		msg.public_key = example_id().public_key;
		msg.public_key_type = example_id().public_key_type;
		msg.personal_information[0].signature =
			example_id().personal_information[0].signature.clone();
		msg.personal_information[1].signature =
			example_id().personal_information[1].signature.clone();
		assert_eq!(msg, example_id());
		return Ok(());
	}

	#[test]
	fn verify_ed25519() {
		let msg = signed_example_id_ed25519();
		message::verify(&msg).unwrap();

		fn test_mod<F>(f: F)
		where
			F: Fn(&mut message::CryptographicId),
		{
			let mut msg = signed_example_id_ed25519();
			f(&mut msg);
			assert!(message::verify(&msg).is_err());
		}
		test_mod(|a| {
			a.public_key[4] = 2;
		});
		test_mod(|a| {
			a.timestamp = 1234;
		});
		test_mod(|a| {
			a.msg = b"haha".to_vec();
		});
		test_mod(|a| {
			a.public_key_type = PublicKeyType::Prime256v1 as i32;
		});
		test_mod(|a| {
			a.signature[10] = 18;
		});
		test_mod(|a| a.personal_information[0].r#type = 50);
		test_mod(|a| a.personal_information[0].value[4] = 50);
		test_mod(|a| a.personal_information[1].timestamp = 50);
		test_mod(|a| a.personal_information[1].signature[4] = 50);
	}

	fn signed_prime256v1_message() -> message::CryptographicId {
		let data = fs::read_file(&fs::to_path_buf(
			"tests/files/message/verify_prime256v1",
		))
		.unwrap();
		return message::CryptographicId::decode(&*data).unwrap();
	}

	#[test]
	fn fingerprint() -> Result<(), DynError> {
		let p256_msg = signed_prime256v1_message();
		assert_eq!(
			super::fingerprint(&p256_msg)?,
			vec![
				37, 14, 249, 247, 15, 234, 71, 25, 89, 5, 23,
				166, 133, 31, 254, 16, 11, 219, 31, 43, 79,
				170, 147, 7, 232, 67, 2, 189, 165, 246, 85,
				133
			]
		);
		let ed25519_msg = signed_example_id_ed25519();
		assert_eq!(
			super::fingerprint(&ed25519_msg)?,
			vec![
				101, 82, 102, 168, 36, 174, 45, 89, 6, 178,
				113, 79, 120, 111, 19, 50, 15, 198, 239, 109,
				62, 149, 56, 184, 126, 74, 170, 106, 123, 94,
				251, 108
			]
		);
		return Ok(());
	}

	#[test]
	fn verify_prime256v1() {
		let msg = signed_prime256v1_message();
		message::verify(&msg).unwrap();

		fn test_mod<F>(f: F)
		where
			F: Fn(&mut message::CryptographicId),
		{
			let mut msg = signed_prime256v1_message();
			f(&mut msg);
			assert!(message::verify(&msg).is_err());
		}
		test_mod(|a| {
			a.public_key[4] = 2;
		});
		test_mod(|a| {
			a.timestamp = 1234;
		});
		test_mod(|a| {
			a.msg = b"haha".to_vec();
		});
		test_mod(|a| {
			a.public_key_type = PublicKeyType::Ed25519 as i32;
		});
		test_mod(|a| {
			a.signature[10] = 18;
		});
		test_mod(|a| a.personal_information[0].r#type = 50);
		test_mod(|a| a.personal_information[0].value[4] = 50);
		test_mod(|a| a.personal_information[1].timestamp = 50);
		test_mod(|a| a.personal_information[1].signature[4] = 50);
	}

	#[test]
	fn verify_current_with_msg() -> Result<(), DynError> {
		let mut key = super::SigningConfig::load(&fs::to_path_buf(
			TESTKEY_PATH,
		))
		.unwrap();
		let mut msg = example_id();
		let now = super::time::now();
		let correct_msg = "myMessage".to_string();
		msg.public_key = key.public_key().unwrap();
		// still in the range
		msg.timestamp = now + 3;
		message::sign(&mut msg, &mut key)?;
		super::verify_current_with_msg(&msg, &correct_msg).unwrap();

		// oldest possible
		msg.timestamp = now - super::time::ONE_MINUTE_IN_SEC + 2;
		message::sign(&mut msg, &mut key)?;
		super::verify_current_with_msg(&msg, &correct_msg).unwrap();

		// wrong msg
		assert_eq!(
			super::verify_current_with_msg(
				&msg,
				&"1234".to_string()
			),
			Err("Wrong message, please share 1234".to_string())
		);
		// in the future
		msg.timestamp = now + 7;
		message::sign(&mut msg, &mut key)?;
		assert_eq!(
			super::verify_current_with_msg(&msg, &&correct_msg),
			Err("Signature in the future".to_string())
		);
		// in the past
		msg.timestamp = now - super::time::ONE_MINUTE_IN_SEC - 1;
		message::sign(&mut msg, &mut key)?;
		assert_eq!(
			super::verify_current_with_msg(&msg, &&correct_msg),
			Err("Signature older than 1m".to_string())
		);
		// wrong sig
		msg.timestamp = now - 1;
		message::sign(&mut msg, &mut key)?;
		msg.timestamp = now - 3;
		let err = super::verify_current_with_msg(&msg, &&correct_msg);
		assert!(err.is_err());
		match err {
			Err(e) => assert!(e.starts_with("Wrong signature: ")),
			_ => (),
		}
		return Ok(());
	}
}
