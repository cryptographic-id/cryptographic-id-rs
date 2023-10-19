use crate::conv;
use crate::sign::SigningConfig;
#[cfg(test)]
use crate::test_common::verify_p256;
use prost::Message;

include!(concat!(env!("OUT_DIR"), "/cryptographic_id.rs"));

pub fn to_data(m: &CryptographicId) -> Result<Vec<u8>, prost::EncodeError> {
	let mut buf = Vec::new();
	buf.reserve(m.encoded_len());
	m.encode(&mut buf)?;
	return Ok(buf);
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

#[cfg(test)]
pub fn verify(
	data: &CryptographicId,
) -> Result<(), Box<dyn std::error::Error>> {
	let to_sign_arr = to_sign_arr(&data);
	let sign_data = conv::flatten_binary_vec(&to_sign_arr);
	verify_p256(&data.public_key, &sign_data, &data.signature)?;

	for e in &data.personal_information {
		let e_to_sign_arr = personal_info_to_sign_arr(&e);
		let e_sign_data = conv::flatten_binary_vec(&e_to_sign_arr);
		verify_p256(&data.public_key, &e_sign_data, &e.signature)?;
	}
	return Ok(());
}

#[cfg(test)]
mod tests {
	use crate::error::DynError;
	use crate::fs;
	use crate::message;
	use message::cryptographic_id::PersonalInformation;
	use message::cryptographic_id::PersonalInformationType;
	use message::cryptographic_id::PublicKeyType;

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
	fn to_data() {
		let msg = example_id();
		assert_eq!(
			super::to_data(&msg).unwrap(),
			[
				10, 6, 48, 49, 50, 51, 52, 53, 16, 181, 6, 26,
				9, 109, 121, 77, 101, 115, 115, 97, 103, 101,
				82, 10, 18, 5, 80, 101, 116, 101, 114, 24, 181,
				6, 82, 17, 8, 7, 18, 10, 43, 49, 50, 51, 52,
				53, 54, 55, 56, 57, 24, 181, 6
			]
		);
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
		assert_eq!(super::to_data(&msg).unwrap(), exp_result);
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
}
