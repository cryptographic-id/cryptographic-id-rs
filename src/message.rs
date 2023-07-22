use prost::Message;
use crate::ed25519;

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
		data.msg.clone()];
	return to_sign_arr.to_vec();
}

fn personal_info_to_sign_arr(info: &cryptographic_id::PersonalInformation)
		-> Vec<Vec<u8>> {
	return [
		info.timestamp.to_be_bytes().to_vec(),
		info.r#type.to_be_bytes().to_vec(),
		info.value.clone()].to_vec();
}

pub fn sign(data: &mut CryptographicId, keypair: &ed25519::SigningKey) {
	let to_sign_arr = to_sign_arr(&data);
	data.signature = ed25519::sign_array(&keypair, &to_sign_arr);

	for e in &mut data.personal_information {
		let e_to_sign_arr = personal_info_to_sign_arr(&e);
		e.signature = ed25519::sign_array(
			&keypair, &e_to_sign_arr.to_vec());
	}
}

#[cfg(test)]
mod tests {
	use crate::message;
	use crate::ed25519;
	use crate::fs;
	use message::cryptographic_id::PublicKeyType;
	use message::cryptographic_id::PersonalInformation;
	use message::cryptographic_id::PersonalInformationType;

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
				PersonalInformation{
					r#type: first_name_type as i32,
					value: "Peter".as_bytes().to_vec(),
					timestamp: 821,
					signature: vec![],
				},
				PersonalInformation{
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
				b"myMessage".to_vec()]);
	}

	#[test]
	fn personal_info_to_sign_arr() {
		let info = PersonalInformation{
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
				b"+123456789".to_vec()]);
	}

	#[test]
	fn to_data() {
		let msg = example_id();
		assert_eq!(
			super::to_data(&msg).unwrap(),
			[10, 6, 48, 49, 50, 51, 52, 53, 16, 181, 6, 26, 9,
			 109, 121, 77, 101, 115, 115, 97, 103, 101, 82, 10, 18,
			 5, 80, 101, 116, 101, 114, 24, 181, 6, 82, 17, 8, 7,
			 18, 10, 43, 49, 50, 51, 52, 53, 54, 55, 56, 57, 24,
			 181, 6]);
	}

	#[test]
	fn sign() {
		let key = ed25519::load_keypair_from_file(
			&fs::to_path_buf(
				"tests/files/message/sign/key")).unwrap();
		let mut msg = example_id();
		msg.public_key = key.verifying_key().to_bytes().to_vec();
		message::sign(&mut msg, &key);
		let exp_result = fs::read_file(
			&fs::to_path_buf(
				"tests/files/message/sign/result")).unwrap();
		assert_eq!(super::to_data(&msg).unwrap(), exp_result);
	}
}
