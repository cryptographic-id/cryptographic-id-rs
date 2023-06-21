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
		data.msg.clone()];
	return to_sign_arr.to_vec();
}


#[cfg(test)]
mod tests {
	use crate::message;
	use message::cryptographic_id::PublicKeyType;

	fn example_id() -> message::CryptographicId {
		return message::CryptographicId {
			public_key: b"012345".to_vec(),
			timestamp: 821,
			msg: b"myMessage".to_vec(),
			public_key_type: PublicKeyType::Ed25519 as i32,
			signature: Vec::new(),
			personal_information: Vec::new(),
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
	fn to_data() {
		let msg = example_id();
		assert_eq!(
			super::to_data(&msg).unwrap(),
			[10, 6, 48, 49, 50, 51, 52, 53, 16, 181, 6, 26, 9, 109,
			 121, 77, 101, 115, 115, 97, 103, 101]);
	}
}
