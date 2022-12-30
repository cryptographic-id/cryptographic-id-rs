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
