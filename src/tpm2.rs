use std::io;
use std::path::PathBuf;
use prost::Message;
use crate::conv;
use crate::fs;
use crate::message;
use crate::time;
use message::cryptographic_id::SignatureType;

fn id_path(out: &PathBuf) -> PathBuf {
	let mut out_id = out.clone();
	out_id.push("id.bin");
	return out_id;
}

fn to_sign_path(out: &PathBuf) -> PathBuf {
	let mut out_sig = out.clone();
	out_sig.push("to_sign.bin");
	return out_sig;
}

pub fn build(key_path: PathBuf, msg_path: PathBuf, out: PathBuf)
		-> io::Result<()> {
	let timestamp = time::now();
	let msg = message::CryptographicId {
		public_key: fs::read_file(key_path)?,
		timestamp: timestamp,
		msg: fs::read_file(msg_path)?,
		signature: Vec::new(),
		signature_type: SignatureType::Prime256v1Sha256 as i32,
		personal_information: Vec::new(),
	};
	let out_id = id_path(&out);
	fs::write_file(message::to_data(&msg)?, out_id)?;
	let out_sign = to_sign_path(&out);
	let sign_data = conv::flatten_binary_vec(&message::to_sign_arr(&msg));
	fs::write_file(sign_data, out_sign)?;
	return Ok(());
}

pub fn read_id(sig_path: PathBuf, out: PathBuf)
		-> io::Result<message::CryptographicId> {
	let id_path = id_path(&out);
	let data = fs::read_file(id_path)?;
	let sig = fs::read_file(sig_path)?;
	let buf: &[u8] = &data;
	let mut msg = message::CryptographicId::decode(buf)?;
	msg.signature = sig;
	return Ok(msg);
}
