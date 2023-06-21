use std::io;
use std::path::PathBuf;
use prost::Message;
use crate::conv;
use crate::fs;
use crate::message;
use message::cryptographic_id::PublicKeyType;

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

pub fn build(key_path: &PathBuf, msg_path: &PathBuf, timestamp: u64,
             out: &PathBuf) -> io::Result<()> {
	let msg = message::CryptographicId {
		public_key: fs::read_file(&key_path)?,
		timestamp: timestamp,
		msg: fs::read_file(&msg_path)?,
		signature: Vec::new(),
		public_key_type: PublicKeyType::Prime256v1 as i32,
		personal_information: Vec::new(),
	};
	let out_id = id_path(&out);
	fs::write_file(&message::to_data(&msg)?, &out_id)?;
	let out_sign = to_sign_path(&out);
	let sign_data = conv::flatten_binary_vec(&message::to_sign_arr(&msg));
	fs::write_file(&sign_data, &out_sign)?;
	return Ok(());
}

pub fn read_id(sig_path: &PathBuf, out: &PathBuf)
		-> io::Result<message::CryptographicId> {
	let id_path = id_path(&out);
	let data = fs::read_file(&id_path)?;
	let sig = fs::read_file(&sig_path)?;
	let buf: &[u8] = &data;
	let mut msg = message::CryptographicId::decode(buf)?;
	msg.signature = sig;
	return Ok(msg);
}

#[cfg(test)]
mod tests {
	use std::io;
	use super::fs;
	use tempfile;

	#[test]
	fn id_path() {
		let path = fs::to_path_buf("/my/dir/to");
		assert_eq!(
			super::id_path(&path),
			fs::to_path_buf("/my/dir/to/id.bin"));
	}

	#[test]
	fn to_sign_path() {
		let path = super::fs::to_path_buf("/my/important/dir");
		assert_eq!(
			super::to_sign_path(&path),
			fs::to_path_buf("/my/important/dir/to_sign.bin"));
	}

	#[test]
	fn build() -> io::Result<()> {
		let tmpdir_in = tempfile::tempdir()?;
		let tmpdir_out = tempfile::tempdir()?;
		let key_path = tmpdir_in.path().join("keyfile.bin");
		let msg_path = tmpdir_in.path().join("msgfile.bin");
		let pubkey = b"a_wrong_pubkey".to_vec();
		let msg = b"my_message".to_vec();
		fs::write_file(&pubkey, &key_path)?;
		fs::write_file(&msg, &msg_path)?;
		let timestamp = 1412424562;
		let outpath = &tmpdir_out.path().to_path_buf();
		super::build(&key_path, &msg_path, timestamp, &outpath)?;
		let tosign = super::to_sign_path(&outpath);
		assert_eq!(
			fs::read_file(&tosign)?,
			[0, 0, 0, 0, 84, 47, 227, 114, 97, 95, 119, 114, 111,
			 110, 103, 95, 112, 117, 98, 107, 101, 121, 109, 121,
			 95, 109, 101, 115, 115, 97, 103, 101]);
		let sig_path = tmpdir_in.path().join("sig.bin");
		let sig = b"a broken sig".to_vec();
		fs::write_file(&sig, &sig_path)?;
		let id = super::read_id(&sig_path, &outpath)?;
		let compare_id = super::message::CryptographicId {
			public_key: pubkey,
			timestamp: timestamp,
			msg: msg,
			signature: sig,
			public_key_type: super::PublicKeyType::Prime256v1 as i32,
			personal_information: Vec::new(),
		};
		assert_eq!(id, compare_id);
		return Ok(());
	}

	#[test]
	fn read_id() {
		let out_path = fs::to_path_buf("tests/files/tpm2/read_id");
		let sig_path = fs::to_path_buf(
			"tests/files/tpm2/read_id/sig.bin");
		let id = super::read_id(&sig_path, &out_path).unwrap();
		let compare_id = super::message::CryptographicId {
			public_key: vec![7, 46, 24, 93, 146, 72, 214, 162],
			timestamp: 1687083430,
			msg: vec![87, 114, 105, 116, 101, 32, 109, 101, 32, 97,
			          110, 32, 101, 109, 97, 105, 108, 33],
			signature: vec![72, 83, 24, 92, 251, 82, 184, 83],
			public_key_type: super::PublicKeyType::Ed25519 as i32,
			personal_information: Vec::new(),
		};
		assert_eq!(id, compare_id);
	}
}
