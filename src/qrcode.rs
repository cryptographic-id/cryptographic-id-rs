use base64;
use base64::Engine as _;
use qrcode::QrCode;
use qrcode::types::QrError;

pub fn as_string(buf: &Vec<u8>) -> Result<String, QrError> {
	let msg: String = base64::engine::general_purpose::STANDARD.encode(
		&buf);
	let code = QrCode::new(&msg)?;
	let string = code.render::<char>()
		.quiet_zone(false)
		.module_dimensions(2, 1)
		.build();
	return Ok(string);
}

#[cfg(test)]
mod tests {
	use crate::fs;

	#[test]
	fn as_string() {
		let data = vec![61, 12, 83, 23, 72, 61, 23, 61, 7, 9, 1];
		let s = super::as_string(&data).unwrap();
		assert_eq!(
			s.as_bytes().to_vec(),
			fs::read_file(&fs::to_path_buf(
				"tests/files/qrcode/as_string")).unwrap());
	}
}
