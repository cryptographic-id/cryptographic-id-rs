use qrcode::types::QrError;
use qrcode::QrCode;

pub fn as_string(msg: &String) -> Result<String, QrError> {
	let code = QrCode::new(&msg)?;
	let string = code
		.render::<char>()
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
		let data = "PQxTF0g9Fz0HCQE=".to_string();
		let s = super::as_string(&data).unwrap();
		assert_eq!(
			s.as_bytes().to_vec(),
			fs::read_file(&fs::to_path_buf(
				"tests/files/qrcode/as_string"
			))
			.unwrap()
		);
	}
}
