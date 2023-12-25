pub fn bytes_to_hex(bytes_vec: &Vec<u8>) -> String {
	return bytes_vec
		.iter()
		.map(|b| format!("{:02x}", b).to_uppercase())
		.collect::<Vec<String>>()
		.join(":");
}

pub fn flatten_binary_vec(vec: &Vec<Vec<u8>>) -> Vec<u8> {
	return vec.iter().flat_map(|v| v.iter().copied()).collect();
}

pub fn fingerprint_to_hex(bytes: &Vec<u8>) -> String {
	let hex = bytes_to_hex(bytes);
	if hex.len() != 95 {
		return hex;
	}
	return vec![
		hex[0..23].to_string(),
		hex[24..47].to_string(),
		hex[48..71].to_string(),
		hex[72..95].to_string(),
	]
	.join("\n");
}

#[cfg(test)]
mod tests {
	#[test]
	fn bytes_to_hex() {
		let res = super::bytes_to_hex(&vec![
			2, 6, 19, 78, 46, 7, 41, 221, 11,
		]);
		assert_eq!(res, "02:06:13:4E:2E:07:29:DD:0B");
	}

	#[test]
	fn flatten_binary_vec() {
		let flat = super::flatten_binary_vec(&vec![
			vec![2, 6, 19],
			vec![78, 46, 7, 41],
			vec![],
			vec![221, 11],
		]);
		assert_eq!(flat, vec![2, 6, 19, 78, 46, 7, 41, 221, 11]);
	}

	#[test]
	fn fingerprint_to_hex() {
		let bytes = vec![
			11, 45, 192, 121, 75, 216, 66, 161, 194, 65, 46, 224,
			202, 78, 123, 254, 118, 250, 181, 249, 84, 175, 77,
			202, 182, 149, 196, 114, 76, 188, 183, 1,
		];
		assert_eq!(
			super::fingerprint_to_hex(&bytes),
			"0B:2D:C0:79:4B:D8:42:A1\n\
			C2:41:2E:E0:CA:4E:7B:FE\n\
			76:FA:B5:F9:54:AF:4D:CA\n\
			B6:95:C4:72:4C:BC:B7:01"
		);
	}
}
