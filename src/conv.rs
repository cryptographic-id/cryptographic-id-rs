pub fn bytes_to_hex(bytes_vec: Vec<u8>) -> String {
	return bytes_vec.iter().map(
		|b| format!("{:02x}", b).to_uppercase()
	).collect::<Vec<String>>().join(":");
}

pub fn flatten_binary_vec(vec: &Vec<Vec<u8>>) -> Vec<u8> {
	return vec.iter().flat_map(
		|v| v.iter().copied()).collect();
}

#[cfg(test)]
mod tests {
	#[test]
	fn bytes_to_hex() {
		let res = super::bytes_to_hex(
			vec![2, 6, 19, 78, 46, 7, 41, 221, 11]);
		assert_eq!(res, "02:06:13:4E:2E:07:29:DD:0B");
	}

	#[test]
	fn flatten_binary_vec() {
		let flat = super::flatten_binary_vec(&vec![
			vec![2, 6, 19],
			vec![78, 46, 7, 41],
			vec![],
			vec![221, 11]]);
		assert_eq!(flat, vec![2, 6, 19, 78, 46, 7, 41, 221, 11]);
	}
}
