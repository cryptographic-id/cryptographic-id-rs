pub fn bytes_to_hex(bytes_vec: Vec<u8>) -> String {
	return bytes_vec.iter().map(
		|b| format!("{:02x}", b).to_uppercase()
	).collect::<Vec<String>>().join(":");
}

pub fn flatten_binary_vec(vec: &Vec<Vec<u8>>) -> Vec<u8> {
	return vec.iter().flat_map(
		|v| v.iter().copied()).collect();
}
