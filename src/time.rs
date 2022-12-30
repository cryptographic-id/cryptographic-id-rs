use std::time::SystemTime;

pub fn now() -> u64 {
	return match SystemTime::now().duration_since(SystemTime::UNIX_EPOCH) {
		Ok(k) => k.as_secs(),
		Err(_) => {
			panic!("SystemTime before UNIX EPOCH!");
		},
	};
}
