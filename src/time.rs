use std::time::SystemTime;

pub fn now() -> u64 {
	return match SystemTime::now().duration_since(SystemTime::UNIX_EPOCH) {
		Ok(k) => k.as_secs(),
		Err(_) => {
			panic!("SystemTime before UNIX EPOCH!");
		}
	};
}

#[cfg(test)]
mod tests {
	use std::{thread, time::Duration};

	#[test]
	fn now() {
		let now1 = super::now();
		let now2 = super::now();
		let now3 = super::now();
		// Either the second flip was before or after now2, not both
		assert!(now1 == now2 || now2 == now3);
		assert!(now1 <= now2 && now2 <= now3);
		assert!(1686503287 < now1);
		thread::sleep(Duration::from_secs(1));
		assert!(now3 < super::now());
	}
}
