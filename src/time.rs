use crate::error::DynError;
use std::time::SystemTime;

pub const SEC_TO_MILLIS: u64 = 1000;
pub const ONE_MINUTE_IN_MILLIS: u64 = 60 * SEC_TO_MILLIS;

pub fn now() -> Result<u64, DynError> {
	let s = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH)?;
	return Ok(s.as_millis().try_into()?);
}

#[cfg(test)]
mod tests {
	use std::{thread, time::Duration};

	#[test]
	fn now() -> Result<(), super::DynError> {
		let now1 = super::now()?;
		let now2 = super::now()?;
		let now3 = super::now()?;
		// Either the flip was before or after now2, not both
		assert!(now1 == now2 || now2 == now3);
		assert!(now1 <= now2 && now2 <= now3);
		assert!(1686503287000 < now1);
		thread::sleep(Duration::from_millis(1));
		assert!(now3 < super::now()?);
		return Ok(());
	}
}
