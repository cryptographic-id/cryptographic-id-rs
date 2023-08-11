use crate::error::DynError;
use crate::message;
use crate::message::CryptographicId;
use crate::time;
use crate::tpm2;

use std::{
	io,
	io::Write,
	ops::Range,
	sync::atomic::{AtomicBool, Ordering},
};

use qrcode_scanner::QRScanStream;

const MESSAGE_VALID: u64 = time::ONE_MINUTE_IN_MILLIS;

pub fn create_camera<'a>(path: String) -> Result<QRScanStream<'a>, DynError> {
	return Ok(qrcode_scanner::QRScanStream::new(path)?);
}

pub fn scan_id(
	qr_stream: &mut QRScanStream,
	stopper: &AtomicBool,
	mut gen_range: impl FnMut(Range<u64>) -> u64,
	output: &mut impl Write,
) -> Result<CryptographicId, DynError> {
	let mut exp_msg = "".to_string();
	let mut msg_timestamp = 0;
	let mut print = |msg: String| {
		output.write_all(msg.as_bytes())?;
		return Ok::<(), io::Error>(());
	};
	loop {
		if stopper.load(Ordering::Relaxed) {
			return Err("Scan aborted".into());
		}
		let now = time::now()?;
		if msg_timestamp + MESSAGE_VALID < now {
			msg_timestamp = now;
			let exp_num = gen_range(0..1000000);
			exp_msg = format!("{:0>6}", exp_num);
			print(format!("Send message: {}\n", exp_msg))?;
		}
		let results = match qr_stream.decode_next() {
			Ok(r) => r,
			Err(e) => {
				print(format!(
					"Failed to decode image: {}\n",
					e
				))?;
				continue;
			}
		};
		for res in results {
			let msg = match message::from_base64(res) {
				Ok(b) => b,
				Err(e) => {
					print(format!(
						"Failed to decode: \
							{:?}\n",
						e
					))?;
					continue;
				}
			};
			match message::verify_current_with_msg(&msg, &exp_msg) {
				Ok(()) => (),
				Err(s) => {
					print(format!("{}\n", s))?;
					continue;
				}
			};
			return Ok(msg);
		}
	}
}

pub fn scan_and_measure<'a>(
	qr_stream: &mut QRScanStream<'a>,
	tpm2_ctx: &mut tpm2::Context,
	pcr: tpm2::PcrHandle,
	stopper: &AtomicBool,
	mut gen_range: impl FnMut(Range<u64>) -> u64,
) -> Result<(), DynError> {
	let (hash, err) = match scan_id(
		qr_stream,
		stopper,
		&mut gen_range,
		&mut io::stdout(),
	) {
		Ok(msg) => match message::fingerprint(&msg) {
			Ok(f) => (f, Ok(())),
			// Error case should not happen, the signing key
			// is correct, since the signature was checked
			Err(e) => (vec![0xf0; 32], Err(e)),
		},
		Err(e) => {
			println!("Failed to scan id: {}", e);
			(vec![0xf0; 32], Err(e))
		}
	};
	tpm2::pcr_extend(tpm2_ctx, pcr, hash)?;
	// always meassure something in case of error
	err?;
	return Ok(());
}

#[cfg(test)]
mod tests {
	use crate::error::DynError;
	use crate::fs;
	use crate::message;
	use crate::sign::SigningConfig;
	use crate::time;
	use crate::tpm2;
	use qrcode_scanner::QRScanStream;
	use std::collections::VecDeque;
	use std::sync::atomic::{AtomicBool, Ordering};
	use std::{thread, time::Duration};
	use tss_esapi::structures::{Digest, PcrSlot};

	fn load_test_key() -> Result<SigningConfig, DynError> {
		let file = fs::to_path_buf("tests/files/scan/signing_key");
		return Ok(SigningConfig::load(&file)?);
	}

	fn example_msg() -> message::CryptographicId {
		let key_type = crate::PublicKeyType::Ed25519 as i32;
		return message::CryptographicId {
			public_key: vec![],
			timestamp: 0,
			msg: "Testmessage".as_bytes().to_vec(),
			public_key_type: key_type,
			signature: Vec::new(),
			personal_information: Vec::new(),
		};
	}

	#[test]
	#[ignore]
	fn scan_id() -> Result<(), DynError> {
		let mut key = load_test_key()?;
		let mut output: Vec<u8> = Vec::new();
		let mut msg = example_msg();
		let code1 = 444444;
		let code2 = 123456;
		let sleep = super::MESSAGE_VALID;
		let after_sleep = time::now()? + sleep;

		// correct code 2, when code 1
		msg.msg = code2.to_string().as_bytes().to_vec();
		msg.timestamp = after_sleep - 1;
		message::sign(&mut msg, &mut key)?;
		let res1 = message::to_base64(&msg)?;
		// message in the past
		msg.timestamp = after_sleep - super::MESSAGE_VALID - 1;
		msg.msg = code2.to_string().as_bytes().to_vec();
		message::sign(&mut msg, &mut key)?;
		let res2 = message::to_base64(&msg)?;
		// correct message
		msg.timestamp = after_sleep - 1;
		message::sign(&mut msg, &mut key)?;
		let res3 = message::to_base64(&msg)?;

		let data = VecDeque::from([
			Ok(vec![res1.clone(), "broken qrcode".to_string()]),
			Ok(vec![res1.clone(), res2.clone()]),
			Ok(vec![res2.clone(), res3.clone()]),
		]);
		let mut scanner = QRScanStream::with_test_results(data)?;
		let mut first_run = true;

		let result = super::scan_id(
			&mut scanner,
			&super::AtomicBool::new(false),
			|_| {
				if first_run {
					first_run = false;
					thread::sleep(Duration::from_millis(
						sleep + 1,
					));
					code1
				} else {
					code2
				}
			},
			&mut output,
		)?;
		assert_eq!(result, msg);
		assert_eq!(
			std::str::from_utf8(&output)?,
			"Send message: 444444\n\
			Wrong message, please share 444444\n\
			Failed to decode: Base64Error(InvalidLength)\n\
			Send message: 123456\n"
		);
		return Ok(());
	}

	static SCAN_ID_TEST_BOOL: AtomicBool = AtomicBool::new(false);

	#[test]
	fn scan_id_stopper() -> Result<(), DynError> {
		let mut output: Vec<u8> = Vec::new();
		let msg = example_msg();
		let res1 = message::to_base64(&msg)?;

		let data = VecDeque::from([
			Ok(vec![res1.clone()]),
			Ok(vec![res1.clone()]),
			Ok(vec![res1.clone()]),
		]);
		let mut scanner = QRScanStream::with_test_results(data)?;

		let result = super::scan_id(
			&mut scanner,
			&SCAN_ID_TEST_BOOL,
			|_| {
				SCAN_ID_TEST_BOOL
					.store(true, Ordering::Relaxed);
				987654
			},
			&mut output,
		);
		assert!(matches!(
			result,
			Err(e) if format!("{}", e) == "Scan aborted"));
		assert_eq!(
			std::str::from_utf8(&output)?,
			"Send message: 987654\n\
			Wrong message, please share 987654\n"
		);
		return Ok(());
	}

	#[test]
	fn scan_and_measure() -> Result<(), DynError> {
		let mut key = load_test_key()?;
		let mut msg = example_msg();
		let code = 765432;
		msg.msg = code.to_string().as_bytes().to_vec();
		msg.timestamp = time::now()?;
		message::sign(&mut msg, &mut key)?;
		let res = message::to_base64(&msg)?;

		let data = VecDeque::from([Ok(vec![res.clone()])]);
		let mut scanner = QRScanStream::with_test_results(data)?;
		let mut tpm2_ctx = tpm2::create_context()?;
		super::scan_and_measure(
			&mut scanner,
			&mut tpm2_ctx,
			super::tpm2::PcrHandle::Pcr8,
			&AtomicBool::new(false),
			|_| code,
		)?;
		let sha1 = Digest::try_from(vec![
			211, 76, 155, 19, 129, 231, 47, 147, 60, 85, 161, 27,
			224, 255, 120, 56, 136, 122, 161, 212,
		])?;
		let sha256 = Digest::try_from(vec![
			69, 118, 210, 215, 174, 24, 252, 210, 145, 250, 146,
			34, 123, 169, 90, 53, 251, 122, 191, 11, 29, 10, 50, 3,
			3, 57, 167, 67, 255, 241, 250, 51,
		])?;
		tpm2::tests::assert_pcr_bank(
			&mut tpm2_ctx,
			PcrSlot::Slot8,
			vec![sha1, sha256],
		)?;
		return Ok(());
	}

	#[test]
	fn scan_and_measure_error() -> Result<(), DynError> {
		let data = VecDeque::from([Ok(vec![])]);
		let mut scanner = QRScanStream::with_test_results(data)?;
		let mut tpm2_ctx = tpm2::create_context()?;
		let result = super::scan_and_measure(
			&mut scanner,
			&mut tpm2_ctx,
			super::tpm2::PcrHandle::Pcr9,
			&AtomicBool::new(true),
			|_| 555,
		);
		assert!(matches!(
			result,
			Err(e) if format!("{}", e) == "Scan aborted"));
		let sha1 = Digest::try_from(vec![
			55, 2, 26, 169, 90, 41, 122, 229, 93, 119, 203, 95,
			120, 25, 36, 2, 150, 209, 87, 179,
		])?;
		let sha256 = Digest::try_from(vec![
			69, 181, 67, 179, 102, 148, 197, 253, 15, 144, 223,
			198, 7, 191, 146, 161, 115, 87, 16, 48, 7, 86, 67, 251,
			31, 177, 224, 221, 19, 171, 117, 141,
		])?;
		tpm2::tests::assert_pcr_bank(
			&mut tpm2_ctx,
			PcrSlot::Slot9,
			vec![sha1, sha256],
		)?;
		return Ok(());
	}
}
