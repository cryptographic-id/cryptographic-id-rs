use crate::scan;
use crate::tpm2;
use rand;
use rand::Rng;
use std::sync::atomic::AtomicBool;

pub fn tpm2_scan_and_measure(
	cam_path: String,
	pcr_str: String,
	stopper: &AtomicBool,
) -> i32 {
	let pcr = match tpm2::str_to_pcrhandle(&pcr_str) {
		Ok(p) => p,
		Err(e) => {
			println!("Failed to parse pcr {}: {}", pcr_str, e);
			return -3;
		}
	};
	let mut camera = match scan::create_camera(cam_path) {
		Ok(c) => c,
		Err(e) => {
			println!("{}", e);
			return -1;
		}
	};
	let mut context = match tpm2::create_context() {
		Ok(c) => c,
		Err(e) => {
			println!("Failed to open tpm2: {}", e);
			return -1;
		}
	};
	match scan::scan_and_measure(
		&mut camera,
		&mut context,
		pcr,
		stopper,
		|x| rand::thread_rng().gen_range(x),
	) {
		Ok(_) => return 0,
		Err(e) => {
			println!("Failed to scan and measure: {}", e);
			return -4;
		}
	};
}
