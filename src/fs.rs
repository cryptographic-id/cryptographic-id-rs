use std::io;
use std::path::Path;
use std::path::PathBuf;
use std::fs::File;
use std::io::BufReader;
use std::io::Read;
use std::io::Write;

pub fn to_path_buf(s: &str) -> PathBuf {
	return Path::new(s).to_path_buf();
}

pub fn write_file(data: &Vec<u8>, filename: &PathBuf) -> io::Result<()> {
	let mut f = File::create(filename)?;
	f.write_all(&data)?;
	return Ok(());
}

pub fn read_file(filename: &PathBuf) -> io::Result<Vec<u8>> {
	let f = File::open(filename)?;
	let mut reader = BufReader::new(f);
	let mut buffer = Vec::new();
	reader.read_to_end(&mut buffer)?;
	return Ok(buffer);
}

#[cfg(test)]
mod tests {
	use std::path::Path;
	use crate::fs::io::ErrorKind;
	use tempfile;

	#[test]
	fn to_path_buf() {
		assert_eq!(
			super::to_path_buf("/my/dir/file"),
			Path::new("/my/dir/file").to_path_buf());
	}

	#[test]
	fn read_file() {
		let path = super::to_path_buf("tests/files/read_file");
		let res = super::read_file(&path).unwrap();
		assert_eq!(res, b"Just a\ntest\nfile\n");
	}

	#[test]
	fn read_file_inexistent() {
		let path = super::to_path_buf("/tmp/inexistent/read_file");
		let res = super::read_file(&path);
		let error = res.unwrap_err().kind();
		assert_eq!(error, ErrorKind::NotFound);
	}

	#[test]
	fn write_file() {
		let tmpdir = tempfile::tempdir().unwrap();
		let file_path = tmpdir.path().join("write_test");
		let val = vec![93, 61, 93, 233, 92, 71, 20];
		super::write_file(&val, &file_path).unwrap();
		assert_eq!(super::read_file(&file_path).unwrap(), val);
	}

	#[test]
	fn write_file_inexistent() {
		let path = Path::new("/tmp/inexistent/read_file").to_path_buf();
		let val = vec![93];
		let res = super::write_file(&val, &path);
		let error = res.unwrap_err().kind();
		assert_eq!(error, ErrorKind::NotFound);
	}
}
