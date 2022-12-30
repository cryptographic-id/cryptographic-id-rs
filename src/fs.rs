use std::io;
use std::path::PathBuf;
use std::fs::File;
use std::io::BufReader;
use std::io::Read;
use std::io::Write;

pub fn write_file(data: Vec<u8>, filename: PathBuf) -> io::Result<()> {
	let mut f = File::create(filename)?;
	f.write_all(&data)?;
	return Ok(());
}

pub fn read_file(filename: PathBuf) -> io::Result<Vec<u8>> {
	let f = File::open(filename)?;
	let mut reader = BufReader::new(f);
	let mut buffer = Vec::new();
	reader.read_to_end(&mut buffer)?;
	return Ok(buffer);
}
