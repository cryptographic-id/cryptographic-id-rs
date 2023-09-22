use std::io::Result;

fn main() -> Result<()> {
	prost_build::compile_protos(
		&["src/cryptographic-id-protocol/cryptographic_id.proto"],
		&["src/cryptographic-id-protocol/"],
	)?;
	return Ok(());
}
