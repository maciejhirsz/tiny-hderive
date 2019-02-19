#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Error {
    Secp256k1(secp256k1::Error),
    InvalidDerivationPath,
}

impl From<std::num::ParseIntError> for Error {
	fn from(err: std::num::ParseIntError) -> Error {
		Error:
	}
}