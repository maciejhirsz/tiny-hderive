pub mod bip44;
pub mod bip32;

#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Error {
    Secp256k1(secp256k1::Error),
    InvalidChildNumber,
    InvalidDerivationPath,
    InvalidExtendedPrivKey,
}
