use libsecp256k1::{SecretKey, PublicKey};
use base58::FromBase58;
use sha2::Sha512;
use hmac::{Hmac, Mac, NewMac};
use memzero::Memzero;
use no_std_compat::ops::Deref;
use no_std_compat::str::FromStr;
use no_std_compat::fmt;

use crate::bip44::{ChildNumber, IntoDerivationPath};
use crate::Error;

type HmacSha512 = Hmac<Sha512>;

#[derive(Clone, PartialEq, Eq)]
pub struct Protected(Memzero<[u8; 32]>);

impl<Data: AsRef<[u8]>> From<Data> for Protected {
    fn from(data: Data) -> Protected {
        let mut buf = [0u8; 32];

        buf.copy_from_slice(data.as_ref());

        Protected(Memzero::from(buf))
    }
}

impl Deref for Protected {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl fmt::Debug for Protected {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Protected")
    }
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ExtendedPrivKey {
    secret_key: SecretKey,
    chain_code: Protected,
}

impl ExtendedPrivKey {
    /// Attempts to derive an extended private key from a path.
    pub fn derive<Path>(seed: &[u8], path: Path) -> Result<ExtendedPrivKey, Error>
    where
        Path: IntoDerivationPath,
    {
        let mut hmac: Hmac<Sha512> = HmacSha512::new_from_slice(b"Bitcoin seed").expect("seed is always correct; qed");
        hmac.update(seed);

        let result = hmac.finalize().into_bytes();
        let (secret_key, chain_code) = result.split_at(32);

        let mut sk = ExtendedPrivKey {
            secret_key: SecretKey::parse_slice(secret_key).map_err(Error::Secp256k1)?,
            chain_code: Protected::from(chain_code),
        };

        for child in path.into()?.as_ref() {
            sk = sk.child(*child)?;
        }

        Ok(sk)
    }

    pub fn secret(&self) -> [u8; 32] {
        self.secret_key.serialize()
    }

    pub fn child(&self, child: ChildNumber) -> Result<ExtendedPrivKey, Error> {
        let mut hmac: Hmac<Sha512> = HmacSha512::new_from_slice(&self.chain_code)
            .map_err(|_| Error::InvalidChildNumber)?;

        if child.is_normal() {
            hmac.update(&PublicKey::from_secret_key(&self.secret_key).serialize_compressed()[..]);
        } else {
            hmac.update(&[0]);
            hmac.update(&self.secret_key.serialize()[..]);
        }

        hmac.update(&child.to_bytes());

        let result = hmac.finalize().into_bytes();
        let (secret_key, chain_code) = result.split_at(32);

        let mut secret_key = SecretKey::parse_slice(&secret_key).map_err(Error::Secp256k1)?;
        secret_key.tweak_add_assign(&self.secret_key).map_err(Error::Secp256k1)?;

        Ok(ExtendedPrivKey {
            secret_key,
            chain_code: Protected::from(&chain_code)
        })
    }
}

impl FromStr for ExtendedPrivKey {
    type Err = Error;

    fn from_str(xprv: &str) -> Result<ExtendedPrivKey, Error> {
        let data = xprv.from_base58().map_err(|_| Error::InvalidExtendedPrivKey)?;

        if data.len() != 82 {
            return Err(Error::InvalidExtendedPrivKey);
        }

        Ok(ExtendedPrivKey {
            chain_code: Protected::from(&data[13..45]),
            secret_key: SecretKey::parse_slice(&data[46..78]).map_err(|e| Error::Secp256k1(e))?
        })
    }
}
