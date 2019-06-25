# tiny-hderive

A library for deriving secp256k1 secret keys from [**BIP39**](https://crates.io/crates/bip39) seeds, using **BIP32** crypto and **BIP44** path formats.

```rust
use tiny_hderive::bip32::ExtendedPrivKey;

// Seed should be generated from your BIP39 phrase first!
let seed: &[u8] = &[42; 64];
let ext = ExtendedPrivKey::derive(seed, "m/44'/60'/0'/0/0").unwrap();

// Byte array of the secp256k1 secret key that can be used with Bitcoin or Ethereum.
assert_eq!(&ext.secret(), b"\x98\x84\xbf\x56\x24\xfa\xdd\x7f\xb2\x80\x4c\xfb\x0c\xb6\xf7\x1f\x28\x9e\x21\x1f\xcf\x0d\xe8\x36\xa3\x84\x17\x57\xda\xd9\x70\xd0");

// Deriving child keys from base one is also possible
use tiny_hderive::bip44::ChildNumber;
use std::str::FromStr;

let base_ext = ExtendedPrivKey::derive(seed, "m/44'/60'/0'/0").unwrap();
// child_ext is a key which is derived from this path: m/44'/60'/0'/0/0
let child_ext = base_ext.child(ChildNumber::from_str("0").unwrap()).unwrap();

assert_eq!(ext, child_ext);
```
