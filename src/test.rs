
use super::*;
use bip32::ExtendedPrivKey;
use bip39::{Language, Mnemonic, Seed};
use bip44::{ChildNumber, DerivationPath, HARDENED_BIT};
use hex_literal::hex;
use no_std_compat::str::FromStr;

#[test]
fn bip39_to_address() {
    let phrase = "panda eyebrow bullet gorilla call smoke muffin taste mesh discover soft ostrich alcohol speed nation flash devote level hobby quick inner drive ghost inside";

    let expected_secret_key = b"\xff\x1e\x68\xeb\x7b\xf2\xf4\x86\x51\xc4\x7e\xf0\x17\x7e\xb8\x15\x85\x73\x22\x25\x7c\x58\x94\xbb\x4c\xfd\x11\x76\xc9\x98\x93\x14";

    let mnemonic = Mnemonic::from_phrase(phrase, Language::English).unwrap();
    let seed = Seed::new(&mnemonic, "");

    let account = ExtendedPrivKey::derive(seed.as_bytes(), "m/44'/60'/0'/0/0").unwrap();

    assert_eq!(
        expected_secret_key,
        &account.secret(),
        "Secret key is invalid"
    );

    // // Test child method
    let account = ExtendedPrivKey::derive(seed.as_bytes(), "m/44'/60'/0'/0")
        .unwrap()
        .child(ChildNumber::from_str("0").unwrap())
        .unwrap();

    assert_eq!(
        expected_secret_key,
        &account.secret(),
        "Secret key is invalid"
    );
}

#[test]
fn derive_path() {
    let path: DerivationPath = "m/44'/60'/0'/0".parse().unwrap();

    assert_eq!(
        path,
        DerivationPath {
            path: vec![
                ChildNumber(44 | HARDENED_BIT),
                ChildNumber(60 | HARDENED_BIT),
                ChildNumber(0 | HARDENED_BIT),
                ChildNumber(0),
            ],
        }
    );
}

#[test]
fn bip32_test_vec_1() {
    let seed: Vec<u8> = hex!["000102030405060708090a0b0c0d0e0f"].into();
    
    // path: "m"
    let priv_key = "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi";
    let account = ExtendedPrivKey::derive(seed.as_ref(), "m").unwrap();
    let des_account = ExtendedPrivKey::from_str(priv_key).unwrap();
    assert_eq!(account, des_account, "error in deriving m");

    // path: "m/0'"
    let priv_key = "xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL5hj6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7";
    let account = ExtendedPrivKey::derive(seed.as_ref(), "m/0'").unwrap();
    let des_account = ExtendedPrivKey::from_str(priv_key).unwrap();
    assert_eq!(account, des_account, "error in deriving m/0'");

    let account = ExtendedPrivKey::derive(seed.as_ref(), "m/0").unwrap();
    assert_ne!(account, des_account, "error in derive m/0'");

    // path: "m/0'/1"
    let priv_key = "xprv9wTYmMFdV23N2TdNG573QoEsfRrWKQgWeibmLntzniatZvR9BmLnvSxqu53Kw1UmYPxLgboyZQaXwTCg8MSY3H2EU4pWcQDnRnrVA1xe8fs";
    let account = ExtendedPrivKey::derive(seed.as_ref(), "m/0'/1").unwrap();
    let des_account = ExtendedPrivKey::from_str(priv_key).unwrap();
    assert_eq!(account, des_account, "error in deriving m/0'/1");

    // path: "m/0'/1/2'"
    let priv_key = "xprv9z4pot5VBttmtdRTWfWQmoH1taj2axGVzFqSb8C9xaxKymcFzXBDptWmT7FwuEzG3ryjH4ktypQSAewRiNMjANTtpgP4mLTj34bhnZX7UiM";
    let account = ExtendedPrivKey::derive(seed.as_ref(), "m/0'/1/2'").unwrap();
    let des_account = ExtendedPrivKey::from_str(priv_key).unwrap();
    assert_eq!(account, des_account, "error in deriving m/0'/1/2'");
    
    // path: "m/0'/1/2'/2"
    let priv_key = "xprvA2JDeKCSNNZky6uBCviVfJSKyQ1mDYahRjijr5idH2WwLsEd4Hsb2Tyh8RfQMuPh7f7RtyzTtdrbdqqsunu5Mm3wDvUAKRHSC34sJ7in334";
    let account = ExtendedPrivKey::derive(seed.as_ref(), "m/0'/1/2'/2").unwrap();
    let des_account = ExtendedPrivKey::from_str(priv_key).unwrap();
    assert_eq!(account, des_account, "error in deriving m/0'/1/2'/2");

    // path: "m/0'/1/2'/2/1000000000"
    let priv_key = "xprvA41z7zogVVwxVSgdKUHDy1SKmdb533PjDz7J6N6mV6uS3ze1ai8FHa8kmHScGpWmj4WggLyQjgPie1rFSruoUihUZREPSL39UNdE3BBDu76";
    let account = ExtendedPrivKey::derive(seed.as_ref(), "m/0'/1/2'/2/1000000000").unwrap();
    let des_account = ExtendedPrivKey::from_str(priv_key).unwrap();
    assert_eq!(account, des_account, "error in deriving m/0'/1/2'/2/1000000000");
}

#[test]
fn bip_test_vec_2(){
    let seed: Vec<u8> = hex!["fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542"].into();
    
    // path: "m"
    let priv_key = "xprv9s21ZrQH143K31xYSDQpPDxsXRTUcvj2iNHm5NUtrGiGG5e2DtALGdso3pGz6ssrdK4PFmM8NSpSBHNqPqm55Qn3LqFtT2emdEXVYsCzC2U";
    let account = ExtendedPrivKey::derive(seed.as_ref(), "m").unwrap();
    let des_account = ExtendedPrivKey::from_str(priv_key).unwrap();
    assert_eq!(account, des_account, "error in deriving m");

    // path: "m/0'"
    let priv_key = "xprv9vHkqa6EV4sPZHYqZznhT2NPtPCjKuDKGY38FBWLvgaDx45zo9WQRUT3dKYnjwih2yJD9mkrocEZXo1ex8G81dwSM1fwqWpWkeS3v86pgKt";
    let account = ExtendedPrivKey::derive(seed.as_ref(), "m/0").unwrap();
    let des_account = ExtendedPrivKey::from_str(priv_key).unwrap();
    assert_eq!(account, des_account, "error in deriving m/0");

    let account = ExtendedPrivKey::derive(seed.as_ref(), "m/0'").unwrap();
    assert_ne!(account, des_account, "error in derive m/0'");

    // path: "m/0/2147483647'"
    let priv_key = "xprv9wSp6B7kry3Vj9m1zSnLvN3xH8RdsPP1Mh7fAaR7aRLcQMKTR2vidYEeEg2mUCTAwCd6vnxVrcjfy2kRgVsFawNzmjuHc2YmYRmagcEPdU9";
    let account = ExtendedPrivKey::derive(seed.as_ref(), "m/0/2147483647'").unwrap();
    let des_account = ExtendedPrivKey::from_str(priv_key).unwrap();
    assert_eq!(account, des_account, "error in deriving m/0/2147483647'");

    // path: "m/0/2147483647'/1"
    let priv_key = "xprv9zFnWC6h2cLgpmSA46vutJzBcfJ8yaJGg8cX1e5StJh45BBciYTRXSd25UEPVuesF9yog62tGAQtHjXajPPdbRCHuWS6T8XA2ECKADdw4Ef";
    let account = ExtendedPrivKey::derive(seed.as_ref(), "m/0/2147483647'/1").unwrap();
    let des_account = ExtendedPrivKey::from_str(priv_key).unwrap();
    assert_eq!(account, des_account, "error in deriving m/0/2147483647'/1");
    
    // path: "m/0/2147483647'/1/2147483646'"
    let priv_key = "xprvA1RpRA33e1JQ7ifknakTFpgNXPmW2YvmhqLQYMmrj4xJXXWYpDPS3xz7iAxn8L39njGVyuoseXzU6rcxFLJ8HFsTjSyQbLYnMpCqE2VbFWc";
    let account = ExtendedPrivKey::derive(seed.as_ref(), "m/0/2147483647'/1/2147483646'").unwrap();
    let des_account = ExtendedPrivKey::from_str(priv_key).unwrap();
    assert_eq!(account, des_account, "error in deriving m/0/2147483647'/1/2147483646'");

    // path: "m/0/2147483647'/1/2147483646'/2"
    let priv_key = "xprvA2nrNbFZABcdryreWet9Ea4LvTJcGsqrMzxHx98MMrotbir7yrKCEXw7nadnHM8Dq38EGfSh6dqA9QWTyefMLEcBYJUuekgW4BYPJcr9E7j";
    let account = ExtendedPrivKey::derive(seed.as_ref(), "m/0/2147483647'/1/2147483646'/2").unwrap();
    let des_account = ExtendedPrivKey::from_str(priv_key).unwrap();
    assert_eq!(account, des_account, "error in deriving m/0/2147483647'/1/2147483646'/2");
}

#[test]
fn bip32_test_vec_3() {
    let seed: Vec<u8> = hex!["4b381541583be4423346c643850da4b320e46a87ae3d2a4e6da11eba819cd4acba45d239319ac14f863b8d5ab5a0d0c64d2e8a1e7d1457df2e5a3c51c73235be"].into();
    
    // path: "m"
    let priv_key = "xprv9s21ZrQH143K25QhxbucbDDuQ4naNntJRi4KUfWT7xo4EKsHt2QJDu7KXp1A3u7Bi1j8ph3EGsZ9Xvz9dGuVrtHHs7pXeTzjuxBrCmmhgC6";
    let account = ExtendedPrivKey::derive(seed.as_ref(), "m").unwrap();
    let des_account = ExtendedPrivKey::from_str(priv_key).unwrap();
    assert_eq!(account, des_account, "error in deriving m");

    // path: "m/0'"
    let priv_key = "xprv9uPDJpEQgRQfDcW7BkF7eTya6RPxXeJCqCJGHuCJ4GiRVLzkTXBAJMu2qaMWPrS7AANYqdq6vcBcBUdJCVVFceUvJFjaPdGZ2y9WACViL4L";
    let account = ExtendedPrivKey::derive(seed.as_ref(), "m/0'").unwrap();
    let des_account = ExtendedPrivKey::from_str(priv_key).unwrap();
    assert_eq!(account, des_account, "error in deriving m/0'");

    let account = ExtendedPrivKey::derive(seed.as_ref(), "m/0").unwrap();
    assert_ne!(account, des_account, "error in derive m/0");
}

#[test]

fn bip32_test_vec_4() {
    let seed: Vec<u8> = hex!["3ddd5602285899a946114506157c7997e5444528f3003f6134712147db19b678"].into();
    
    // path: "m"
    let priv_key = "xprv9s21ZrQH143K48vGoLGRPxgo2JNkJ3J3fqkirQC2zVdk5Dgd5w14S7fRDyHH4dWNHUgkvsvNDCkvAwcSHNAQwhwgNMgZhLtQC63zxwhQmRv";
    let account = ExtendedPrivKey::derive(seed.as_ref(), "m").unwrap();
    let des_account = ExtendedPrivKey::from_str(priv_key).unwrap();
    assert_eq!(account, des_account, "error in deriving m");

    // path: "m/0'"
    let priv_key = "xprv9vB7xEWwNp9kh1wQRfCCQMnZUEG21LpbR9NPCNN1dwhiZkjjeGRnaALmPXCX7SgjFTiCTT6bXes17boXtjq3xLpcDjzEuGLQBM5ohqkao9G";
    let account = ExtendedPrivKey::derive(seed.as_ref(), "m/0'").unwrap();
    let des_account = ExtendedPrivKey::from_str(priv_key).unwrap();
    assert_eq!(account, des_account, "error in deriving m/0'");

    let account = ExtendedPrivKey::derive(seed.as_ref(), "m/0").unwrap();
    assert_ne!(account, des_account, "error in derive m/0'");

    // path: "m/0'/1'"
    let priv_key = "xprv9xJocDuwtYCMNAo3Zw76WENQeAS6WGXQ55RCy7tDJ8oALr4FWkuVoHJeHVAcAqiZLE7Je3vZJHxspZdFHfnBEjHqU5hG1Jaj32dVoS6XLT1";
    let account = ExtendedPrivKey::derive(seed.as_ref(), "m/0'/1'").unwrap();
    let des_account = ExtendedPrivKey::from_str(priv_key).unwrap();
    assert_eq!(account, des_account, "error in deriving m/0'/1'");
}