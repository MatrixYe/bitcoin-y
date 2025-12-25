use bitcoin_y::errors::KeyPairError;
use bitcoin_y::key::{KeyPair, sign, verify};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keypair_creation() {
        let keypair = KeyPair::new();
        let secret_bytes = keypair.secret_key.secret_bytes();
        assert!(!secret_bytes.iter().all(|&x| x == 0));
    }

    #[test]
    fn test_keypair_from_secret() {
        let keypair1 = KeyPair::new();
        let keypair2: KeyPair = keypair1.secret_key.into();
        assert_eq!(keypair1.public_key, keypair2.public_key);
    }

    #[test]
    fn test_sign_and_verify() {
        let keypair = KeyPair::new();
        let message = b"Hello, world!";
        let signature = sign(&keypair, message);
        assert!(verify(message, &keypair.public_key, &signature));
    }

    #[test]
    fn test_verify_invalid_signature() {
        let keypair1 = KeyPair::new();
        let keypair2 = KeyPair::new();
        let message = b"Hello, world!";
        let signature = sign(&keypair1, message);
        assert!(!verify(message, &keypair2.public_key, &signature));
    }

    #[test]
    fn test_verify_modified_message() {
        let keypair = KeyPair::new();
        let message = b"Hello, world!";
        let signature = sign(&keypair, message);
        assert!(!verify(
            b"Modified message",
            &keypair.public_key,
            &signature
        ));
    }

    #[test]
    fn test_get_public_key() {
        let keypair = KeyPair::new();
        let public_key = {
            let this = &keypair;
            hex::encode(this.public_key.serialize())
        };
        println!("{:?}", public_key);
        println!("{:?}", public_key.len());
    }

    #[test]
    fn test_get_secret_key() {
        let keypair = KeyPair::new();
        let secret_key = keypair.get_secret_key();
        println!("{:?}", secret_key);
        println!("{:?}", secret_key.len());
        assert_eq!(secret_key.len(), 64);
    }

    #[test]
    fn test_temp() {
        let keypair = KeyPair::new();
        let secret_key = keypair.get_secret_key();
        let public_key = {
            let this = &keypair;
            hex::encode(this.public_key.serialize())
        };
        println!("secret_key:{:?}", secret_key);
        println!("public_key:{:?}", public_key);

        let sig = sign(&keypair, b"Hello,world!");
        let ok: bool = verify(b"Hello,world!", &keypair.public_key, &sig);
        assert!(ok);
        println!("sig: {:?}", hex::encode(sig.serialize_compact()));
        println!("ok: {:?}", ok);
    }

    #[test]
    fn test_sk2pk() {
        let keypair: KeyPair = "72242708cbb6ee199d03e06aa7e419c0247618844da0ef1a587f7f145eb1c7ba"
            .try_into()
            .unwrap();

        let secret_key = keypair.get_secret_key();
        let public_key = {
            let this = &keypair;
            hex::encode(this.public_key.serialize())
        };
        println!("secret_key:{:?}", secret_key);
        println!("public_key:{:?}", public_key);
        assert_eq!(
            secret_key,
            "72242708cbb6ee199d03e06aa7e419c0247618844da0ef1a587f7f145eb1c7ba"
        );
        assert_eq!(
            public_key,
            "03de5983f0ef2eb9e4af1268b826b900bdd672c251d5af7523dcd10b6eac5d5e57"
        );

        let sig = sign(&keypair, b"Hello, world!");
        let ok = verify(b"Hello, world!", &keypair.public_key, &sig);
        println!("ok: {:?}", ok);
    }

    #[test]
    fn test_bitcoin_address_generation() {
        let keypair: KeyPair = "72242708cbb6ee199d03e06aa7e419c0247618844da0ef1a587f7f145eb1c7ba"
            .try_into()
            .unwrap();

        let address = keypair.to_address();

        println!("Bitcoin Address: {}", address);
        assert_eq!(address, "1G1fWxQ6sMiKhSk3eoWwQijTMahjzcS1xG".to_string());

        assert!(address.as_str().starts_with("1"));
        assert!(address.len() >= 26 && address.len() <= 35);
    }

    #[test]
    fn test_try_from_invalid_hex_length() {
        let result: Result<KeyPair, KeyPairError> = "invalid".try_into();
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), KeyPairError::InvalidHexLength(7));
    }

    #[test]
    fn test_try_from_invalid_secret_key() {
        let result: Result<KeyPair, KeyPairError> =
            "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff".try_into();
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), KeyPairError::InvalidSecretKey);
    }

    #[test]
    fn test_try_from_valid_hex() {
        let keypair: KeyPair = "72242708cbb6ee199d03e06aa7e419c0247618844da0ef1a587f7f145eb1c7ba"
            .try_into()
            .unwrap();
        assert_eq!(
            keypair.get_secret_key(),
            "72242708cbb6ee199d03e06aa7e419c0247618844da0ef1a587f7f145eb1c7ba"
        );
    }

    #[test]
    fn test_try_from_string() {
        let hex_string =
            String::from("72242708cbb6ee199d03e06aa7e419c0247618844da0ef1a587f7f145eb1c7ba");
        let keypair: KeyPair = hex_string.try_into().unwrap();
        assert_eq!(
            keypair.get_secret_key(),
            "72242708cbb6ee199d03e06aa7e419c0247618844da0ef1a587f7f145eb1c7ba"
        );
    }

    #[test]
    fn test_try_from_byte_array() {
        let bytes: [u8; 32] = [
            0x72, 0x24, 0x27, 0x08, 0xcb, 0xb6, 0xee, 0x19, 0x9d, 0x03, 0xe0, 0x6a, 0xa7, 0xe4,
            0x19, 0xc0, 0x24, 0x76, 0x18, 0x84, 0x4d, 0xa0, 0xef, 0x1a, 0x58, 0x7f, 0x7f, 0x14,
            0x5e, 0xb1, 0xc7, 0xba,
        ];
        let keypair: KeyPair = bytes.try_into().unwrap();
        assert_eq!(
            keypair.get_secret_key(),
            "72242708cbb6ee199d03e06aa7e419c0247618844da0ef1a587f7f145eb1c7ba"
        );
    }

    #[test]
    fn test_try_from_invalid_byte_array() {
        let bytes: [u8; 32] = [0xff; 32];
        let result: Result<KeyPair, KeyPairError> = bytes.try_into();
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), KeyPairError::InvalidSecretKey);
    }
}
