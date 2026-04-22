use bitcoin_y::block::BlockHeader;
use bitcoin_y::hash::{Hash256, block_hash, hash160, merkle_root, sha256, sha256d, txid};
use bitcoin_y::tx::{OutPoint, Transaction, TxIn, TxOut};
use bitcoin_y::utils::ripemd160;

fn genesis_coinbase_transaction() -> Transaction {
    Transaction {
        version: 1,
        vin: vec![TxIn {
            prevout: OutPoint::null(),
            script_sig: hex::decode(
                "04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73",
            )
            .unwrap(),
            sequence: u32::MAX,
        }],
        vout: vec![TxOut {
            value: 5_000_000_000,
            script_pubkey: hex::decode(
                "4104678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5fac",
            )
            .unwrap(),
        }],
        lock_time: 0,
    }
}

#[test]
fn sha256_matches_known_vector() {
    let result = sha256(b"abc");
    let expected = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
    assert_eq!(hex::encode(result), expected);
}

#[test]
fn ripemd160_matches_known_vector() {
    let result = ripemd160(b"abc");
    let expected = "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc";
    assert_eq!(hex::encode(result), expected);
}

#[test]
fn hash160_matches_known_vector() {
    let result = hash160(b"abc");
    let expected = "bb1be98c142444d7a56aa3981c3942a978e4dc33";
    assert_eq!(hex::encode(result), expected);
}

#[test]
fn sha256d_matches_known_vector() {
    let result = sha256d(b"abc");
    let expected = "4f8b42c22dd3729b519ba6f68d2da7cc5b2d606d05daed5ad5128cc03e6c6358";
    assert_eq!(hex::encode(result.0), expected);
}

#[test]
fn hash256_display_hex_roundtrip() {
    let display = "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f";
    let hash = Hash256::from_display_hex(display).unwrap();
    assert_eq!(hash.to_display_hex(), display);
    assert_eq!(hash.to_string(), display);
}

#[test]
fn genesis_coinbase_txid_matches_reference() {
    let tx = genesis_coinbase_transaction();
    let expected = "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b";
    assert_eq!(txid(&tx).to_display_hex(), expected);
    assert_eq!(
        merkle_root(std::slice::from_ref(&tx)).to_display_hex(),
        expected
    );
}

#[test]
fn genesis_block_hash_matches_reference() {
    let header = BlockHeader {
        version: 1,
        prev_block: Hash256::zero(),
        merkle_root: Hash256::from_display_hex(
            "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b",
        )
        .unwrap(),
        time: 1231006505,
        bits: 0x1d00ffff,
        nonce: 2083236893,
    };

    let expected = "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f";
    assert_eq!(block_hash(&header).to_display_hex(), expected);
}
