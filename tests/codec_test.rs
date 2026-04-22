use bitcoin_y::block::{Block, BlockHeader};
use bitcoin_y::codec::{
    deserialize_block, deserialize_block_header, deserialize_compact_size, deserialize_transaction,
    serialize_block, serialize_block_header, serialize_compact_size, serialize_transaction,
};
use bitcoin_y::hash::{Hash256, txid};
use bitcoin_y::tx::{OutPoint, Transaction, TxIn, TxOut};

fn sample_transaction() -> Transaction {
    Transaction {
        version: 2,
        vin: vec![TxIn {
            prevout: OutPoint {
                hash: Hash256([1; 32]),
                n: 3,
            },
            script_sig: vec![0x51, 0x21, 0x02, 0xab],
            sequence: 0xffff_fffe,
        }],
        vout: vec![TxOut {
            value: 12_345,
            script_pubkey: vec![0x76, 0xa9, 0x14, 0x88, 0xac],
        }],
        lock_time: 42,
    }
}

#[test]
fn compact_size_roundtrip() {
    let cases = [0, 1, 0xfc, 0xfd, 0xffff, 0x1_0000, 0x1_0000_0000];
    for value in cases {
        let encoded = serialize_compact_size(value);
        let (decoded, used) = deserialize_compact_size(&encoded).unwrap();
        assert_eq!(decoded, value);
        assert_eq!(used, encoded.len());
    }
}

#[test]
fn compact_size_rejects_non_canonical_encoding() {
    let error = deserialize_compact_size(&[0xfd, 0x01, 0x00]).unwrap_err();
    assert!(error.to_string().contains("Non-canonical CompactSize"));
}

#[test]
fn transaction_roundtrip_matches_reference_bytes() {
    let tx = Transaction {
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
    };

    let expected = concat!(
        "01000000",
        "01",
        "0000000000000000000000000000000000000000000000000000000000000000",
        "ffffffff",
        "4d",
        "04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73",
        "ffffffff",
        "01",
        "00f2052a01000000",
        "43",
        "4104678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5fac",
        "00000000"
    );

    let serialized = serialize_transaction(&tx);
    assert_eq!(hex::encode(&serialized), expected);
    assert_eq!(deserialize_transaction(&serialized).unwrap(), tx);
    assert_eq!(
        txid(&tx).to_display_hex(),
        "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b"
    );
}

#[test]
fn block_header_roundtrip_matches_reference_bytes() {
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

    let expected = concat!(
        "01000000",
        "0000000000000000000000000000000000000000000000000000000000000000",
        "3ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a",
        "29ab5f49",
        "ffff001d",
        "1dac2b7c"
    );

    let serialized = serialize_block_header(&header);
    assert_eq!(hex::encode(serialized), expected);
    assert_eq!(deserialize_block_header(&serialized).unwrap(), header);
}

#[test]
fn block_roundtrip_preserves_transactions() {
    let tx = sample_transaction();
    let block = Block {
        header: BlockHeader {
            version: 3,
            prev_block: Hash256([2; 32]),
            merkle_root: Hash256([3; 32]),
            time: 1_700_000_000,
            bits: 0x1d00ffff,
            nonce: 99,
        },
        txdata: vec![tx.clone()],
    };

    let serialized = serialize_block(&block);
    let decoded = deserialize_block(&serialized).unwrap();
    assert_eq!(decoded, block);
    assert_eq!(decoded.txdata[0], tx);
}
