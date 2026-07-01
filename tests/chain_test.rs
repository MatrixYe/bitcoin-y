use bitcoin_y::bignum::BigNum;
use bitcoin_y::block::BlockHeader;
use bitcoin_y::chain::{BlockIndex, BlockTree, ChainError};
use bitcoin_y::uint256::Uint256;

fn header(prev_block: Uint256, bits: u32, nonce: u32) -> BlockHeader {
    BlockHeader {
        version: 1,
        prev_block,
        merkle_root: Uint256::from_u32(nonce + 1),
        time: nonce,
        bits,
        nonce,
    }
}

#[test]
fn block_index_accumulates_own_work_for_genesis_and_children() {
    let genesis_header = header(Uint256::ZERO, 0x1d00ffff, 0);
    let genesis = BlockIndex::new(&genesis_header, None);
    assert_eq!(genesis.height, 0);
    assert_eq!(genesis.get_chain_work(), genesis.get_block_work());

    let child_header = header(genesis.hash(), 0x1d00ffff, 1);
    let child = BlockIndex::new(&child_header, Some(&genesis));
    assert_eq!(child.height, 1);
    assert_eq!(
        child.get_chain_work(),
        genesis.get_block_work() + child.get_block_work()
    );
}

#[test]
fn block_work_uses_target_plus_one_formula() {
    let index = BlockIndex::new(&header(Uint256::ZERO, 0x1d00ffff, 0), None);
    assert_eq!(
        index.get_block_work(),
        BigNum::from_hex("100010001").unwrap()
    );
}

#[test]
fn block_tree_tracks_active_chain_and_best_tip() {
    let mut tree = BlockTree::new();
    let genesis_hash = tree
        .add_genesis(&header(Uint256::ZERO, 0x1d00ffff, 0))
        .unwrap();
    let block1_hash = tree
        .add_header(&header(genesis_hash, 0x1d00ffff, 1))
        .unwrap();

    assert_eq!(tree.len(), 2);
    assert_eq!(tree.genesis_hash(), Some(genesis_hash));
    assert_eq!(tree.best_hash(), Some(block1_hash));
    assert_eq!(tree.best_height(), Some(1));
    assert_eq!(tree.active_chain(), &[genesis_hash, block1_hash]);
    assert_eq!(tree.active_hash_at_height(0), Some(genesis_hash));
    assert_eq!(tree.active_hash_at_height(1), Some(block1_hash));
    assert_eq!(tree.get(genesis_hash).unwrap().next, Some(block1_hash));
    assert!(tree.is_in_best_chain(genesis_hash));
    assert!(tree.is_in_best_chain(block1_hash));
}

#[test]
fn block_tree_switches_best_chain_by_accumulated_work() {
    let mut tree = BlockTree::new();
    let genesis_hash = tree
        .add_genesis(&header(Uint256::ZERO, 0x1d00ffff, 0))
        .unwrap();

    let low_hash = tree
        .add_header(&header(genesis_hash, 0x1d00ffff, 1))
        .unwrap();
    let high_hash = tree
        .add_header(&header(genesis_hash, 0x1b0404cb, 2))
        .unwrap();

    assert_eq!(tree.best_hash(), Some(high_hash));
    assert_eq!(tree.get(genesis_hash).unwrap().next, Some(high_hash));
    assert_eq!(tree.children(genesis_hash).len(), 2);
    assert!(!tree.is_in_best_chain(low_hash));
    assert!(tree.is_in_best_chain(high_hash));
}

#[test]
fn block_tree_finds_fork_point() {
    let mut tree = BlockTree::new();
    let genesis_hash = tree
        .add_genesis(&header(Uint256::ZERO, 0x1d00ffff, 0))
        .unwrap();
    let left_hash = tree
        .add_header(&header(genesis_hash, 0x1d00ffff, 1))
        .unwrap();
    let right_hash = tree
        .add_header(&header(genesis_hash, 0x1d00ffff, 2))
        .unwrap();
    let right_child_hash = tree.add_header(&header(right_hash, 0x1d00ffff, 3)).unwrap();

    assert_eq!(
        tree.fork_point(left_hash, right_child_hash),
        Ok(genesis_hash)
    );
}

#[test]
fn block_tree_rejects_duplicate_genesis_and_unknown_parent() {
    let mut tree = BlockTree::new();
    let genesis = header(Uint256::ZERO, 0x1d00ffff, 0);
    let genesis_hash = tree.add_genesis(&genesis).unwrap();

    assert_eq!(
        tree.add_genesis(&genesis),
        Err(ChainError::GenesisAlreadyExists { hash: genesis_hash })
    );

    let missing_prev = Uint256::from_u32(99);
    assert_eq!(
        tree.add_header(&header(missing_prev, 0x1d00ffff, 1)),
        Err(ChainError::UnknownPrevBlock { prev: missing_prev })
    );
}
