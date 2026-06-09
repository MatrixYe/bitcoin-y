use bitcoin_y::hash::sha256d;
use bitcoin_y::merkle::compute_merkle_root;
use bitcoin_y::uint256::Uint256;

fn hash_pair(left: Uint256, right: Uint256) -> Uint256 {
    let mut bytes = [0u8; 64];
    bytes[..32].copy_from_slice(&left.to_bytes());
    bytes[32..].copy_from_slice(&right.to_bytes());
    Uint256::from_bytes(sha256d(&bytes))
}

#[test]
fn empty_tree_returns_zero() {
    assert_eq!(compute_merkle_root(Vec::new()), Uint256::ZERO);
}

#[test]
fn single_node_is_its_own_root() {
    let txid =
        Uint256::from_hex("4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b")
            .unwrap();

    assert_eq!(compute_merkle_root(vec![txid]), txid);
}

#[test]
fn two_nodes_are_hashed_in_order() {
    let first = Uint256::from_u32(1);
    let second = Uint256::from_u32(2);

    assert_eq!(
        compute_merkle_root(vec![first, second]),
        hash_pair(first, second)
    );
    assert_ne!(
        compute_merkle_root(vec![first, second]),
        compute_merkle_root(vec![second, first])
    );
}

#[test]
fn odd_layer_duplicates_the_last_node() {
    let first = Uint256::from_u32(1);
    let second = Uint256::from_u32(2);
    let last = Uint256::from_u32(3);

    let left_branch = hash_pair(first, second);
    let right_branch = hash_pair(last, last);
    let expected = hash_pair(left_branch, right_branch);

    assert_eq!(compute_merkle_root(vec![first, second, last]), expected);
}

#[test]
fn odd_nodes_are_duplicated_at_each_tree_level() {
    let nodes = [
        Uint256::from_u32(1),
        Uint256::from_u32(2),
        Uint256::from_u32(3),
        Uint256::from_u32(4),
        Uint256::from_u32(5),
    ];

    let left = hash_pair(hash_pair(nodes[0], nodes[1]), hash_pair(nodes[2], nodes[3]));
    let duplicated_last = hash_pair(nodes[4], nodes[4]);
    let right = hash_pair(duplicated_last, duplicated_last);
    let expected = hash_pair(left, right);

    assert_eq!(compute_merkle_root(nodes.to_vec()), expected);
}
