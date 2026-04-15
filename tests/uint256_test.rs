/// @Name: uint256_test
///
/// @Date: 2026/4/16 03:15
///
/// @Author: Matrix.Ye
///
/// @Description: null

#[cfg(test)]
mod tests {
    use bitcoin_y::uint256::Uint256;

    #[test]
    fn test_nbit_to_uint256() {
        let x = 0x1b0404cb;
        let y = "0x00000000000404CB000000000000000000000000000000000000000000000000";
        let (target, _, _) = Uint256::set_compact(0x1b0404cb);
        assert_eq!(target, Uint256::from_hex_string(y).unwrap());

        let i = target.get_compact(false);
        assert_eq!(i, x);
    }
}
