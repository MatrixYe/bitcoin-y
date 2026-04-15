use bitcoin_y::uint256::Uint256;

/// @Name: main
///
/// @Date: 2026/4/9 03:41
///
/// @Author: Matrix.Ye
///
/// @Description: ///
///
mod block;
mod cons;
mod db;
mod errors;
mod key;
mod script;
mod tx;
mod uint256;
mod utils;
fn main() {
    // 示例 1: 从 nBits 转换为 Uint256
    // 比特币创世区块的 nBits = 0x1d00ffff

    let buff = [
        (
            0x1d00ffff,
            "0x00000000FFFF0000000000000000000000000000000000000000000000000000",
        ),
        (
            0x1b0404cb,
            "0x00000000000404CB000000000000000000000000000000000000000000000000",
        ),
        (
            0x20123456,
            "0x1234560000000000000000000000000000000000000000000000000000000000",
        ),
    ];
    for (x, y) in buff {
        let (target, negative, overflow) = Uint256::set_compact(x);
        let y = Uint256::from_hex_string(y).unwrap();
        println!("计算Target:{:?}", target.to_hex_string(true));
        println!("解压缩 是否匹配：{:?}", target == y);
        let a = target.get_compact(false);
        println!("压缩   是否匹配:{:?} {:?} {:?}", x, a, x == a);

        println!("{:?}", "--------------------------------");
    }
}
