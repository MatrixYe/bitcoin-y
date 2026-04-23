use bitcoin_y::uint256::Uint256;

/// @Name: main
///
/// @Date: 2026/4/9 03:41
///
/// @Author: Matrix.Ye
///
/// @Description: ///
fn main() {
    env_logger::init(); // 不要注释，env_logger必须初始化才能使用
    // 测试 u64 转 Uint256
    let u64_val = 0x123456789abcdefu64;
    let uint = Uint256::from(u64_val);
    assert_eq!(uint.words()[0], 0x89abcdef);
    assert_eq!(uint.words()[1], 0x1234567);

    // 测试 hex 转换（大端显示序）
    let hex = "0000000000000000000000000000000000000000000000000000000000000001";
    let uint = Uint256::from_hex_string(hex).unwrap();
    assert_eq!(uint.words()[0], 1);
    assert_eq!(uint.to_hex_string(false), hex);
}

#[allow(dead_code)]
fn temp() {
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
        let (target, _negative, _overflow) = Uint256::set_compact(x);
        let y = Uint256::from_hex_string(y).unwrap();
        println!("计算Target:{:?}", target.to_hex_string(true));
        println!("解压缩 是否匹配：{:?}", target == y);
        let a = target.get_compact(false);
        println!("压缩   是否匹配:{:?} {:?} {:?}", x, a, x == a);

        println!("{:?}", "--------------------------------");
    }
}
