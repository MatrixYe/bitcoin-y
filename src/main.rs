use bitcoin_y::uint256::Uint256;
use std::{i64, u16, u32, u64};
pub mod bignum;

/// @Name: main
///
/// @Date: 2026/4/9 03:41
///
/// @Author: Matrix.Ye
///
/// @Description: ///
fn main() {
    env_logger::init(); // 不要注释，env_logger必须初始化才能使用
    // // 测试 u64 转 Uint256
    // let u64_val = 0x123456789abcdefu64;
    // let uint = Uint256::from(u64_val);
    // assert_eq!(uint.words()[0], 0x89abcdef);
    // assert_eq!(uint.words()[1], 0x1234567);
    //
    // // 测试 hex 转换（大端显示序）
    // let hex = "0000000000000000000000000000000000000000000000000000000000000001";
    // let uint = Uint256::from_hex_string(hex).unwrap();
    // assert_eq!(uint.words()[0], 1);
    // assert_eq!(uint.to_hex_string(false), hex);

    println!("u8::MAX = {:?}", u8::MAX);
    println!("i8::MAX = {:?}", i8::MAX);

    println!("u16::MAX = {:?}", u16::MAX);
    println!("i16::MAX = {:?}", i16::MAX);

    println!("u32::MAX = {:?}", u32::MAX);
    println!("i32::MAX = {:?}", i32::MAX);

    println!("u64::MAX = {:?}", u64::MAX);
    println!("i64::MAX = {:?}", i64::MAX);

    println!("u128::MAX = {:?}", std::u128::MAX);
    println!("i128::MAX = {:?}", std::i128::MAX);
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
