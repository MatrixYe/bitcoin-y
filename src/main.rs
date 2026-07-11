/// @Name: main
///
/// @Date: 2026/4/9 03:41
///
/// @Author: Matrix.Ye
///
/// @Description: ///

use bitcoin_y::uint256::Uint256;
fn main() {
    env_logger::init(); // 不要注释，env_logger必须初始化才能使用
    let m=Uint256::MAX;
    println!("{}",m);
}