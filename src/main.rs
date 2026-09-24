//! @Name: main
//!
//! @Date: 2026/4/9 03:41
//!
//! @Author: Matrix.Ye
//!
//! @Description: null

use bitcoin_y::params::{Network, Params};
fn main() {
    env_logger::init(); // 不要注释，env_logger必须初始化才能使用
    let params = Params::from_network(Network::Main);
    println!("{:?}", params.consensus.genesis_hash);
}
