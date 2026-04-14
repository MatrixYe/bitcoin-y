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
fn main() -> Result<(), ()> {
    env_logger::init();
    let pdb = db::DB::new("test.db");
    pdb.init().expect("Error initializing pdb");
    println!("{:?}", "to do other...");

    Ok(())
}
