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

fn main() -> Result<(), ()> {
    env_logger::init();
    let pdb = db::DB::new("test.db");
    pdb.init();

    Ok(())
}
