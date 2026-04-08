/// @Name: main
///
/// @Date: 2026/4/9 03:41
///
/// @Author: Matrix.Ye
///
/// @Description: dadas
///
mod block;
mod cons;
mod db;
mod errors;
mod key;

// main.rs
use rusqlite::{Connection, Result};

macro_rules! db {
    ($db:expr) => {
        Connection::open($db)?
    };
}
macro_rules! exe {
    ($db:expr, $sql:expr) => {
        $db.execute($sql, ())?
    };
}
macro_rules! query {
    ($db:expr, $sql:expr) => {
        $db.query_row($sql, (), |r| r.get(0))?
    };
}

fn main() -> Result<()> {
    let db = db!("mini.db"); // 打开/创建库
    exe!(
        db,
        "CREATE TABLE IF NOT EXISTS user(id INTEGER PRIMARY KEY,name TEXT)"
    ); // 建表
    exe!(db, "INSERT INTO user(name) VALUES('宏太爽了')"); // 插入
    exe!(db, "INSERT INTO user(name) VALUES('鸡鸡太爽了')"); // 插入
    exe!(db, "INSERT INTO user(name) VALUES('rust太爽了')"); // 插入
    exe!(db, "INSERT INTO user(name) VALUES('sqlite太爽了')"); // 插入
    let name: String = query!(db, "SELECT name FROM user WHERE id=99"); // 查询

    println!("{:?}", name);
    Ok(())
}
