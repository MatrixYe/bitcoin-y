/// @Name: db
///
/// @Date: 2026/4/9 04:21
///
/// @Author: Matrix.Ye
///
use rusqlite::Connection;


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
fn xxx() {
    let conn = Connection::open("db.sqlite3").unwrap();
}
