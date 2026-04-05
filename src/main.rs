mod block;
mod cons;
mod errors;
mod key;

use std::ops::Add;

// 通用 add 函数：支持所有实现了 Add trait 的类型
fn add<T: Add<Output = T>>(a: T, b: T) -> T {
    a + b
}

fn main() {
    // 支持 i32
    // println!("{:?}", add(1, 2)); // 3
    // // 支持 i64
    // println!("{:?}", add(10i64, 20i64)); // 30
    // println!("{:?}", add(1.001, 2.002)); // 30
    // 支持 String（字符串拼接）
    // println!("{:?}", add(true,false)); // Hello Rust
    let mut buff = Vec::with_capacity(25);
    buff.push(0x00);
    buff.extend_from_slice(&[1, 2, 3, 4, 5]);

    println!("{:?}", buff.len());
}
