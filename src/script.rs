pub mod consts;
pub mod error;
pub mod interpreter;
pub mod opcode;
pub mod parser;
pub mod verify;

/// @Name: script
///
/// @Date: 2026/4/23 09:55
///
/// @Author: Matrix.Ye
///
/// @Description: 脚本系统
/// Script is a stack machine (like Forth) that evaluates a predicate
/// returning a bool indicating valid or not.  There are no loops.
///

pub type Script = Vec<u8>;

pub use consts::{MAX_OPS_PER_SCRIPT, MAX_SCRIPT_ELEMENT_SIZE, MAX_SCRIPT_SIZE, MAX_STACK_SIZE};
pub use error::ScriptError;
