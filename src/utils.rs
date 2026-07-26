//! @Name: utils
//!
//! @Date: 2026/7/24 16:50
//!
//! @Author: Matrix.Ye
//!
//! @Description: 简单的工具函数
//!
//!

use std::cmp::min;
use std::time::{SystemTime, UNIX_EPOCH};


/// # 获取系统自适应时间
///
/// 参考 原版  `utils::GetAdjustedTime`
/// 因为需要涉及节点，暂时不按照原版实现，而是用当前系统时间替换
pub fn get_adjusted_time() -> u32 {
    let adjusted_time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    min(u32::MAX as u64, adjusted_time) as u32
}


