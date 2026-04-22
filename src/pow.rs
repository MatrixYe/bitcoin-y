// @Name: pow
// @Date: 2026/4/16 00:19
// @Author: Matrix.Ye
// @Description: null

use crate::hash::Hash256;
use crate::uint256::Uint256;

/// 工作量检查
pub fn check_proof_of_work(hash: Hash256, nbits: u32) -> bool {
    let Some(target) = nbit_to_target(nbits) else {
        return false;
    };

    Uint256::from(hash) <= target
}

/// 压缩目标值nbit => 目标值target
pub fn nbit_to_target(nbit: u32) -> Option<Uint256> {
    let (target, negative, overflow) = Uint256::set_compact(nbit);
    if negative || overflow || target.is_zero() {
        return None;
    }

    Some(target)
}

/// 目标值 target => 压缩目标值nbit
pub fn target_to_nbit(target: Uint256) -> u32 {
    target.get_compact(false)
}

/// 获取下一个工作量证明目标值
pub fn get_next_work_required() {
    unimplemented!()
}

pub fn calculate_next_work_required() {
    unimplemented!()
}
