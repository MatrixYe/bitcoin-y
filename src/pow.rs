/// @Name: pow
///
/// @Date: 2026/4/16 00:19
///
/// @Author: Matrix.Ye
///
/// @Description: null
// pow.rs
use crate::uint256::Uint256;


///```c++
/// // pow.cpp
/// std::optional<arith_uint256> DeriveTarget(unsigned int nBits, const uint256 pow_limit)
/// {
///     bool fNegative;
///     bool fOverflow;
///     arith_uint256 bnTarget;  // 这里声明为 arith_uint256 类型
///
///     bnTarget.SetCompact(nBits, &fNegative, &fOverflow);  // 调用 SetCompact 方法
///
///     // 检查范围
///     if (fNegative || bnTarget == 0 || fOverflow || bnTarget > UintToArith256(pow_limit))
///         return {};
///
///     return bnTarget;  // 返回 arith_uint256 类型
/// }
/// ```
///
/// ```cpp
/// // pow.cpp
/// bool CheckProofOfWorkImpl(uint256 hash, unsigned int nBits, const Consensus::Params& params)
/// {
///     auto bnTarget{DeriveTarget(nBits, params.powLimit)};  // 接收 arith_uint256 类型
///     if (!bnTarget) return false;
///
///     // 检查工作量证明是否匹配声明的难度
///     if (UintToArith256(hash) > bnTarget)  // 与 arith_uint256 类型比较
///         return false;
///
///     return true;
/// }
/// ```

/// 工作量检查
pub fn check_proof_of_work(hash: Uint256, nbits: u32) -> bool {
    let (target, _, _) = Uint256::set_compact(nbits);

    if hash > target {
        false;
    }
    //仅当区块哈希小于目标哈希时，才是有效工作量
    true // hash < target
}

/// 压缩目标值nbit => 目标值target
pub fn nbit_to_target(nbit: u32, limit: Uint256) -> Uint256 {
    let (u, _, _) = Uint256::set_compact(nbit);
    u
}

/// 目标值 target => 压缩目标值nbit
pub fn target_to_nbit(target: Uint256) -> u32 {
    target.get_compact(false)
}

/// 获取下一个工作量证明目标值
pub fn get_next_work_required() {
    unimplemented!()
}

///
pub fn calculate_next_work_required() {
    unimplemented!()
}
