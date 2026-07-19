//! @Name: pow
//!
//! @Date: 2026/7/20 03:23
//!
//! @Author: Matrix.Ye
//!
//! @Description: 本模块用于*工作量*相关的计算，因为挖矿和验证两个步骤都需要依赖Pow规则，所以我将它单独定义为一个模块，此模块将在`mining`和`validation`模块中使用。
//! ## 基本功能：
//! - 获取下一个难度
//! - 验证工作量
//! - 难度限制
//! - 。。。
//!

use crate::bignum::BigNum;
use crate::chain::{BlockIndex, BlockTree};
use crate::parms::ChainParams;

/// 计算下一个区块需要的难度指标，参考原版`GetNextWorkRequired`
/// ## 实现逻辑：
/// 1. 确定目标时间周期(10分钟)，目标时间调整周期(14天)
/// 2. 如果下个区块是创世区块，那么默认使用最大target，并返回压缩值
/// 2. 如果非创世区块，计算下个区块是否恰好处于调整点
/// 3. 如果没有处于调整点，那么延续上一个区块的`nbit`并返回
/// 4. 如果出于难度调整点，那么继续计算
///     1. 获取当前块的时间戳和往前推2016个块的时间戳，计算实际时间差`nActualTimespan`,
///     2. 限制实际时间差`nActualTimespan`，最大`4*nTargetTimespan`，最小 `nTargetTimespan/4`
///     2. 新目标值 = 旧目标值 * 实际耗时 / 理想耗时
/// 5. 限制不能低于最低难度
/// 6. 返回难度指标的压缩值 `bnNew.GetCompact()`

pub fn get_next_work_required(chain: &BlockTree, last: &BlockIndex, params: &ChainParams) -> u32 {
    let target_spacing = params.target_spacing;
    let target_timespan = params.target_timespan;


    let interval = target_timespan / target_spacing;

    if last.is_genesis() {
        return params.pow_limit;
    }

    if (last.height + 1) % interval != 0 {
        return last.bits;
    }
    let first = last.height.saturating_sub(interval + 1); // 防止溢出，高度不够时，停在0
    let first = chain.get_active_hash_at_height(first);
    let first = chain.get(first.unwrap()).unwrap();
    let mut actual_time_span = last.time - first.time;

    if actual_time_span > target_timespan.saturating_mul(4) {
        actual_time_span = target_timespan.saturating_mul(4);
    }
    if actual_time_span < target_timespan.saturating_div(4) {
        actual_time_span = target_timespan.saturating_div(4);
    }

    let mut new_target = BigNum::set_compact(last.bits);
    new_target *= BigNum::from_u32(actual_time_span);
    new_target /= BigNum::from_u32(target_timespan);

    // 返回目标压缩值
    new_target.to_u32().unwrap()
}




