/// @Name: script
///
/// @Date: 2026/4/13 09:55
///
/// @Author: Matrix.Ye
///
/// @Description:
///
///
///

/// 比特币脚本CScript : public vector<unsigned char>)
// pub struct CScript(pub Vec<u8>);
pub type CScript = Vec<u8>;
// 核心：实现 Deref 特征，让 CScript 可以直接使用 Vec<u8> 的所有方法
// 等价于 C++ 的「继承vector」
// impl std::ops::Deref for CScript {
//     // 目标类型 = 底层的字节数组
//     type Target = Vec<u8>;
//
//     // 解引用：返回内部的Vec<u8>
//     fn deref(&self) -> &Self::Target {
//         &self.0
//     }
// }
//
// // 可选：实现 DerefMut，支持修改内部Vec（增删字节）
// impl std::ops::DerefMut for CScript {
//     fn deref_mut(&mut self) -> &mut Self::Target {
//         &mut self.0
//     }
// }
