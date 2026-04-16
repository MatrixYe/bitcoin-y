/// @Name: build
///
/// @Date: 2026/4/17 01:01
///
/// @Author: Matrix.Ye
///
/// @Description: null
use prost_build::Config;


fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 🔥 核心：指定生成的 rs 文件输出到【项目根目录 / proto_gen 】文件夹
    // 你可以自由修改路径：src/proto_gen 、proto/gen 都可以
    let out_dir = std::path::Path::new("./proto_gen");
    std::fs::create_dir_all(out_dir)?;

    // 编译 proto 文件，并将代码生成到指定目录
    Config::new()
        .out_dir(out_dir) // 关键配置：自定义输出目录
        .compile_protos(
            &["proto/transaction.proto",
                "proto/block.proto"],
            &["proto/"],
        )?;

    Ok(())
}
