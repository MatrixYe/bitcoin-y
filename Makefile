# 定义默认目标：运行tests/目录下所有集成测试
.DEFAULT_GOAL := test

# ========================================
# 核心测试命令
# ========================================
# 目标1：运行tests/目录下所有集成测试（默认目标）
test:
	@echo "========================================"
	@echo "运行 tests/ 目录下所有集成测试..."
	@echo "========================================"
	cargo test --test '*'

# 目标2：运行指定的单个测试文件（需传 FILE 参数，如 make test-specific FILE=integration_test）
test-specific:
	@if [ -z "$(FILE)" ]; then \
		echo "错误：请指定要运行的测试文件（不含.rs后缀），例如：make test-specific FILE=integration_test"; \
		exit 1; \
	fi
	@echo "========================================"
	@echo "运行 tests/ 目录下的 $(FILE).rs 测试文件..."
	@echo "========================================"
	cargo test --test $(FILE)

# 目标3：运行集成测试并显示打印输出（默认cargo test会隐藏println!）
test-show-output:
	@echo "========================================"
	@echo "运行集成测试并显示输出..."
	@echo "========================================"
	cargo test --test '*' -- --show-output

# 目标4：单线程运行集成测试（避免多线程输出混乱）
test-single-thread:
	@echo "========================================"
	@echo "单线程运行集成测试..."
	@echo "========================================"
	cargo test --test '*' -- --test-threads=1

# 目标5：运行集成测试（包含被#[ignore]标记的测试）
test-with-ignored:
	@echo "========================================"
	@echo "运行集成测试（包含忽略的测试）..."
	@echo "========================================"
	cargo test --test '*' -- --ignored

# ========================================
# 辅助命令
# ========================================
# 清理编译产物（测试相关的临时文件）
clean:
	@echo "清理编译产物..."
	cargo clean

# 查看所有可用目标
help:
	@echo "可用命令："
	@echo "  make                - 运行tests/目录下所有集成测试（默认）"
	@echo "  make test-specific FILE=<文件名> - 运行指定的测试文件（如 make test-specific FILE=integration_test）"
	@echo "  make test-show-output - 运行集成测试并显示打印输出"
	@echo "  make test-single-thread - 单线程运行集成测试"
	@echo "  make test-with-ignored - 运行集成测试（包含忽略的测试）"
	@echo "  make clean          - 清理编译产物"
	@echo "  make help           - 查看帮助信息"