.PHONY: build run test clean docker fmt lint check

# 默认目标
all: build

# 构建
build:
	cargo build --release

# 调试构建
build-debug:
	cargo build

# 运行
run:
	cargo run -- serve --port 8080

# 运行（调试模式）
run-debug:
	RUST_LOG=debug cargo run -- serve --port 8080

# 初始化
init:
	cargo run -- init

# 测试
test:
	cargo test

# 测试（显示输出）
test-verbose:
	cargo test -- --nocapture

# 清理
clean:
	cargo clean
	rm -rf data/*.db

# Docker 构建
docker:
	docker build -t datachain-rust .

# Docker 运行
docker-run:
	docker run -d -p 8004:8080 --name datachain-rust datachain-rust

# Docker Compose
docker-up:
	docker-compose up -d

docker-down:
	docker-compose down

# 格式化
fmt:
	cargo fmt

# 检查格式
fmt-check:
	cargo fmt -- --check

# Lint
lint:
	cargo clippy -- -D warnings

# 类型检查
check:
	cargo check

# 文档
doc:
	cargo doc --open

# 运行示例
example:
	cargo run --example basic_usage

# 安装依赖
deps:
	rustup component add clippy rustfmt

# 发布构建
release:
	cargo build --release
	strip target/release/datachain

# 帮助
help:
	@echo "可用命令:"
	@echo "  make build       - 构建发布版本"
	@echo "  make build-debug - 构建调试版本"
	@echo "  make run         - 运行服务"
	@echo "  make run-debug   - 调试模式运行"
	@echo "  make init        - 初始化区块链"
	@echo "  make test        - 运行测试"
	@echo "  make clean       - 清理构建"
	@echo "  make docker      - 构建 Docker 镜像"
	@echo "  make docker-up   - 启动 Docker Compose"
	@echo "  make fmt         - 格式化代码"
	@echo "  make lint        - 代码检查"
	@echo "  make doc         - 生成文档"
	@echo "  make example     - 运行示例"
