# 构建阶段 - 使用最新稳定版 Rust
FROM rust:latest AS builder

# 安装构建依赖
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# 复制所有源代码
COPY . .

# 构建（不使用缓存技巧，直接完整构建）
RUN cargo build --release 2>&1 | tee /tmp/build.log

# 验证构建结果
RUN ls -la /app/target/release/datachain && \
    file /app/target/release/datachain && \
    /app/target/release/datachain --help

# 运行阶段
FROM debian:bookworm-slim

# 安装运行时依赖
RUN apt-get update && apt-get install -y \
    ca-certificates \
    wget \
    libssl3 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# 复制二进制文件
COPY --from=builder /app/target/release/datachain /app/datachain

# 创建数据目录
RUN mkdir -p /app/data /app/config

# 复制默认配置
COPY config/config.toml /app/config/config.toml

# 设置环境变量
ENV TZ=Asia/Shanghai
ENV RUST_LOG=debug
ENV RUST_BACKTRACE=1

# 暴露端口
EXPOSE 8080

# 健康检查
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD wget -q --spider http://localhost:8080/health || exit 1

# 启动命令
ENTRYPOINT ["/app/datachain"]
CMD ["--config", "/app/config/config.toml", "serve", "--port", "8080"]
