# 构建阶段
FROM rust:1.75-alpine AS builder

# 安装构建依赖
RUN apk add --no-cache musl-dev openssl-dev openssl-libs-static pkgconfig

WORKDIR /app

# 复制 Cargo 文件
COPY Cargo.toml ./

# 创建虚拟 src 以缓存依赖
RUN mkdir src && echo "fn main() {}" > src/main.rs
RUN cargo build --release 2>/dev/null || true
RUN rm -rf src

# 复制源代码
COPY src ./src
COPY examples ./examples

# 构建
RUN cargo build --release

# 运行阶段
FROM alpine:3.19

# 安装运行时依赖
RUN apk add --no-cache ca-certificates tzdata wget

WORKDIR /app

# 复制二进制文件
COPY --from=builder /app/target/release/datachain /app/datachain

# 创建数据目录
RUN mkdir -p /app/data /app/config

# 复制默认配置
COPY config.toml /app/config/config.toml

# 设置环境变量
ENV TZ=Asia/Shanghai
ENV RUST_LOG=info

# 暴露端口
EXPOSE 8080

# 健康检查
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD wget -q --spider http://localhost:8080/health || exit 1

# 启动命令
ENTRYPOINT ["/app/datachain"]
CMD ["serve", "--port", "8080", "--config", "/app/config/config.toml"]
