# 构建阶段 —— 真实编译 Rust(失败即中断,不再用 || true 掩盖)
FROM rust:latest AS builder

RUN apt-get update && apt-get install -y pkg-config libssl-dev && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY . .

# 真实编译 release 二进制。编译失败会使镜像构建失败(此前用 'cargo build || true'
# 掩盖失败并回退占位文件,导致镜像跑的是假的 python health server)。
RUN cargo build --release --bin datachain

# 运行阶段
FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install -y ca-certificates wget libsqlite3-0 \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app

# 复制真实编译产物
COPY --from=builder /app/target/release/datachain /app/datachain
COPY config/config.toml /app/config/config.toml

RUN useradd -u 10001 -m appuser \
    && mkdir -p /app/data /app/config \
    && chown -R appuser:appuser /app

ENV TZ=Asia/Shanghai
USER appuser
EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=10s --start-period=10s --retries=3 \
    CMD wget -q --spider http://localhost:8080/health || exit 1

# 启动真实服务(api::run_server 提供 /health 与 /ws)
CMD ["/app/datachain", "serve", "--config", "/app/config/config.toml"]
