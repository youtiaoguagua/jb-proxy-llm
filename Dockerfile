# 使用官方Go镜像作为构建环境
FROM golang:1.23-alpine AS builder

# 设置环境变量
ENV GO111MODULE=on \
    CGO_ENABLED=0 \
    GOOS=linux \
    GOARCH=amd64

# 设置工作目录
WORKDIR /app

# 复制源代码
COPY . .

# 初始化模块并下载依赖
RUN go mod tidy
RUN go mod download



# 构建二进制文件（优化构建大小）
RUN go build -ldflags="-s -w" -o proxy-server .

# 最终运行镜像
FROM scratch

# 设置工作目录
WORKDIR /app

# 从构建阶段复制二进制文件
COPY --from=builder /app/proxy-server .

# 启动命令
CMD ["./proxy-server"]