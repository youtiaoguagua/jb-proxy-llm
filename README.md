# OpenAI API Proxy Server

高性能的OpenAI兼容API代理服务器，支持Chat Completions、Models列表和智能缓存。

## 特性

- 🔄 完整的OpenAI API兼容（`/v1/chat/completions`, `/v1/models`）
- ⚡ `/v1/models` 智能缓存（24小时）
- 🏗️ 流式和非流式响应支持
- 🔐 **入参Authorization验证**（可选）
- 📊 详细的调试日志和性能监控
- 🔧 环境变量配置
- 🐳 Docker支持

## 快速开始

### 使用Docker（推荐）

```bash
# 基础代理（无授权验证）
docker run -d \
  -p 8080:8080 \
  -e TARGET_HOST="https://api.example.com" \
  -e AUTH_BEARER="sk-your-api-key" \
  ghcr.io/jb-llm/proxy-server:latest

# 带授权验证的代理
docker run -d \
  -p 8080:8080 \
  -e TARGET_HOST="https://api.example.com" \
  -e AUTH_BEARER="sk-your-api-key" \
  -e AUTH_VALIDATION="true" \
  -e ALLOWED_TOKENS="token1,token2,sk-your-client-token" \
  -e ADMIN_TOKEN="your-admin-token-for-cache-clear" \
  ghcr.io/jb-llm/proxy-server:latest
```

### 本地开发

```bash
# 克隆项目
git clone https://github.com/your-username/jb-proxy-llm.git
cd jb-proxy-llm

# 复制配置文件
cp .env.example .env.local

# 编辑配置
nano .env.local  # 填入真实API密钥和服务器地址

# 运行
go run .
```

## API端点

```bash
# 启用授权验证后的API调用
curl -X POST http://localhost:8080/v1/chat/completions \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer your-allowed-token" \
  -d '{"model":"gpt-3.5-turbo","messages":[{"role":"user","content":"Hello"}]}'

# Models (自动缓存24小时)
curl -H "Authorization: Bearer your-allowed-token" \
  http://localhost:8080/v1/models

# 清除缓存（需要ADMIN_TOKEN）
curl -X POST -H "Authorization: Bearer your-admin-token" \
  http://localhost:8080/admin/cache/clear

# 未授权访问的响应示例
# HTTP 401
# {
#   "error": "unauthorized",
#   "message": "Invalid or missing authorization token",
#   "time": "2024-01-01T12:00:00Z"
# }
```

## 配置

| 变量 | 说明 | 默认值 | 必需 |
|------|------|--------|------|
| `TARGET_HOST` | API服务器地址 | `https://api.example.com` | ✅ |
| `AUTH_BEARER` | 目标服务器的Bearer Token | - | ✅ |
| `PROXY_PORT` | 监听端口 | `8080` | - |
| `LOG_LEVEL` | 日志级别 (`debug\|info\|error`) | `info` | - |
| `DEBUG_MODE` | 调试模式 | `false` | - |
| `AUTH_VALIDATION` | 是否启用入参授权验证 | `false` | - |
| `ALLOWED_TOKENS` | 允许的token列表（逗号分隔） | - | - |
| `DEFAULT_AUTH_HEADER` | 请求头名称 | `Authorization` | - |
| `ADMIN_TOKEN` | 管理员token | - | - |

## Docker部署

```dockerfile
# 多阶段构建
FROM golang:1.21-alpine AS builder
WORKDIR /app
COPY . .
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o proxy-server .

FROM alpine:latest
RUN apk --no-cache add ca-certificates
WORKDIR /root/
COPY --from=builder /app/proxy-server .
EXPOSE 8080
CMD ["./proxy-server"]
```

### Docker Compose

```yaml
version: '3.8'
services:
  proxy:
    image: ghcr.io/jb-llm/proxy-server:latest
    ports:
      - "8080:8080"
    environment:
      TARGET_HOST: "https://api.example.com"
      AUTH_BEARER: "sk-your-api-key"
      LOG_LEVEL: "info"
    restart: unless-stopped
```

## 安全注意事项

- ⚠️ **永远不要**在代码中硬编码API密钥
- ✅ **建议**使用环境变量或密钥管理服务
- 🔒 生产环境**必须**禁用调试模式
- 🔄 定期轮换API密钥

## 许可证

MIT License - 详见 [LICENSE](LICENSE) 文件

## 贡献

欢迎提交Issue和Pull Request！

---

🐳 **Docker镜像**: `ghcr.io/jb-llm/proxy-server`
📦 **自动构建**: 每次push自动构建和发布