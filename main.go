package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// 配置结构体
type Config struct {
	Port              int
	TargetHost        string
	AuthBearer        string
	LogLevel          string
	DebugMode         bool
	AuthValidation    bool     // 是否入参Authorization验证
	AllowedTokens     []string // 允许的token列表
	DefaultAuthHeader string   // 默认使用的Authorization头
}

// 默认配置
var config = Config{
	Port:              8080,
	TargetHost:        "https://api.example.com",
	AuthBearer:        "your-api-key-here",
	LogLevel:          "info",
	DebugMode:         false,
	AuthValidation:    false,
	AllowedTokens:     []string{},
	DefaultAuthHeader: "Authorization",
}

// 日志级别
const (
	DEBUG = "debug"
	INFO  = "info"
	ERROR = "error"
)

// 缓存项结构体
type CacheItem struct {
	Data       []byte
	ExpiresAt  time.Time
	Headers    map[string][]string
	StatusCode int
}

// /v1/models 缓存
var (
	modelsCache   *CacheItem
	modelsCacheMu sync.RWMutex
	cacheDuration = 24 * time.Hour // 24小时缓存
)

func main() {
	loadConfig()
	setupLogging()

	// 注册我们的代理处理器函数
	http.HandleFunc("/v1/chat/completions", proxyHandler)
	http.HandleFunc("/v1/models", modelsHandler)
	http.HandleFunc("/admin/cache/clear", clearCacheHandler)

	logInfo("SSE 代理服务器启动，监听端口: %d", config.Port)
	logInfo("转发地址: -> %s", config.TargetHost)
	logInfo("支持的端点: /v1/chat/completions, /v1/models (24h缓存), /admin/cache/clear")
	logInfo("缓存时长: 24小时")
	logInfo("日志级别: %s", config.LogLevel)
	logInfo("调试模式: %v", config.DebugMode)
	logInfo("入参Authorization验证: %v", config.AuthValidation)
	if config.AuthValidation && len(config.AllowedTokens) > 0 {
		logInfo("允许的Token数量: %d", len(config.AllowedTokens))
	}

	// 启动HTTP服务器
	if err := http.ListenAndServe(fmt.Sprintf(":%d", config.Port), nil); err != nil {
		logFatal("服务器启动失败: %v", err)
	}
}

// 加载配置
func loadConfig() {
	// 然后尝试加载 .env
	loadEnvFile(".env")

	// 从环境变量读取配置（会覆盖.env文件中的设置）
	if port := os.Getenv("PROXY_PORT"); port != "" {
		if p, err := strconv.Atoi(port); err == nil {
			config.Port = p
		}
	}

	if target := os.Getenv("TARGET_HOST"); target != "" {
		config.TargetHost = target
	}

	if auth := os.Getenv("AUTH_BEARER"); auth != "" {
		config.AuthBearer = auth
	}

	if logLevel := os.Getenv("LOG_LEVEL"); logLevel != "" {
		config.LogLevel = strings.ToLower(logLevel)
	}

	if debug := os.Getenv("DEBUG_MODE"); debug != "" {
		config.DebugMode = strings.ToLower(debug) == "true" || debug == "1"
	}

	// Authorization验证配置
	if authValidation := os.Getenv("AUTH_VALIDATION"); authValidation != "" {
		config.AuthValidation = strings.ToLower(authValidation) == "true" || authValidation == "1"
	}

	if allowedTokens := os.Getenv("ALLOWED_TOKENS"); allowedTokens != "" {
		config.AllowedTokens = strings.Split(allowedTokens, ",")
		// 清理每个token的空格
		for i := range config.AllowedTokens {
			config.AllowedTokens[i] = strings.TrimSpace(config.AllowedTokens[i])
		}
	}

	if defaultAuthHeader := os.Getenv("DEFAULT_AUTH_HEADER"); defaultAuthHeader != "" {
		config.DefaultAuthHeader = defaultAuthHeader
	}
}

// 加载.env文件
func loadEnvFile(filename string) {
	data, err := os.ReadFile(filename)
	if err != nil {
		logDebug("无法读取 %s 文件: %v", filename, err)
		return
	}

	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		parts := strings.SplitN(line, "=", 2)
		if len(parts) == 2 {
			key := strings.TrimSpace(parts[0])
			value := strings.TrimSpace(parts[1])
			os.Setenv(key, value)
		}
	}

	logDebug("成功加载配置文件: %s", filename)
}

// 设置日志
func setupLogging() {
	// 设置日志格式
	log.SetFlags(log.LstdFlags | log.Lshortfile)
}

// 日志函数
func logDebug(format string, v ...interface{}) {
	if config.DebugMode || config.LogLevel == DEBUG {
		log.Printf("[DEBUG] "+format, v...)
	}
}

func logInfo(format string, v ...interface{}) {
	if config.DebugMode || config.LogLevel == DEBUG || config.LogLevel == INFO {
		log.Printf("[INFO] "+format, v...)
	}
}

func logError(format string, v ...interface{}) {
	log.Printf("[ERROR] "+format, v...)
}

func logFatal(format string, v ...interface{}) {
	log.Fatalf("[FATAL] "+format, v...)
}

// validateAuthorization 验证请求的授权
func validateAuthorization(r *http.Request) bool {
	// 如果没有启用验证，直接通过
	if !config.AuthValidation {
		return true
	}

	// 如果允许的token列表为空，直接通过
	if len(config.AllowedTokens) == 0 {
		return true
	}

	// 获取Authorization头
	authHeader := r.Header.Get(config.DefaultAuthHeader)
	if authHeader == "" {
		logError("请求缺少%s头", config.DefaultAuthHeader)
		return false
	}

	// 解析Bearer token
	token := ""
	if strings.HasPrefix(strings.ToLower(authHeader), "bearer ") {
		token = strings.TrimSpace(authHeader[7:]) // 去掉"Bearer "
	} else {
		token = authHeader
	}

	// 验证token是否在允许列表中
	for _, allowedToken := range config.AllowedTokens {
		if allowedToken == token {
			return true
		}
	}

	// 调试模式下记录token（只记录前几位）
	if config.DebugMode {
		if len(token) > 8 {
			logError("未授权的token: %s...", token[:8])
		} else {
			logError("未授权的token: %s", token)
		}
	} else {
		logError("未授权的请求")
	}

	return false
}

// sendUnauthorizedResponse 发送未授权响应
func sendUnauthorizedResponse(w http.ResponseWriter, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("WWW-Authenticate", `Bearer realm="API"`)
	w.WriteHeader(http.StatusUnauthorized)

	response := map[string]string{
		"error":   "unauthorized",
		"message": message,
		"time":    time.Now().Format(time.RFC3339),
	}
	json.NewEncoder(w).Encode(response)
}

// proxyHandler 是核心的请求处理逻辑，根据b服务的响应来决定转发方式
func proxyHandler(w http.ResponseWriter, r *http.Request) {
	logInfo("收到请求: %s %s", r.Method, r.URL.Path)

	// 验证授权
	if !validateAuthorization(r) {
		sendUnauthorizedResponse(w, "Invalid or missing authorization token")
		return
	}

	// Debug模式记录详细请求信息
	if config.DebugMode {
		logRequestDetails(r)
	}

	// 1. 构建目标URL，使用原始请求的路径
	targetURL := config.TargetHost + r.URL.Path

	// 2. 创建转发请求
	// 注意：这里直接使用 r.Body，不需要预先读取和解析
	var bodyBytes []byte
	var err error

	if r.Body != nil {
		bodyBytes, err = io.ReadAll(r.Body)
		if err != nil {
			logError("读取请求体失败: %v", err)
			http.Error(w, "读取请求体失败", http.StatusInternalServerError)
			return
		}
		r.Body.Close()
	}

	// Debug模式记录请求体
	if config.DebugMode && len(bodyBytes) > 0 {
		logDebug("请求体: %s", formatJSON(bodyBytes))
	}

	req, err := http.NewRequest(r.Method, targetURL, bytes.NewReader(bodyBytes))
	if err != nil {
		logError("创建转发请求失败: %v", err)
		http.Error(w, "创建转发请求失败", http.StatusInternalServerError)
		return
	}

	// 3. 复制原始请求的Header（例如 Authorization, Content-Type等）
	copyHeaders(r.Header, req.Header)

	// 清除原有的Authorization头，添加配置的Authorization
	req.Header.Del("Authorization")
	req.Header.Add("Authorization", "Bearer "+config.AuthBearer)

	// 4. 发送请求到目标服务器
	client := &http.Client{
		Timeout: 60 * time.Second, // 设置超时时间
	}
	resp, err := client.Do(req)
	if err != nil {
		logError("转发请求失败: %v", err)
		http.Error(w, "转发请求失败", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	// Debug模式记录响应信息
	if config.DebugMode {
		logResponseDetails(resp)
	}

	// 5. 根据目标服务器的响应头决定如何转发
	contentType := resp.Header.Get("Content-Type")

	if strings.HasPrefix(strings.ToLower(contentType), "text/event-stream") {
		// 5a. 如果是SSE流，则进行流式转发
		logInfo("检测到目标服务器返回 'text/event-stream'，开始流式转发...")
		handleStreamResponse(w, resp)
	} else {
		// 5b. 否则，进行非流式转发
		logInfo("检测到目标服务器返回非流式内容，类型为 '%s'，开始普通转发...", contentType)
		handleNonStreamResponse(w, resp)
	}
}

// 记录请求详细信息
func logRequestDetails(r *http.Request) {
	logDebug("=== 请求详细信息 ===")
	logDebug("URL: %s", r.URL.String())
	logDebug("Method: %s", r.Method)
	logDebug("Protocol: %s", r.Proto)
	logDebug("Host: %s", r.Host)
	logDebug("Remote Addr: %s", r.RemoteAddr)

	logDebug("=== 请求Headers ===")
	for key, values := range r.Header {
		// 隐藏敏感信息
		if strings.ToLower(key) == "authorization" {
			logDebug("%s: [HIDDEN]", key)
		} else {
			logDebug("%s: %v", key, values)
		}
	}
}

// 记录响应详细信息
func logResponseDetails(resp *http.Response) {
	logDebug("=== 响应详细信息 ===")
	logDebug("Status Code: %d", resp.StatusCode)
	logDebug("Status: %s", resp.Status)
	logDebug("Protocol: %s", resp.Proto)

	logDebug("=== 响应Headers ===")
	for key, values := range resp.Header {
		logDebug("%s: %v", key, values)
	}
}

// 格式化JSON输出（单行输出）
func formatJSON(data []byte) string {
	// 直接返回原始JSON字符串，保持单行格式
	return string(data)
}

// handleNonStreamResponse 处理非流式响应
func handleNonStreamResponse(w http.ResponseWriter, resp *http.Response) {
	// 将目标服务器的响应头和状态码复制给客户端
	copyHeaders(resp.Header, w.Header())
	w.WriteHeader(resp.StatusCode)

	// 将响应体完整地复制给客户端
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		logError("读取响应体失败: %v", err)
		return
	}

	// Debug模式记录响应体
	if config.DebugMode && len(respBody) > 0 {
		logDebug("响应体: %s", formatJSON(respBody))
	}

	if _, err := w.Write(respBody); err != nil {
		logError("回写非流式响应体失败: %v", err)
	}

	logInfo("非流式响应转发完成")
}

// handleStreamResponse 处理流式响应
func handleStreamResponse(w http.ResponseWriter, resp *http.Response) {
	// 将目标服务器的响应头（如 Content-Type, Cache-Control）复制给客户端
	copyHeaders(resp.Header, w.Header())

	// 获取 Flusher 接口，用于实时发送数据
	flusher, ok := w.(http.Flusher)
	if !ok {
		logError("Error: ResponseWriter does not support flushing")
		http.Error(w, "Streaming unsupported", http.StatusInternalServerError)
		return
	}

	// 从目标服务器的响应流中逐行读取，并实时写入客户端
	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		line := scanner.Text()
		// Debug模式记录流数据
		if config.DebugMode {
			logDebug("流数据: %s", line)
		}
		// 直接按行转发，保持原始SSE格式
		fmt.Fprintln(w, line)
		flusher.Flush() // 关键：立即将数据发送给客户端
	}

	// 检查扫描过程中是否有错误
	if err := scanner.Err(); err != nil {
		logError("读取流数据时出错: %v", err)
	}

	logInfo("流式响应转发完成")
}

// copyHeaders 是一个辅助函数，用于复制HTTP Header
func copyHeaders(source http.Header, dest http.Header) {
	for key, values := range source {
		// 跳过一些不应被复制的Header
		if strings.ToLower(key) == "connection" || strings.ToLower(key) == "host" {
			continue
		}
		for _, value := range values {
			dest.Add(key, value)
		}
	}
}

// modelsHandler 处理 /v1/models 请求，支持缓存
func modelsHandler(w http.ResponseWriter, r *http.Request) {
	logInfo("收到 /v1/models 请求: %s %s", r.Method, r.URL.Path)

	// 验证授权
	if !validateAuthorization(r) {
		sendUnauthorizedResponse(w, "Invalid or missing authorization token")
		return
	}

	// 只处理 GET 请求
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// 检查缓存
	modelsCacheMu.RLock()
	if modelsCache != nil && time.Now().Before(modelsCache.ExpiresAt) {
		logInfo("使用缓存的 /v1/models 响应")

		// 复制缓存的响应头
		for key, values := range modelsCache.Headers {
			for _, value := range values {
				w.Header().Add(key, value)
			}
		}

		w.WriteHeader(modelsCache.StatusCode)
		w.Write(modelsCache.Data)
		modelsCacheMu.RUnlock()
		return
	}
	modelsCacheMu.RUnlock()

	// 缓存未命中或已过期，转发请求
	if config.DebugMode {
		logDebug("缓存未命中，转发请求到目标服务器")
	}

	forwardModelsRequest(w, r)
}

// forwardModelsRequest 转发 /v1/models 请求到目标服务器并缓存响应
func forwardModelsRequest(w http.ResponseWriter, r *http.Request) {
	targetURL := config.TargetHost + "/v1/models"

	// 创建转发请求
	req, err := http.NewRequest(r.Method, targetURL, r.Body)
	if err != nil {
		logError("创建转发请求失败: %v", err)
		http.Error(w, "创建转发请求失败", http.StatusInternalServerError)
		return
	}

	// 复制请求头
	copyHeaders(r.Header, req.Header)

	// 清除原有的Authorization头，添加配置的Authorization
	req.Header.Del("Authorization")
	req.Header.Add("Authorization", "Bearer "+config.AuthBearer)

	// 发送请求
	client := &http.Client{
		Timeout: 60 * time.Second,
	}
	resp, err := client.Do(req)
	if err != nil {
		logError("转发 /v1/models 请求失败: %v", err)
		http.Error(w, "转发请求失败", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	// Debug模式记录响应信息
	if config.DebugMode {
		logResponseDetails(resp)
	}

	// 读取响应数据
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		logError("读取 /v1/models 响应失败: %v", err)
		http.Error(w, "读取响应失败", http.StatusInternalServerError)
		return
	}

	// 缓存响应
	modelsCacheMu.Lock()
	headersCopy := make(map[string][]string)
	for key, values := range resp.Header {
		headersCopy[key] = make([]string, len(values))
		copy(headersCopy[key], values)
	}

	modelsCache = &CacheItem{
		Data:       make([]byte, len(respBody)),
		ExpiresAt:  time.Now().Add(cacheDuration),
		Headers:    headersCopy,
		StatusCode: resp.StatusCode,
	}
	copy(modelsCache.Data, respBody)
	modelsCacheMu.Unlock()

	logInfo("/v1/models 响应已缓存，过期时间: %v", time.Now().Add(cacheDuration))

	// 将响应返回给客户端
	for key, values := range headersCopy {
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}
	w.WriteHeader(resp.StatusCode)
	w.Write(respBody)

	logInfo("/v1/models 请求完成并缓存")
}

// clearCacheHandler 处理清除缓存的请求
func clearCacheHandler(w http.ResponseWriter, r *http.Request) {
	// 管理端点可选认证（如果启用了验证，则检查admin token）
	if config.AuthValidation {
		adminToken := os.Getenv("ADMIN_TOKEN")
		if adminToken != "" {
			authHeader := r.Header.Get(config.DefaultAuthHeader)
			token := ""
			if strings.HasPrefix(strings.ToLower(authHeader), "bearer ") {
				token = strings.TrimSpace(authHeader[7:])
			} else if authHeader != "" {
				token = authHeader
			}

			if token != adminToken {
				sendUnauthorizedResponse(w, "Admin token required")
				return
			}
		}
	}
	modelsCacheMu.Lock()
	modelsCache = nil
	modelsCacheMu.Unlock()

	logInfo("缓存已清除")

	response := map[string]string{
		"message": "缓存已成功清除",
		"time":    time.Now().Format(time.RFC3339),
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}
