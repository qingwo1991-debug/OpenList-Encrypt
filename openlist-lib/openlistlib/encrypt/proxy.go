package encrypt

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"path"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
	"golang.org/x/net/http2"
)

// 流式传输优化常量
const (
	// streamBufferSize 流传输缓冲区大小 (512KB)，优化大文件播放
	streamBufferSize = 512 * 1024
	// mediumBufferSize 中等文件缓冲区 (128KB)
	mediumBufferSize = 128 * 1024
	// smallBufferSize 小文件/API响应缓冲区 (32KB)
	smallBufferSize = 32 * 1024
	// prefetchBufferSize 视频预读缓冲区大小 (2MB)，优化快进体验
	prefetchBufferSize = 2 * 1024 * 1024
	// fileCacheTTL 文件信息缓存过期时间
	fileCacheTTL = 10 * time.Minute
	// fileCacheMaxSize 文件缓存最大条目数
	fileCacheMaxSize = 10000
	// redirectCacheTTL 重定向缓存过期时间
	redirectCacheTTL = 5 * time.Minute
	// parallelDecryptThreshold 并行解密文件名的阈值（降低以更早启用并行）
	parallelDecryptThreshold = 5
	// defaultParallelDecrypt 默认并行解密数（当无法获取 CPU 核心数时使用）
	defaultParallelDecrypt = 8
	// maxParallelDecryptLimit 最大并行解密数上限
	maxParallelDecryptLimit = 32
)

// 动态计算的并行解密数，根据 CPU 核心数自动调整
var maxParallelDecrypt = func() int {
	numCPU := runtime.NumCPU()
	if numCPU <= 0 {
		// 无法获取核心数，使用默认值
		return defaultParallelDecrypt
	}
	// 并发数 = CPU 核心数 * 2，范围 [4, maxParallelDecryptLimit]
	parallel := numCPU * 2
	if parallel < 4 {
		parallel = 4
	}
	if parallel > maxParallelDecryptLimit {
		parallel = maxParallelDecryptLimit
	}
	log.Infof("Auto-detected %d CPU cores, using %d parallel decrypt workers", numCPU, parallel)
	return parallel
}()

// 常见视频封面文件扩展名
var coverExtensions = map[string]bool{
	".jpg": true, ".jpeg": true, ".png": true,
	".webp": true, ".gif": true, ".bmp": true,
}

// 分级缓冲区池，根据文件大小选择合适的缓冲区
var (
	// largeBufferPool 大文件缓冲区池 (512KB)
	largeBufferPool = sync.Pool{
		New: func() interface{} {
			buf := make([]byte, streamBufferSize)
			return &buf
		},
	}
	// mediumBufferPool 中等文件缓冲区池 (128KB)
	mediumBufferPool = sync.Pool{
		New: func() interface{} {
			buf := make([]byte, mediumBufferSize)
			return &buf
		},
	}
	// smallBufferPool 小文件缓冲区池 (32KB)
	smallBufferPool = sync.Pool{
		New: func() interface{} {
			buf := make([]byte, smallBufferSize)
			return &buf
		},
	}
)

// ErrStopRedirect 用于停止自动重定向跟随
var ErrStopRedirect = errors.New("redirect stopped")

// RedirectInfo 重定向信息，用于缓存和代理重定向
type RedirectInfo struct {
	RedirectURL string       `json:"redirectUrl"` // 实际重定向目标
	PasswdInfo  *EncryptPath `json:"passwdInfo"`  // 加密配置
	FileSize    int64        `json:"fileSize"`    // 文件大小
	OriginalURL string       `json:"originalUrl"` // 原始请求URL
	Headers     http.Header  `json:"headers"`     // 原始请求头
}

// copyWithBuffer 使用大缓冲区池进行高效复制（用于流媒体）
func copyWithBuffer(dst io.Writer, src io.Reader) (int64, error) {
	bufPtr := largeBufferPool.Get().(*[]byte)
	defer largeBufferPool.Put(bufPtr)
	return io.CopyBuffer(dst, src, *bufPtr)
}

// copyWithSmallBuffer 使用小缓冲区池进行复制（用于小文件/API）
func copyWithSmallBuffer(dst io.Writer, src io.Reader) (int64, error) {
	bufPtr := smallBufferPool.Get().(*[]byte)
	defer smallBufferPool.Put(bufPtr)
	return io.CopyBuffer(dst, src, *bufPtr)
}

// copyWithAdaptiveBuffer 根据文件大小自适应选择缓冲区
func copyWithAdaptiveBuffer(dst io.Writer, src io.Reader, fileSize int64) (int64, error) {
	if fileSize <= 0 || fileSize > 10*1024*1024 { // 未知大小或大于 10MB
		return copyWithBuffer(dst, src)
	} else if fileSize > 1024*1024 { // 1MB - 10MB
		bufPtr := mediumBufferPool.Get().(*[]byte)
		defer mediumBufferPool.Put(bufPtr)
		return io.CopyBuffer(dst, src, *bufPtr)
	} else { // 小于 1MB
		return copyWithSmallBuffer(dst, src)
	}
}

// CachedFileInfo 带过期时间的文件信息缓存
type CachedFileInfo struct {
	Info     *FileInfo
	ExpireAt time.Time
}

// CachedRedirectInfo 带过期时间的重定向信息缓存
type CachedRedirectInfo struct {
	Info     *RedirectInfo
	ExpireAt time.Time
}

// EncryptPath 加密路径配置
type EncryptPath struct {
	Path     string         `json:"path"`     // 路径正则表达式
	Password string         `json:"password"` // 加密密码
	EncType  EncryptionType `json:"encType"`  // 加密类型
	EncName  bool           `json:"encName"`  // 是否加密文件名
	Enable   bool           `json:"enable"`   // 是否启用
	regex    *regexp.Regexp // 编译后的正则表达式
}

// ProxyConfig 代理配置
type ProxyConfig struct {
	AlistHost     string         `json:"alistHost"`     // Alist 服务地址
	AlistPort     int            `json:"alistPort"`     // Alist 服务端口
	AlistHttps    bool           `json:"alistHttps"`    // 是否使用 HTTPS
	ProxyPort     int            `json:"proxyPort"`     // 代理服务端口
	EncryptPaths  []*EncryptPath `json:"encryptPaths"`  // 加密路径配置
	AdminPassword string         `json:"adminPassword"` // 管理密码
	// ProbeOnDownload: attempt HEAD or Range=0-0 to discover remote file size when missing
	ProbeOnDownload bool `json:"probeOnDownload"`
	// EnableH2C: 启用 H2C (HTTP/2 Cleartext) 连接到后端，需要后端 OpenList 也开启 enable_h2c
	EnableH2C bool `json:"enableH2C"`
}

// ProxyServer 加密代理服务器
type ProxyServer struct {
	config         *ProxyConfig
	httpClient     *http.Client
	streamClient   *http.Client
	transport      *http.Transport
	h2cTransport   *http2.Transport // H2C Transport (如果启用)
	server         *http.Server
	running        bool
	mutex          sync.RWMutex
	fileCache      sync.Map // 文件信息缓存 (path -> *CachedFileInfo)
	fileCacheCount int64    // 缓存条目计数
	redirectCache  sync.Map // 重定向缓存 (key -> *CachedRedirectInfo)
	cleanupTicker  *time.Ticker
	cleanupDone    chan struct{}
}

// FileInfo 文件信息
type FileInfo struct {
	Name     string `json:"name"`
	Size     int64  `json:"size"`
	IsDir    bool   `json:"is_dir"`
	Modified string `json:"modified"`
	Path     string `json:"path"`
}

var (
// 保留全局 redirectCache 以兼容现有代码，但新代码使用 ProxyServer.redirectCache
)

// NewProxyServer 创建代理服务器
func NewProxyServer(config *ProxyConfig) (*ProxyServer, error) {
	if config == nil {
		return nil, errors.New("config cannot be nil")
	}

	// 编译路径正则表达式
	// 使用安全的通配符->正则转换：先 QuoteMeta 再恢复通配符
	wildcardToRegex := func(raw string) string {
		a := "__AST__"
		q := "__QST__"
		tmp := strings.ReplaceAll(raw, "*", a)
		tmp = strings.ReplaceAll(tmp, "?", q)
		tmp = regexp.QuoteMeta(tmp)
		tmp = strings.ReplaceAll(tmp, a, ".*")
		tmp = strings.ReplaceAll(tmp, q, ".")
		return tmp
	}

	for _, ep := range config.EncryptPaths {
		if ep.Path == "" {
			continue
		}
		raw := ep.Path
		// 处理以 /* 结尾的目录匹配
		if strings.HasSuffix(raw, "/*") {
			base := strings.TrimSuffix(raw, "/*")
			converted := wildcardToRegex(base)
			var pattern string
			if strings.HasPrefix(base, "/") {
				pattern = "^" + converted + "(/.*)?$"
			} else {
				pattern = "^/?" + converted + "(/.*)?$"
			}
			log.Infof("Init path %s -> regex pattern: %s", ep.Path, pattern)
			if reg, err := regexp.Compile(pattern); err == nil {
				ep.regex = reg
			} else {
				log.Warnf("Invalid path pattern: %s, error: %v", ep.Path, err)
			}
			continue
		}

		// 处理以 / 结尾的目录匹配（与 /* 类似，匹配目录及其子路径）
		if strings.HasSuffix(raw, "/") {
			base := strings.TrimSuffix(raw, "/")
			converted := wildcardToRegex(base)
			var pattern string
			if strings.HasPrefix(base, "/") {
				pattern = "^" + converted + "(/.*)?$"
			} else {
				pattern = "^/?" + converted + "(/.*)?$"
			}
			log.Infof("Init path %s -> regex pattern: %s", ep.Path, pattern)
			if reg, err := regexp.Compile(pattern); err == nil {
				ep.regex = reg
			} else {
				log.Warnf("Invalid path pattern: %s, error: %v", ep.Path, err)
			}
			continue
		}

		converted := wildcardToRegex(raw)
		var pattern string
		if strings.HasPrefix(raw, "^") {
			pattern = converted
		} else if strings.HasPrefix(raw, "/") {
			pattern = "^" + converted + "(/.*)?$"
		} else {
			pattern = "^/?" + converted + "(/.*)?$"
		}
		log.Infof("Init path %s -> regex pattern: %s", ep.Path, pattern)
		if reg, err := regexp.Compile(pattern); err == nil {
			ep.regex = reg
		} else {
			log.Warnf("Invalid path pattern: %s, error: %v", ep.Path, err)
		}
	}

	// ProbeOnDownload is controlled by configuration / frontend; do not override here.

	// 创建 Transport，支持 HTTP/2 over TLS
	transport := &http.Transport{
		MaxIdleConns:          200,               // 增加最大空闲连接
		MaxIdleConnsPerHost:   100,               // 增加每主机空闲连接（从50提升）
		MaxConnsPerHost:       200,               // 增加每主机最大连接（从100提升）
		IdleConnTimeout:       300 * time.Second, // 延长空闲超时（从120s提升到5分钟）
		DisableCompression:    true,              // 禁用压缩，减少 CPU 开销（视频流通常已压缩）
		ResponseHeaderTimeout: 60 * time.Second,  // 响应头超时（从30s提升）
		ForceAttemptHTTP2:     true,              // 启用 HTTP/2 (HTTPS)
		TLSClientConfig:       &tls.Config{},
		// 连接建立优化
		DialContext: (&net.Dialer{
			Timeout:   30 * time.Second, // 连接超时
			KeepAlive: 60 * time.Second, // TCP KeepAlive，防止连接被中间设备断开
		}).DialContext,
	}

	// 配置 HTTP/2 over TLS 支持
	if err := http2.ConfigureTransport(transport); err != nil {
		log.Warnf("Failed to configure HTTP/2: %v, falling back to HTTP/1.1", err)
	}

	var httpClient, streamClient *http.Client
	var h2cTransport *http2.Transport

	// 如果启用 H2C，创建支持 H2C 的客户端
	if config.EnableH2C {
		log.Info("H2C (HTTP/2 Cleartext) enabled for backend connections")
		// H2C Transport - 用于明文 HTTP/2
		h2cTransport = &http2.Transport{
			AllowHTTP: true, // 允许明文 HTTP
			DialTLSContext: func(ctx context.Context, network, addr string, cfg *tls.Config) (net.Conn, error) {
				// 对于 H2C，我们实际上是做普通的 TCP 连接
				var d net.Dialer
				return d.DialContext(ctx, network, addr)
			},
		}

		// 测试 H2C 连接是否可用
		testClient := &http.Client{Timeout: 5 * time.Second, Transport: h2cTransport}
		testURL := fmt.Sprintf("http://%s:%d/ping", config.AlistHost, config.AlistPort)
		resp, err := testClient.Get(testURL)
		if err != nil {
			log.Warnf("H2C connection test failed: %v, falling back to HTTP/1.1", err)
			// H2C 连接失败，回退到 HTTP/1.1
			h2cTransport = nil
			httpClient = &http.Client{
				Timeout:   30 * time.Second,
				Transport: transport,
				// 禁用自动重定向跟随，手动处理 302/303 重定向
				CheckRedirect: func(req *http.Request, via []*http.Request) error {
					return http.ErrUseLastResponse
				},
			}
			streamClient = &http.Client{
				Timeout:   0,
				Transport: transport,
				CheckRedirect: func(req *http.Request, via []*http.Request) error {
					return http.ErrUseLastResponse
				},
			}
		} else {
			resp.Body.Close()
			log.Info("H2C connection test successful")
			httpClient = &http.Client{
				Timeout:   30 * time.Second,
				Transport: h2cTransport,
				CheckRedirect: func(req *http.Request, via []*http.Request) error {
					return http.ErrUseLastResponse
				},
			}
			streamClient = &http.Client{
				Timeout:   0,
				Transport: h2cTransport,
				CheckRedirect: func(req *http.Request, via []*http.Request) error {
					return http.ErrUseLastResponse
				},
			}
		}
	} else {
		// 标准 HTTP/1.1 或 HTTP/2 over TLS
		// 禁用自动重定向跟随，手动处理 302/303 重定向
		httpClient = &http.Client{
			Timeout:   30 * time.Second,
			Transport: transport,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}
		streamClient = &http.Client{
			Timeout:   0,
			Transport: transport,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}
	}

	server := &ProxyServer{
		config:       config,
		transport:    transport,
		h2cTransport: h2cTransport,
		httpClient:   httpClient,
		streamClient: streamClient,
		cleanupDone:  make(chan struct{}),
	}

	// 启动缓存清理协程
	server.startCacheCleanup()

	return server, nil
}

// startCacheCleanup 启动定期缓存清理
func (p *ProxyServer) startCacheCleanup() {
	p.cleanupTicker = time.NewTicker(2 * time.Minute)
	go func() {
		for {
			select {
			case <-p.cleanupTicker.C:
				p.cleanupExpiredCache()
			case <-p.cleanupDone:
				return
			}
		}
	}()
}

// stopCacheCleanup 停止缓存清理
func (p *ProxyServer) stopCacheCleanup() {
	if p.cleanupTicker != nil {
		p.cleanupTicker.Stop()
	}
	if p.cleanupDone != nil {
		close(p.cleanupDone)
	}
}

// cleanupExpiredCache 清理过期的缓存条目
func (p *ProxyServer) cleanupExpiredCache() {
	now := time.Now()
	var deletedCount int64

	// 清理文件缓存
	p.fileCache.Range(func(key, value interface{}) bool {
		if cached, ok := value.(*CachedFileInfo); ok {
			if now.After(cached.ExpireAt) {
				p.fileCache.Delete(key)
				deletedCount++
			}
		}
		return true
	})

	// 清理重定向缓存
	p.redirectCache.Range(func(key, value interface{}) bool {
		if cached, ok := value.(*CachedRedirectInfo); ok {
			if now.After(cached.ExpireAt) {
				p.redirectCache.Delete(key)
			}
		}
		return true
	})

	if deletedCount > 0 {
		log.Debugf("Cache cleanup: removed %d expired file entries", deletedCount)
	}
}

// normalizeCacheKey 统一缓存键（对齐 alist-encrypt：decodeURIComponent）
func normalizeCacheKey(p string) string {
	if decoded, err := url.PathUnescape(p); err == nil {
		return decoded
	}
	return p
}

// storeFileCache 存储文件信息到缓存（带 TTL）
func (p *ProxyServer) storeFileCache(path string, info *FileInfo) {
	key := normalizeCacheKey(path)
	entry := &CachedFileInfo{
		Info:     info,
		ExpireAt: time.Now().Add(fileCacheTTL),
	}
	p.fileCache.Store(key, entry)
	// 兼容：也保存原始 key
	if key != path {
		p.fileCache.Store(path, entry)
	}
}

// loadFileCache 从缓存加载文件信息（检查 TTL）
func (p *ProxyServer) loadFileCache(path string) (*FileInfo, bool) {
	key := normalizeCacheKey(path)
	if value, ok := p.fileCache.Load(key); ok {
		if cached, ok := value.(*CachedFileInfo); ok {
			if time.Now().Before(cached.ExpireAt) {
				return cached.Info, true
			}
			// 过期了，删除
			p.fileCache.Delete(key)
		}
	}
	// 回退尝试原始 key
	if key != path {
		if value, ok := p.fileCache.Load(path); ok {
			if cached, ok := value.(*CachedFileInfo); ok {
				if time.Now().Before(cached.ExpireAt) {
					return cached.Info, true
				}
				p.fileCache.Delete(path)
			}
		}
	}
	return nil, false
}

// storeRedirectCache 存储重定向信息到缓存（带 TTL）
func (p *ProxyServer) storeRedirectCache(key string, info *RedirectInfo) {
	p.redirectCache.Store(key, &CachedRedirectInfo{
		Info:     info,
		ExpireAt: time.Now().Add(redirectCacheTTL),
	})
}

// loadRedirectCache 从缓存加载重定向信息（检查 TTL）
func (p *ProxyServer) loadRedirectCache(key string) (*RedirectInfo, bool) {
	if value, ok := p.redirectCache.Load(key); ok {
		if cached, ok := value.(*CachedRedirectInfo); ok {
			if time.Now().Before(cached.ExpireAt) {
				return cached.Info, true
			}
			// 过期了，删除
			p.redirectCache.Delete(key)
		}
	}
	return nil, false
}

// Start 启动代理服务器
func (p *ProxyServer) Start() error {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	if p.running {
		return errors.New("proxy server is already running")
	}

	mux := http.NewServeMux()

	// 路由配置
	mux.HandleFunc("/ping", p.handlePing)
	// 加密配置 API（供 App 前端的加密 tab 使用）
	mux.HandleFunc("/enc-api/getAlistConfig", p.handleConfig)
	mux.HandleFunc("/enc-api/saveAlistConfig", p.handleConfig)
	mux.HandleFunc("/enc-api/getUserInfo", p.handleUserInfo)
	mux.HandleFunc("/api/encrypt/config", p.handleConfig)
	mux.HandleFunc("/api/encrypt/restart", p.handleRestart)
	// 文件操作相关
	mux.HandleFunc("/redirect/", p.handleRedirect)
	mux.HandleFunc("/api/fs/list", p.handleFsList)
	mux.HandleFunc("/api/fs/get", p.handleFsGet)
	mux.HandleFunc("/api/fs/put", p.handleFsPut)
	// 下载和 WebDAV
	mux.HandleFunc("/d/", p.handleDownload)
	mux.HandleFunc("/p/", p.handleDownload)
	mux.HandleFunc("/dav/", p.handleWebDAV)
	mux.HandleFunc("/dav", p.handleWebDAV)
	// 根路径：直接代理到 OpenList (Alist)
	mux.HandleFunc("/", p.handleRoot)

	p.server = &http.Server{
		Addr:         fmt.Sprintf(":%d", p.config.ProxyPort),
		Handler:      mux,
		ReadTimeout:  0, // 视频流需要长连接
		WriteTimeout: 0,
		IdleTimeout:  300 * time.Second, // 5分钟空闲超时，防止后台连接被过早断开
	}

	go func() {
		log.Infof("Encrypt proxy server starting on port %d", p.config.ProxyPort)
		if err := p.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Errorf("Proxy server error: %v", err)
		}
	}()

	p.running = true
	return nil
}

// Stop 停止代理服务器
func (p *ProxyServer) Stop() error {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	if !p.running {
		return nil
	}

	// 停止缓存清理协程
	p.stopCacheCleanup()

	if p.server != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		if err := p.server.Shutdown(ctx); err != nil {
			log.Errorf("Error shutting down proxy server: %v", err)
			return err
		}
	}

	// 关闭 HTTP Transport 的连接池，确保重启时没有残留连接
	if p.transport != nil {
		p.transport.CloseIdleConnections()
	}

	// 关闭 H2C Transport 的连接池
	if p.h2cTransport != nil {
		p.h2cTransport.CloseIdleConnections()
	}

	p.running = false
	log.Info("Encrypt proxy server stopped")
	return nil
}

// IsRunning 检查是否运行中
func (p *ProxyServer) IsRunning() bool {
	p.mutex.RLock()
	defer p.mutex.RUnlock()
	return p.running
}

// UpdateConfig 更新配置（热更新）
func (p *ProxyServer) UpdateConfig(config *ProxyConfig) {
	// Compile regex BEFORE locking to avoid blocking reads too long?
	// Or just do it all under lock but ensure assignment is last.

	log.Infof("Updating Proxy Config with %d paths", len(config.EncryptPaths))

	// Re-compile regex first using the same safe wildcard->regex conversion as NewProxyServer
	wildcardToRegex := func(raw string) string {
		a := "__AST__"
		q := "__QST__"
		tmp := strings.ReplaceAll(raw, "*", a)
		tmp = strings.ReplaceAll(tmp, "?", q)
		tmp = regexp.QuoteMeta(tmp)
		tmp = strings.ReplaceAll(tmp, a, ".*")
		tmp = strings.ReplaceAll(tmp, q, ".")
		return tmp
	}

	for _, ep := range config.EncryptPaths {
		log.Infof("Compiling regex for path: %s", ep.Path)
		if ep.Path == "" {
			continue
		}
		raw := ep.Path
		if strings.HasSuffix(raw, "/*") {
			base := strings.TrimSuffix(raw, "/*")
			converted := wildcardToRegex(base)
			var pattern string
			if strings.HasPrefix(base, "/") {
				pattern = "^" + converted + "(/.*)?$"
			} else {
				pattern = "^/?" + converted + "(/.*)?$"
			}
			log.Infof("Path %s -> regex pattern: %s", ep.Path, pattern)
			if reg, err := regexp.Compile(pattern); err == nil {
				ep.regex = reg
			} else {
				log.Warnf("Invalid path pattern update: %s, error: %v", ep.Path, err)
			}
			continue
		}

		converted := wildcardToRegex(raw)
		var pattern string
		if strings.HasPrefix(raw, "^") {
			pattern = converted
		} else if strings.HasPrefix(raw, "/") {
			pattern = "^" + converted
		} else {
			pattern = "^/?" + converted
		}
		log.Infof("Path %s -> regex pattern: %s", ep.Path, pattern)
		if reg, err := regexp.Compile(pattern); err == nil {
			ep.regex = reg
		} else {
			log.Warnf("Invalid path pattern update: %s, error: %v", ep.Path, err)
		}
	}

	p.mutex.Lock()
	defer p.mutex.Unlock()
	p.config = config
	log.Infof("Proxy Config updated successfully")
}

// getAlistURL 获取 Alist 服务 URL
func (p *ProxyServer) getAlistURL() string {
	protocol := "http"
	if p.config.AlistHttps {
		protocol = "https"
	}
	return fmt.Sprintf("%s://%s:%d", protocol, p.config.AlistHost, p.config.AlistPort)
}

// probeRemoteFileSize 尝试通过 HEAD 或 Range 请求获取远程文件总大小，失败返回 0
func (p *ProxyServer) probeRemoteFileSize(targetURL string, headers http.Header) int64 {
	if p.config != nil && !p.config.ProbeOnDownload {
		return 0
	}
	// try HEAD first
	req, err := http.NewRequest("HEAD", targetURL, nil)
	if err == nil {
		for key, values := range headers {
			if key == "Host" {
				continue
			}
			for _, v := range values {
				req.Header.Add(key, v)
			}
		}
		resp, err := p.streamClient.Do(req)
		if err == nil {
			defer resp.Body.Close()
			if cl := resp.Header.Get("Content-Length"); cl != "" {
				if size, err := strconv.ParseInt(cl, 10, 64); err == nil && size > 0 {
					return size
				}
			}
			if cr := resp.Header.Get("Content-Range"); cr != "" {
				if idx := strings.LastIndex(cr, "/"); idx != -1 {
					totalStr := cr[idx+1:]
					if totalStr != "*" {
						if total, err := strconv.ParseInt(totalStr, 10, 64); err == nil && total > 0 {
							return total
						}
					}
				}
			}
		}
	}

	// fallback: request first byte to get Content-Range
	req2, err := http.NewRequest("GET", targetURL, nil)
	if err == nil {
		for key, values := range headers {
			if key == "Host" {
				continue
			}
			for _, v := range values {
				req2.Header.Add(key, v)
			}
		}
		req2.Header.Set("Range", "bytes=0-0")
		resp2, err := p.streamClient.Do(req2)
		if err == nil {
			defer resp2.Body.Close()
			if cr := resp2.Header.Get("Content-Range"); cr != "" {
				if idx := strings.LastIndex(cr, "/"); idx != -1 {
					totalStr := cr[idx+1:]
					if totalStr != "*" {
						if total, err := strconv.ParseInt(totalStr, 10, 64); err == nil && total > 0 {
							return total
						}
					}
				}
			}
			if cl := resp2.Header.Get("Content-Length"); cl != "" {
				if size, err := strconv.ParseInt(cl, 10, 64); err == nil && size > 0 {
					return size
				}
			}
		}
	}

	return 0
}

// fetchWebDAVFileSize 通过 PROPFIND 获取文件大小（Depth: 0）
func (p *ProxyServer) fetchWebDAVFileSize(targetURL string, headers http.Header) int64 {
	body := `<?xml version="1.0" encoding="utf-8" ?><D:propfind xmlns:D="DAV:"><D:prop><D:getcontentlength/></D:prop></D:propfind>`
	req, err := http.NewRequest("PROPFIND", targetURL, strings.NewReader(body))
	if err != nil {
		return 0
	}
	for key, values := range headers {
		if key == "Host" || strings.EqualFold(key, "Content-Length") {
			continue
		}
		for _, v := range values {
			req.Header.Add(key, v)
		}
	}
	req.Header.Set("Depth", "0")
	req.Header.Set("Content-Type", "application/xml; charset=utf-8")

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return 0
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return 0
	}

	dec := xml.NewDecoder(resp.Body)
	for {
		tok, err := dec.Token()
		if err != nil {
			return 0
		}
		switch t := tok.(type) {
		case xml.StartElement:
			if strings.EqualFold(t.Name.Local, "getcontentlength") {
				if t2, err := dec.Token(); err == nil {
					if cd, ok := t2.(xml.CharData); ok {
						s := strings.TrimSpace(string(cd))
						if s != "" {
							if v, err := strconv.ParseInt(s, 10, 64); err == nil && v > 0 {
								return v
							}
						}
					}
				}
			}
		}
	}
}

// processPropfindResponse 解析并替换 PROPFIND XML 中的 href/displayname，并缓存文件信息
func (p *ProxyServer) processPropfindResponse(body io.Reader, w io.Writer, encPath *EncryptPath) error {
	dec := xml.NewDecoder(body)
	enc := xml.NewEncoder(w)

	inResponse := false
	var curHref string
	var curHrefShow string
	var curSize int64 = -1

	for {
		t, err := dec.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}

		switch tok := t.(type) {
		case xml.StartElement:
			if strings.EqualFold(tok.Name.Local, "response") {
				inResponse = true
				curHref = ""
				curHrefShow = ""
				curSize = -1
			}
			if err := enc.EncodeToken(tok); err != nil {
				return err
			}

			if inResponse && strings.EqualFold(tok.Name.Local, "href") {
				t2, err := dec.Token()
				if err != nil {
					return err
				}
				if cd, ok := t2.(xml.CharData); ok {
					content := string(cd)
					decodedPath, err := url.PathUnescape(content)
					if err == nil {
						curHref = decodedPath
						curHrefShow = decodedPath
						fileName := path.Base(decodedPath)
						if fileName != "/" && fileName != "." && !strings.HasPrefix(fileName, "orig_") {
							// 仅对“看起来像文件”的名称进行解密（与 alist-encrypt 行为一致，避免误判目录）
							ext := path.Ext(fileName)
							if ext != "" {
								showName := ConvertShowName(encPath.Password, encPath.EncType, fileName)
								if showName != fileName && !strings.HasPrefix(showName, "orig_") {
									newPath := path.Join(path.Dir(decodedPath), showName)
									curHrefShow = newPath
									content = (&url.URL{Path: newPath}).EscapedPath()
								}
							}
						}
					}
					if err := enc.EncodeToken(xml.CharData([]byte(content))); err != nil {
						return err
					}
				} else {
					if err := enc.EncodeToken(t2); err != nil {
						return err
					}
				}
				continue
			}

			if inResponse && strings.EqualFold(tok.Name.Local, "displayname") {
				t2, err := dec.Token()
				if err != nil {
					return err
				}
				if cd, ok := t2.(xml.CharData); ok {
					content := string(cd)
					decodedName, err := url.PathUnescape(content)
					if err == nil {
						fileName := decodedName
						if fileName != "/" && fileName != "." && !strings.HasPrefix(fileName, "orig_") {
							ext := path.Ext(fileName)
							if ext != "" {
								showName := ConvertShowName(encPath.Password, encPath.EncType, fileName)
								if showName != fileName && !strings.HasPrefix(showName, "orig_") {
									content = showName
								}
							}
						}
					}
					if err := enc.EncodeToken(xml.CharData([]byte(content))); err != nil {
						return err
					}
				} else {
					if err := enc.EncodeToken(t2); err != nil {
						return err
					}
				}
				continue
			}

			if inResponse && strings.EqualFold(tok.Name.Local, "getcontentlength") {
				t2, err := dec.Token()
				if err != nil {
					return err
				}
				if cd, ok := t2.(xml.CharData); ok {
					s := strings.TrimSpace(string(cd))
					if s != "" {
						if v, err := strconv.ParseInt(s, 10, 64); err == nil {
							curSize = v
						}
					}
					if err := enc.EncodeToken(xml.CharData([]byte(s))); err != nil {
						return err
					}
				} else {
					if err := enc.EncodeToken(t2); err != nil {
						return err
					}
				}
				continue
			}

		case xml.EndElement:
			if err := enc.EncodeToken(tok); err != nil {
				return err
			}
			if inResponse && strings.EqualFold(tok.Name.Local, "response") {
				if curHref != "" {
					name := path.Base(curHref)
					isDir := false
					size := curSize
					if size <= 0 {
						isDir = true
						size = 0
					}
					// 使用带 TTL 的缓存（同时缓存密文与明文路径，便于 WebDAV GET 命中）
					p.storeFileCache(curHref, &FileInfo{Name: name, Size: size, IsDir: isDir, Path: curHref})
					if curHrefShow != "" && curHrefShow != curHref {
						p.storeFileCache(curHrefShow, &FileInfo{Name: path.Base(curHrefShow), Size: size, IsDir: isDir, Path: curHrefShow})
					}
				}
				inResponse = false
			}
		default:
			if err := enc.EncodeToken(tok); err != nil {
				return err
			}
		}
	}
	return enc.Flush()
}

// findEncryptPath 查找匹配的加密路径配置
func (p *ProxyServer) findEncryptPath(filePath string) *EncryptPath {
	p.mutex.RLock()
	defer p.mutex.RUnlock()

	log.Debugf("Checking encryption path for: %q (len=%d)", filePath, len(filePath))

	// 尝试 URL 解码，以防路径被编码
	decodedPath, err := url.PathUnescape(filePath)
	if err != nil {
		decodedPath = filePath
	}

	for _, ep := range p.config.EncryptPaths {
		if !ep.Enable {
			continue
		}
		if ep.regex != nil {
			log.Debugf("Testing rule %q (regex: %s) against %q", ep.Path, ep.regex.String(), filePath)
			if ep.regex.MatchString(filePath) {
				log.Infof("Matched rule: %s for %s (encType=%q, encName=%v)", ep.Path, filePath, ep.EncType, ep.EncName)
				return p.applyFolderOverride(ep, decodedPath)
			}
			if filePath != decodedPath && ep.regex.MatchString(decodedPath) {
				log.Infof("Matched rule (decoded): %s for %s (encType=%q, encName=%v)", ep.Path, decodedPath, ep.EncType, ep.EncName)
				return p.applyFolderOverride(ep, decodedPath)
			}
		} else {
			log.Warnf("Rule %s has nil regex", ep.Path)
		}
	}
	log.Debugf("No encryption path matched for: %q (decoded: %q)", filePath, decodedPath)
	return nil
}

// applyFolderOverride 按 alist-encrypt 逻辑解析目录名中的加密配置
func (p *ProxyServer) applyFolderOverride(ep *EncryptPath, filePath string) *EncryptPath {
	if ep == nil {
		return nil
	}
	folders := strings.Split(filePath, "/")
	for _, folder := range folders {
		if folder == "" {
			continue
		}
		decodedFolder, err := url.PathUnescape(folder)
		if err == nil {
			folder = decodedFolder
		}
		if encType, passwd, ok := DecodeFolderName(ep.Password, ep.EncType, folder); ok {
			newEp := *ep
			newEp.EncType = encType
			newEp.Password = passwd
			return &newEp
		}
	}
	return ep
}

// handlePing 处理 ping 请求
func (p *ProxyServer) handlePing(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":  "ok",
		"version": "1.0.0",
		"time":    time.Now().Unix(),
	})
}

// handleRestart 处理重启请求
func (p *ProxyServer) handleRestart(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"code":    200,
		"message": "Service will restart",
	})

	// 异步重启（给响应时间先返回）
	go func() {
		time.Sleep(500 * time.Millisecond)
		log.Info("Restarting encrypt proxy server...")
		// 实际重启逻辑需要在 encrypt_server.go 中实现
	}()
}

// handleRoot 处理根路径
func (p *ProxyServer) handleRoot(w http.ResponseWriter, r *http.Request) {
	log.Debugf("Handling root request: %s", r.URL.Path)
	// 直接代理到 OpenList (Alist)
	p.handleProxy(w, r)
}

// handleUserInfo 处理用户信息请求
func (p *ProxyServer) handleUserInfo(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	userInfo := map[string]interface{}{
		"username": "admin",
		"avatar":   "",
	}
	roles := []string{"admin"}
	codes := []string{}
	version := "0.1.0"
	json.NewEncoder(w).Encode(map[string]interface{}{
		"code": 200,
		"data": map[string]interface{}{
			"userInfo": userInfo,
			"roles":    roles,
			"codes":    codes,
			"version":  version,
		},
		// 兼容旧前端：直接返回顶层字段
		"userInfo": userInfo,
		"roles":    roles,
		"codes":    codes,
		"version":  version,
	})
}

// handleConfig 处理配置 API
func (p *ProxyServer) handleConfig(w http.ResponseWriter, r *http.Request) {
	// 支持 GET 返回当前配置，支持 POST 保存配置（兼容前端多种请求场景）
	if r.Method == http.MethodGet {
		// 转换为前端期望的格式
		passwdList := make([]map[string]interface{}, 0)
		for _, ep := range p.config.EncryptPaths {
			encType := string(ep.EncType)
			if encType == "aes-ctr" {
				encType = "aesctr"
			} else if encType == "rc4md5" {
				encType = "rc4"
			}

			passwdList = append(passwdList, map[string]interface{}{
				"encPath":  []string{ep.Path},
				"password": ep.Password,
				"encType":  encType,
				"encName":  ep.EncName,
				"enable":   ep.Enable,
			})
		}

		json.NewEncoder(w).Encode(map[string]interface{}{
			"code": 200,
			"data": map[string]interface{}{
				"alistHost":       p.config.AlistHost,
				"alistPort":       p.config.AlistPort,
				"https":           p.config.AlistHttps,
				"proxyPort":       p.config.ProxyPort,
				"passwdList":      passwdList,
				"probeOnDownload": p.config.ProbeOnDownload,
			},
		})
		return
	}

	if r.Method == http.MethodPost {
		// 尝试解析为通用保存结构：优先处理 encryptPaths（前端路径保存），其次处理 saveAlistConfig 兼容格式
		var bodyMap map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&bodyMap); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		// 更新 ProbeOnDownload 如果存在
		if v, ok := bodyMap["probeOnDownload"]; ok {
			if b, ok2 := v.(bool); ok2 {
				p.mutex.Lock()
				p.config.ProbeOnDownload = b
				p.mutex.Unlock()
			}
		}

		// 更新 Alist / Proxy 基本配置（如果前端提交）
		if v, ok := bodyMap["alistHost"]; ok {
			if s, ok2 := v.(string); ok2 {
				p.mutex.Lock()
				p.config.AlistHost = s
				p.mutex.Unlock()
			}
		}
		if v, ok := bodyMap["alistPort"]; ok {
			switch vt := v.(type) {
			case float64:
				p.mutex.Lock()
				p.config.AlistPort = int(vt)
				p.mutex.Unlock()
			case string:
				if port, err := strconv.Atoi(vt); err == nil {
					p.mutex.Lock()
					p.config.AlistPort = port
					p.mutex.Unlock()
				}
			}
		}
		if v, ok := bodyMap["alistHttps"]; ok {
			if b, ok2 := v.(bool); ok2 {
				p.mutex.Lock()
				p.config.AlistHttps = b
				p.mutex.Unlock()
			}
		}
		if v, ok := bodyMap["proxyPort"]; ok {
			switch vt := v.(type) {
			case float64:
				p.mutex.Lock()
				p.config.ProxyPort = int(vt)
				p.mutex.Unlock()
			case string:
				if port, err := strconv.Atoi(vt); err == nil {
					p.mutex.Lock()
					p.config.ProxyPort = port
					p.mutex.Unlock()
				}
			}
		}

		// 如果前端直接提交 encryptPaths（来自页面保存路径）
		if v, ok := bodyMap["encryptPaths"]; ok {
			if arr, ok2 := v.([]interface{}); ok2 {
				var newPaths []*EncryptPath
				for _, item := range arr {
					if m, ok3 := item.(map[string]interface{}); ok3 {
						pathStr, _ := m["path"].(string)
						pwd, _ := m["password"].(string)
						encTypeStr, _ := m["encType"].(string)
						encName, _ := m["encName"].(bool)
						enable, okEnable := m["enable"].(bool)
						if !okEnable {
							enable = true
						}
						var encType EncryptionType
						switch encTypeStr {
						case "aes-ctr", "aesctr":
							encType = EncTypeAESCTR
						case "rc4md5", "rc4":
							encType = EncTypeRC4
						case "mix":
							encType = EncTypeMix
						default:
							encType = EncryptionType(encTypeStr)
						}
						newPaths = append(newPaths, &EncryptPath{Path: pathStr, Password: pwd, EncType: encType, EncName: encName, Enable: enable})
					}
				}
				// assign and compile regex using safe wildcard->regex conversion
				wildcardToRegex := func(raw string) string {
					a := "__AST__"
					q := "__QST__"
					tmp := strings.ReplaceAll(raw, "*", a)
					tmp = strings.ReplaceAll(tmp, "?", q)
					tmp = regexp.QuoteMeta(tmp)
					tmp = strings.ReplaceAll(tmp, a, ".*")
					tmp = strings.ReplaceAll(tmp, q, ".")
					return tmp
				}

				p.mutex.Lock()
				p.config.EncryptPaths = newPaths
				for _, ep := range p.config.EncryptPaths {
					if ep.Path == "" {
						continue
					}
					raw := ep.Path
					if strings.HasSuffix(raw, "/*") {
						base := strings.TrimSuffix(raw, "/*")
						converted := wildcardToRegex(base)
						var pattern string
						if strings.HasPrefix(base, "/") {
							pattern = "^" + converted + "(/.*)?$"
						} else {
							pattern = "^/?" + converted + "(/.*)?$"
						}
						if reg, err := regexp.Compile(pattern); err == nil {
							ep.regex = reg
						}
						continue
					}

					converted := wildcardToRegex(raw)
					var pattern string
					if strings.HasPrefix(raw, "^") {
						pattern = converted
					} else if strings.HasPrefix(raw, "/") {
						pattern = "^" + converted
					} else {
						pattern = "^/?" + converted
					}
					if reg, err := regexp.Compile(pattern); err == nil {
						ep.regex = reg
					}
				}
				p.mutex.Unlock()
			}
		}

		// 兼容旧的 saveAlistConfig 格式（passwdList 等）
		if v, ok := bodyMap["passwdList"]; ok {
			if arr, ok2 := v.([]interface{}); ok2 {
				var newPaths []*EncryptPath
				for _, item := range arr {
					if m, ok3 := item.(map[string]interface{}); ok3 {
						// encPath may be array or string
						if epv, ok4 := m["encPath"]; ok4 {
							switch vv := epv.(type) {
							case string:
								parts := strings.Split(vv, ",")
								for _, pstr := range parts {
									pstr = strings.TrimSpace(pstr)
									if pstr == "" {
										continue
									}
									pwd, _ := m["password"].(string)
									encTypeStr, _ := m["encType"].(string)
									encName, _ := m["encName"].(bool)
									var encType EncryptionType
									switch encTypeStr {
									case "aesctr":
										encType = EncTypeAESCTR
									case "rc4":
										encType = EncTypeRC4
									case "mix":
										encType = EncTypeMix
									default:
										encType = EncryptionType(encTypeStr)
									}
									newPaths = append(newPaths, &EncryptPath{Path: pstr, Password: pwd, EncType: encType, EncName: encName, Enable: true})
								}
							case []interface{}:
								for _, epp := range vv {
									if s, ok5 := epp.(string); ok5 {
										pwd, _ := m["password"].(string)
										encTypeStr, _ := m["encType"].(string)
										encName, _ := m["encName"].(bool)
										var encType EncryptionType
										switch encTypeStr {
										case "aesctr":
											encType = EncTypeAESCTR
										case "rc4":
											encType = EncTypeRC4
										case "mix":
											encType = EncTypeMix
										default:
											encType = EncryptionType(encTypeStr)
										}
										newPaths = append(newPaths, &EncryptPath{Path: s, Password: pwd, EncType: encType, EncName: encName, Enable: true})
									}
								}
							}
						}
					}
				}
				// assign and compile regex using safe wildcard->regex conversion (same as above)
				wildcardToRegex := func(raw string) string {
					a := "__AST__"
					q := "__QST__"
					tmp := strings.ReplaceAll(raw, "*", a)
					tmp = strings.ReplaceAll(tmp, "?", q)
					tmp = regexp.QuoteMeta(tmp)
					tmp = strings.ReplaceAll(tmp, a, ".*")
					tmp = strings.ReplaceAll(tmp, q, ".")
					return tmp
				}

				p.mutex.Lock()
				p.config.EncryptPaths = newPaths
				for _, ep := range p.config.EncryptPaths {
					if ep.Path == "" {
						continue
					}
					raw := ep.Path
					if strings.HasSuffix(raw, "/*") {
						base := strings.TrimSuffix(raw, "/*")
						converted := wildcardToRegex(base)
						var pattern string
						if strings.HasPrefix(base, "/") {
							pattern = "^" + converted + "(/.*)?$"
						} else {
							pattern = "^/?" + converted + "(/.*)?$"
						}
						if reg, err := regexp.Compile(pattern); err == nil {
							ep.regex = reg
						}
						continue
					}
					converted := wildcardToRegex(raw)
					var pattern string
					if strings.HasPrefix(raw, "^") {
						pattern = converted
					} else if strings.HasPrefix(raw, "/") {
						pattern = "^" + converted
					} else {
						pattern = "^/?" + converted
					}
					if reg, err := regexp.Compile(pattern); err == nil {
						ep.regex = reg
					}
				}
				p.mutex.Unlock()
			}
		}

		json.NewEncoder(w).Encode(map[string]interface{}{"code": 200, "message": "Config updated"})
		return
	}

	http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
}

// handleRedirect 处理重定向下载
func (p *ProxyServer) handleRedirect(w http.ResponseWriter, r *http.Request) {
	// 获取重定向 key
	parts := strings.Split(r.URL.Path, "/")
	if len(parts) < 3 {
		http.Error(w, "Invalid redirect key", http.StatusBadRequest)
		return
	}
	key := parts[2]

	// 从缓存获取重定向信息（使用带 TTL 的缓存方法）
	info, ok := p.loadRedirectCache(key)
	if !ok {
		http.Error(w, "Redirect key not found or expired", http.StatusNotFound)
		return
	}

	log.Infof("handleRedirect: key=%s, fileSize=%d, encType=%s, url=%s",
		key, info.FileSize, info.PasswdInfo.EncType, info.RedirectURL)

	// 获取 Range 头
	rangeHeader := r.Header.Get("Range")
	var startPos int64 = 0
	if rangeHeader != "" {
		if strings.HasPrefix(rangeHeader, "bytes=") {
			rangeParts := strings.Split(strings.TrimPrefix(rangeHeader, "bytes="), "-")
			if len(rangeParts) >= 1 {
				startPos, _ = strconv.ParseInt(rangeParts[0], 10, 64)
			}
		}
		log.Infof("handleRedirect: Range header=%s, startPos=%d", rangeHeader, startPos)
	}

	// 创建到实际资源的请求
	req, err := http.NewRequest("GET", info.RedirectURL, nil)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// 复制请求头，但排除一些可能导致问题的头
	for key, values := range r.Header {
		lowerKey := strings.ToLower(key)
		// 不复制 Host 头
		if lowerKey == "host" {
			continue
		}
		// 阿里云盘不允许 referer，会返回 403
		if lowerKey == "referer" {
			continue
		}
		// authorization 是 alist 网页版的 token，不是存储的，删除它可以修复天翼云等无法获取资源的问题
		if lowerKey == "authorization" {
			continue
		}
		for _, value := range values {
			req.Header.Add(key, value)
		}
	}

	// 百度云盘需要特殊的 User-Agent
	if strings.Contains(info.RedirectURL, "baidupcs.com") {
		req.Header.Set("User-Agent", "pan.baidu.com")
	}

	// 发送请求
	// Use streamClient for downloads to avoid client-side timeouts for large/long streams
	resp, err := p.streamClient.Do(req)
	if err != nil {
		log.Errorf("handleRedirect: request failed: %v", err)
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	log.Infof("handleRedirect: response status=%d, content-length=%s",
		resp.StatusCode, resp.Header.Get("Content-Length"))

	statusCode := resp.StatusCode
	if resp.StatusCode == http.StatusOK && resp.Header.Get("Content-Range") != "" {
		statusCode = http.StatusPartialContent
	}

	// 复制响应头
	for key, values := range resp.Header {
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}

	// 下载时解密文件名（修改 Content-Disposition，与 alist-encrypt 一致）
	lastUrl := r.URL.Query().Get("lastUrl")
	if lastUrl != "" && info.PasswdInfo != nil && info.PasswdInfo.EncName {
		if decoded, err := url.QueryUnescape(lastUrl); err == nil {
			lastUrl = decoded
		}
		fileName := path.Base(lastUrl)
		if decoded, err := url.PathUnescape(fileName); err == nil {
			fileName = decoded
		}
		ext := path.Ext(fileName)
		baseName := strings.TrimSuffix(fileName, ext)
		decryptedName := DecodeName(info.PasswdInfo.Password, info.PasswdInfo.EncType, baseName)
		if decryptedName != "" {
			cd := w.Header().Get("Content-Disposition")
			if cd != "" {
				cd = regexp.MustCompile(`filename\*?=[^;]*;?\s*`).ReplaceAllString(cd, "")
			}
			if cd == "" {
				cd = "attachment; "
			} else if !strings.HasSuffix(cd, "; ") && !strings.HasSuffix(cd, ";") {
				cd += "; "
			}
			w.Header().Set("Content-Disposition", cd+fmt.Sprintf("filename*=UTF-8''%s", url.PathEscape(decryptedName)))
			log.Debugf("Decrypted filename in redirect Content-Disposition: %s -> %s", fileName, decryptedName)
		}
	}

	// 检查是否需要解密
	decode := r.URL.Query().Get("decode")
	if decode != "0" && info.PasswdInfo != nil {
		fileSize := info.FileSize

		// 如果 fileSize 为 0，尝试多种方式获取（修复 WebDAV 播放问题）
		if fileSize == 0 {
			// 1. 首先尝试从缓存中查找（使用多种路径变体）
			if info.OriginalURL != "" {
				origPath := info.OriginalURL
				if u, err := url.Parse(info.OriginalURL); err == nil {
					origPath = u.Path
				}
				// 尝试多种路径变体查找缓存
				pathVariants := []string{
					origPath,
					strings.TrimPrefix(origPath, "/dav"),
					"/dav" + strings.TrimPrefix(origPath, "/dav"),
				}
				for _, cachePath := range pathVariants {
					if cachePath == "" {
						continue
					}
					if cached, ok := p.loadFileCache(cachePath); ok && !cached.IsDir && cached.Size > 0 {
						fileSize = cached.Size
						log.Infof("handleRedirect: got fileSize from cache (%s): %d", cachePath, fileSize)
						break
					}
				}
			}

			// 2. 尝试从 Content-Range 获取总大小 (格式: bytes start-end/total)
			if fileSize == 0 {
				if cr := resp.Header.Get("Content-Range"); cr != "" {
					if idx := strings.LastIndex(cr, "/"); idx != -1 {
						totalStr := cr[idx+1:]
						if totalStr != "*" {
							if total, err := strconv.ParseInt(totalStr, 10, 64); err == nil && total > 0 {
								fileSize = total
								log.Infof("handleRedirect: got fileSize from Content-Range: %d", fileSize)
							}
						}
					}
				}
			}

			// 3. 如果 Content-Range 没有总大小，尝试 Content-Length（仅当没有 Range 请求时有效）
			if fileSize == 0 && rangeHeader == "" {
				if cl := resp.Header.Get("Content-Length"); cl != "" {
					if parsedSize, err := strconv.ParseInt(cl, 10, 64); err == nil && parsedSize > 0 {
						fileSize = parsedSize
						log.Infof("handleRedirect: using Content-Length as fileSize: %d", fileSize)
					}
				}
			}

			// 4. 尝试通过 WebDAV PROPFIND 获取文件大小
			if fileSize == 0 && info.OriginalURL != "" {
				origPath := info.OriginalURL
				if u, err := url.Parse(info.OriginalURL); err == nil {
					origPath = u.Path
				}
				// 构建 WebDAV URL
				webdavPath := origPath
				if !strings.HasPrefix(webdavPath, "/dav") {
					webdavPath = "/dav" + webdavPath
				}
				webdavURL := p.getAlistURL() + webdavPath
				if size := p.fetchWebDAVFileSize(webdavURL, info.Headers); size > 0 {
					fileSize = size
					log.Infof("handleRedirect: got fileSize from WebDAV PROPFIND: %d", fileSize)
				}
			}

			// 5. 如果仍然为 0，尝试探测远程文件大小（即使 ProbeOnDownload 未开启也尝试）
			if fileSize == 0 {
				probed := p.probeRemoteFileSize(info.RedirectURL, req.Header)
				if probed > 0 {
					fileSize = probed
					log.Infof("handleRedirect: probed remote fileSize=%d", fileSize)
					// 重新请求以获取新鲜的流
					resp.Body.Close()
					req2, _ := http.NewRequest("GET", info.RedirectURL, nil)
					for key, values := range r.Header {
						lowerKey := strings.ToLower(key)
						if lowerKey == "host" || lowerKey == "referer" || lowerKey == "authorization" {
							continue
						}
						for _, value := range values {
							req2.Header.Add(key, value)
						}
					}
					// 百度云盘需要特殊的 User-Agent
					if strings.Contains(info.RedirectURL, "baidupcs.com") {
						req2.Header.Set("User-Agent", "pan.baidu.com")
					}
					resp, err = p.streamClient.Do(req2)
					if err != nil {
						http.Error(w, err.Error(), http.StatusBadGateway)
						return
					}
					defer resp.Body.Close()
					// 重新复制响应头
					for key := range w.Header() {
						w.Header().Del(key)
					}
					for key, values := range resp.Header {
						for _, value := range values {
							w.Header().Add(key, value)
						}
					}
				}
			}
		}

		// 如果仍然为 0，跳过解密直接代理（记录更详细的警告信息）
		if fileSize == 0 {
			log.Warnf("handleRedirect: fileSize is 0, skipping decryption. originalURL=%s, redirectURL=%s", info.OriginalURL, info.RedirectURL)
			w.WriteHeader(statusCode)
			copyWithBuffer(w, resp.Body)
			return
		}

		// 创建解密器
		encryptor, err := NewFlowEncryptor(info.PasswdInfo.Password, info.PasswdInfo.EncType, fileSize)
		if err != nil {
			log.Errorf("handleRedirect: failed to create encryptor: %v", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		if startPos > 0 {
			encryptor.SetPosition(startPos)
		}

		// 创建解密读取器
		decryptReader := NewDecryptReader(resp.Body, encryptor)

		w.WriteHeader(statusCode)
		copyWithBuffer(w, decryptReader)
	} else {
		w.WriteHeader(statusCode)
		copyWithBuffer(w, resp.Body)
	}
}

// handleFsList 处理文件列表
func (p *ProxyServer) handleFsList(w http.ResponseWriter, r *http.Request) {
	log.Infof("Proxy handling fs list request")
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// 读取请求体
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// 转发请求到 Alist
	req, err := http.NewRequest("POST", p.getAlistURL()+"/api/fs/list", bytes.NewReader(body))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// 复制请求头
	for key, values := range r.Header {
		if key != "Host" {
			for _, value := range values {
				req.Header.Add(key, value)
			}
		}
	}

	resp, err := p.httpClient.Do(req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	// 解析响应（使用流式解码，避免将整个响应读入内存）
	var result map[string]interface{}
	var outBody []byte
	if err := json.NewDecoder(resp.Body).Decode(&result); err == nil {
		if code, ok := result["code"].(float64); ok && code == 200 {
			if data, ok := result["data"].(map[string]interface{}); ok {
				if content, ok := data["content"].([]interface{}); ok {
					var reqData map[string]string
					json.Unmarshal(body, &reqData)
					dirPath := reqData["path"]

					log.Infof("Handling fs list for path: %s", dirPath)

					// 收集需要解密的文件
					var decryptTasks []fileDecryptTask

					for i, item := range content {
						if fileMap, ok := item.(map[string]interface{}); ok {
							name, _ := fileMap["name"].(string)
							size, _ := fileMap["size"].(float64)
							isDir, _ := fileMap["is_dir"].(bool)

							// 优先使用 API 返回的 path 字段，如果没有则使用 dirPath + name
							filePath := path.Join(dirPath, name)
							if apiPath, ok := fileMap["path"].(string); ok && apiPath != "" {
								filePath = apiPath
							}

							// 缓存文件信息（使用带 TTL 的缓存）
							p.storeFileCache(filePath, &FileInfo{
								Name:  name,
								Size:  int64(size),
								IsDir: isDir,
								Path:  filePath,
							})

							// 为每个文件单独查找加密路径配置（与 alist-encrypt 行为一致）
							fileEncPath := p.findEncryptPath(filePath)

							// 收集需要解密文件名的文件
							if fileEncPath != nil && fileEncPath.EncName && !isDir {
								decryptTasks = append(decryptTasks, fileDecryptTask{
									index:    i,
									fileMap:  fileMap,
									name:     name,
									filePath: filePath,
									encPath:  fileEncPath, // 保存每个文件的加密配置
								})
							}
						}
					}

					// 并行解密文件名（当文件数超过阈值时）
					if len(decryptTasks) > 0 {
						if len(decryptTasks) >= parallelDecryptThreshold {
							// 使用并行解密
							p.parallelDecryptFileNamesV2(decryptTasks)
						} else {
							// 串行解密（文件数少时开销更小）
							for _, task := range decryptTasks {
								showName := ConvertShowName(task.encPath.Password, task.encPath.EncType, task.name)
								if showName != task.name && !strings.HasPrefix(showName, "orig_") {
									log.Debugf("Decrypt filename: %s -> %s", task.name, showName)
								}
								task.fileMap["name"] = showName
								// 同步更新 path，避免客户端使用密文 path
								if pathStr, ok := task.fileMap["path"].(string); ok && pathStr != "" {
									task.fileMap["path"] = path.Join(path.Dir(pathStr), showName)
								} else if task.filePath != "" {
									task.fileMap["path"] = path.Join(path.Dir(task.filePath), showName)
								}
							}
						}
					}

					// 封面自动隐藏：将与视频同名的图片设置为视频的 thumb
					p.processCoverFiles(content)

					result["data"] = data
					outBody, _ = json.Marshal(result)
				}
			}
		}
	}

	// 返回响应（若上面未能成功解析 JSON，则尝试原样流式转发）
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(resp.StatusCode)
	if len(outBody) > 0 {
		w.Write(outBody)
		return
	}
	// 如果没有构造好的 respBody，说明上面未进入 JSON 解析分支，直接将 resp.Body 内容拷贝到响应
	// 为了此处可读，需要先重-open resp.Body — 但 resp.Body 已在流式解码中消费或关闭，
	// 所以此分支通常不会被触达。作为保险，尝试写空体。
	return
}

// parallelDecryptFileNames 并行解密文件名（旧版本，使用统一的 encPath）
func (p *ProxyServer) parallelDecryptFileNames(tasks []fileDecryptTask, encPath *EncryptPath) {
	var wg sync.WaitGroup
	semaphore := make(chan struct{}, maxParallelDecrypt)

	for _, task := range tasks {
		wg.Add(1)
		go func(t fileDecryptTask) {
			defer wg.Done()
			semaphore <- struct{}{}        // 获取信号量
			defer func() { <-semaphore }() // 释放信号量

			showName := ConvertShowName(encPath.Password, encPath.EncType, t.name)
			if showName != t.name && !strings.HasPrefix(showName, "orig_") {
				log.Debugf("Parallel decrypt filename: %s -> %s", t.name, showName)
			}
			t.fileMap["name"] = showName
			if pathStr, ok := t.fileMap["path"].(string); ok && pathStr != "" {
				t.fileMap["path"] = path.Join(path.Dir(pathStr), showName)
			} else if t.filePath != "" {
				t.fileMap["path"] = path.Join(path.Dir(t.filePath), showName)
			}
		}(task)
	}
	wg.Wait()
}

// parallelDecryptFileNamesV2 并行解密文件名（新版本，每个文件使用自己的 encPath）
func (p *ProxyServer) parallelDecryptFileNamesV2(tasks []fileDecryptTask) {
	var wg sync.WaitGroup
	semaphore := make(chan struct{}, maxParallelDecrypt)

	for _, task := range tasks {
		wg.Add(1)
		go func(t fileDecryptTask) {
			defer wg.Done()
			semaphore <- struct{}{}        // 获取信号量
			defer func() { <-semaphore }() // 释放信号量

			if t.encPath == nil {
				return
			}
			showName := ConvertShowName(t.encPath.Password, t.encPath.EncType, t.name)
			if showName != t.name && !strings.HasPrefix(showName, "orig_") {
				log.Debugf("Parallel decrypt filename: %s -> %s", t.name, showName)
			}
			t.fileMap["name"] = showName
			if pathStr, ok := t.fileMap["path"].(string); ok && pathStr != "" {
				t.fileMap["path"] = path.Join(path.Dir(pathStr), showName)
			} else if t.filePath != "" {
				t.fileMap["path"] = path.Join(path.Dir(t.filePath), showName)
			}
		}(task)
	}
	wg.Wait()
}

// fileDecryptTask 文件解密任务
type fileDecryptTask struct {
	index    int
	fileMap  map[string]interface{}
	name     string
	filePath string
	encPath  *EncryptPath // 每个文件的加密配置
}

// 常见视频扩展名
var videoExtensions = map[string]bool{
	".mp4": true, ".mkv": true, ".avi": true, ".mov": true,
	".wmv": true, ".flv": true, ".webm": true, ".m4v": true,
	".ts": true, ".rmvb": true, ".rm": true, ".3gp": true,
}

// processCoverFiles 处理封面文件：将与视频同名的图片隐藏并设置为视频的 thumb
func (p *ProxyServer) processCoverFiles(content []interface{}) {
	// 构建视频文件名映射（不含扩展名 -> 文件信息）
	videoMap := make(map[string]map[string]interface{})
	coverFiles := make([]int, 0)

	for i, item := range content {
		if fileMap, ok := item.(map[string]interface{}); ok {
			name, _ := fileMap["name"].(string)
			isDir, _ := fileMap["is_dir"].(bool)
			if isDir || name == "" {
				continue
			}

			ext := strings.ToLower(path.Ext(name))
			baseName := strings.TrimSuffix(name, ext)

			if videoExtensions[ext] {
				videoMap[baseName] = fileMap
			} else if coverExtensions[ext] {
				coverFiles = append(coverFiles, i)
			}
		}
	}

	// 将封面文件与视频匹配
	omitIndices := make(map[int]bool)
	for _, idx := range coverFiles {
		if fileMap, ok := content[idx].(map[string]interface{}); ok {
			name, _ := fileMap["name"].(string)
			ext := strings.ToLower(path.Ext(name))
			baseName := strings.TrimSuffix(name, ext)

			// 查找同名视频
			if videoFileMap, exists := videoMap[baseName]; exists {
				// 设置视频的 thumb 为封面的 path
				if coverPath, ok := fileMap["path"].(string); ok && coverPath != "" {
					videoFileMap["thumb"] = coverPath
					omitIndices[idx] = true
					log.Debugf("Cover auto-hide: %s -> thumb for video %s", name, baseName)
				}
			}
		}
	}

	// 从列表中移除被隐藏的封面（从后向前删除以保持索引正确）
	if len(omitIndices) > 0 {
		// 注意：由于 content 是 []interface{}，我们不能直接修改切片长度
		// 但可以将隐藏的文件标记为 hidden
		for idx := range omitIndices {
			if fileMap, ok := content[idx].(map[string]interface{}); ok {
				fileMap["hidden"] = true
			}
		}
	}
}

// handleFsGet 处理获取文件信息
func (p *ProxyServer) handleFsGet(w http.ResponseWriter, r *http.Request) {
	log.Infof("Proxy handling fs get request")
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// 读取请求体
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	var reqData map[string]string
	if err := json.Unmarshal(body, &reqData); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	originalPath := reqData["path"]
	filePath := originalPath

	// 检查是否需要转换文件名
	encPath := p.findEncryptPath(filePath)
	if encPath != nil && encPath.EncName {
		// 尝试将显示名转换为真实加密名（ConvertRealName 会处理 orig_ 前缀）
		fileName := path.Base(filePath)
		if fileName != "/" && fileName != "." {
			realName := ConvertRealName(encPath.Password, encPath.EncType, filePath)
			filePath = path.Join(path.Dir(filePath), realName)
			reqData["path"] = filePath
			body, _ = json.Marshal(reqData)
		}
	}

	// 转发请求到 Alist
	req, err := http.NewRequest("POST", p.getAlistURL()+"/api/fs/get", bytes.NewReader(body))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// 复制请求头
	for key, values := range r.Header {
		if key != "Host" {
			for _, value := range values {
				req.Header.Add(key, value)
			}
		}
	}

	resp, err := p.httpClient.Do(req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	// 读取响应
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// 检查是否需要修改响应
	if encPath != nil {
		var result map[string]interface{}
		if err := json.Unmarshal(respBody, &result); err == nil {
			if data, ok := result["data"].(map[string]interface{}); ok {
				rawURL, _ := data["raw_url"].(string)
				size, _ := data["size"].(float64)

				log.Infof("handleFsGet: path=%s, size=%v, rawURL=%s", originalPath, size, rawURL)

				// 如果开启了文件名加密，将加密名转换为显示名
				if encPath.EncName {
					if name, ok := data["name"].(string); ok {
						showName := ConvertShowName(encPath.Password, encPath.EncType, name)
						data["name"] = showName
						if pathStr, ok := data["path"].(string); ok && pathStr != "" {
							data["path"] = path.Join(path.Dir(pathStr), showName)
						}
					}
				}

				// 创建重定向缓存（使用带 TTL 的缓存方法）
				key := generateRedirectKey()
				p.storeRedirectCache(key, &RedirectInfo{
					RedirectURL: rawURL,
					PasswdInfo:  encPath,
					FileSize:    int64(size),
					OriginalURL: originalPath,
				})

				// 修改返回的 URL
				scheme := "http"
				host := r.Host
				data["raw_url"] = fmt.Sprintf("%s://%s/redirect/%s?decode=1&lastUrl=%s",
					scheme, host, key, url.QueryEscape(originalPath))

				// 修改 provider 以支持直接播放
				if provider, ok := data["provider"].(string); ok {
					if provider == "AliyundriveOpen" {
						data["provider"] = "Local"
					}
				}

				result["data"] = data
				respBody, _ = json.Marshal(result)
			}
		}
	}

	// 返回响应
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(resp.StatusCode)
	w.Write(respBody)
}

// handleFsPut 处理文件上传请求
func (p *ProxyServer) handleFsPut(w http.ResponseWriter, r *http.Request) {
	log.Infof("Proxy handling fs put request")
	if r.Method != http.MethodPut {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	targetURL := p.getAlistURL() + r.URL.Path
	var body io.Reader = r.Body

	// 获取上传路径
	filePath := r.Header.Get("File-Path")
	if filePath == "" {
		// 尝试从 URL 参数获取 (有些客户端可能通过 URL 传参)
		filePath = r.URL.Query().Get("path")
	}

	// URL 解码
	decodedPath, err := url.PathUnescape(filePath)
	if err == nil {
		filePath = decodedPath
	}

	log.Infof("Uploading file to path: %s", filePath)

	// 检查是否需要加密
	encPath := p.findEncryptPath(filePath)

	// 记录原始文件名用于缓存
	originalFilePath := filePath

	// 如果开启了文件名加密，转换文件名（与 alist-encrypt 一致）
	if encPath != nil && encPath.EncName {
		fileName := path.Base(filePath)
		if fileName != "/" && fileName != "." {
			// alist-encrypt: const encName = encodeName(passwdInfo.password, passwdInfo.encType, fileName)
			// 然后 filePath = dirname + '/' + encName + ext
			ext := path.Ext(fileName)
			encName := EncodeName(encPath.Password, encPath.EncType, fileName)
			newFilePath := path.Join(path.Dir(filePath), encName+ext)
			log.Infof("Encrypting filename: %s -> %s", fileName, encName+ext)

			// 更新 File-Path header
			r.Header.Set("File-Path", url.PathEscape(newFilePath))

			// 更新 targetURL
			targetURL = p.getAlistURL() + "/api/fs/put"
		}
	}

	if encPath != nil {
		log.Infof("Encrypting upload for path: %s", filePath)
		contentLength := r.ContentLength
		if contentLength <= 0 {
			contentLength = 0
		}

		encryptor, err := NewFlowEncryptor(encPath.Password, encPath.EncType, contentLength)
		if err != nil {
			log.Errorf("Failed to create encryptor: %v", err)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}
		body = NewEncryptReader(r.Body, encryptor)

		// 缓存文件信息（与 alist-encrypt 一致：上传前缓存，便于 rclone 的 PROPFIND）
		p.storeFileCache(originalFilePath, &FileInfo{
			Name:  path.Base(originalFilePath),
			Size:  contentLength,
			IsDir: false,
			Path:  originalFilePath,
		})
	}

	req, err := http.NewRequest(r.Method, targetURL, body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// 复制请求头
	for key, values := range r.Header {
		if key != "Host" {
			for _, value := range values {
				req.Header.Add(key, value)
			}
		}
	}

	resp, err := p.httpClient.Do(req)
	if err != nil {
		log.Errorf("FsPut request failed: %v", err)
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	// 复制响应头
	for key, values := range resp.Header {
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}

	w.WriteHeader(resp.StatusCode)
	copyWithBuffer(w, resp.Body)
}

// handleDownload 处理下载请求
func (p *ProxyServer) handleDownload(w http.ResponseWriter, r *http.Request) {
	originalPath := r.URL.Path
	filePath := originalPath

	// 移除 /d/ 或 /p/ 前缀
	if strings.HasPrefix(filePath, "/d/") {
		filePath = strings.TrimPrefix(filePath, "/d/")
	} else if strings.HasPrefix(filePath, "/p/") {
		filePath = strings.TrimPrefix(filePath, "/p/")
	}
	filePath = "/" + filePath

	// 检查是否需要解密
	encPath := p.findEncryptPath(filePath)

	// 构建实际请求的 URL 路径
	actualURLPath := originalPath

	// 如果开启了文件名加密，转换为真实加密名
	if encPath != nil && encPath.EncName {
		fileName := path.Base(filePath)
		if fileName != "/" && fileName != "." {
			realName := ConvertRealName(encPath.Password, encPath.EncType, filePath)
			newFilePath := path.Join(path.Dir(filePath), realName)
			if strings.HasPrefix(originalPath, "/d/") {
				actualURLPath = "/d" + newFilePath
			} else {
				actualURLPath = "/p" + newFilePath
			}
		}
	}

	// 获取文件大小 - 首先尝试从缓存获取（使用带 TTL 的缓存方法）
	var fileSize int64 = 0
	if cached, ok := p.loadFileCache(filePath); ok {
		if !cached.IsDir && cached.Size > 0 {
			fileSize = cached.Size
		}
		log.Debugf("handleDownload: got fileSize from cache: %d for path: %s", fileSize, filePath)
	}
	if fileSize == 0 && encPath != nil && encPath.EncName {
		realName := ConvertRealName(encPath.Password, encPath.EncType, filePath)
		encPathFull := path.Join(path.Dir(filePath), realName)
		if !strings.HasPrefix(encPathFull, "/") {
			encPathFull = "/" + encPathFull
		}
		if cached, ok := p.loadFileCache(encPathFull); ok && !cached.IsDir && cached.Size > 0 {
			fileSize = cached.Size
			log.Debugf("handleDownload: got fileSize from enc cache: %d for path: %s", fileSize, encPathFull)
		}
	}

	// 创建到 Alist 的请求
	req, err := http.NewRequest(r.Method, p.getAlistURL()+actualURLPath, nil)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// 复制请求头
	for key, values := range r.Header {
		if key != "Host" {
			for _, value := range values {
				req.Header.Add(key, value)
			}
		}
	}

	resp, err := p.httpClient.Do(req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	// 处理 302/303 重定向：对于需要解密的路径，创建代理重定向
	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		location := resp.Header.Get("Location")
		log.Infof("handleDownload backend redirect: path=%s statusCode=%d location=%s",
			filePath, resp.StatusCode, location)

		if encPath != nil && encPath.Enable && location != "" {
			// 对于需要解密的 GET 请求，创建代理重定向
			// 生成唯一的重定向 key
			redirectKey := fmt.Sprintf("%d-%s", time.Now().UnixNano(), path.Base(filePath))

			// 缓存重定向信息
			redirectInfo := &RedirectInfo{
				RedirectURL: location,
				PasswdInfo:  encPath,
				FileSize:    fileSize,
				OriginalURL: r.URL.String(),
				Headers:     r.Header.Clone(),
			}
			p.storeRedirectCache(redirectKey, redirectInfo)

			// 构建代理重定向 URL
			proxyLocation := fmt.Sprintf("/redirect/%s?decode=1&lastUrl=%s",
				redirectKey, url.QueryEscape(r.URL.Path))

			log.Infof("handleDownload proxy redirect: path=%s, original=%s, proxy=%s, fileSize=%d",
				filePath, location, proxyLocation, fileSize)

			// 复制响应头（排除 Location）
			for key, values := range resp.Header {
				if strings.ToLower(key) == "location" {
					continue
				}
				for _, value := range values {
					w.Header().Add(key, value)
				}
			}

			// 返回修改后的重定向响应
			w.Header().Set("Location", proxyLocation)
			w.WriteHeader(resp.StatusCode)
			copyWithBuffer(w, resp.Body)
			return
		}

		// 对于不需要解密的请求，直接透传重定向
		for key, values := range resp.Header {
			for _, value := range values {
				w.Header().Add(key, value)
			}
		}
		w.WriteHeader(resp.StatusCode)
		copyWithBuffer(w, resp.Body)
		return
	}

	// 如果缓存中没有文件大小，尝试从响应头获取；如果仍然未知，探测远程总大小（HEAD 或 Range=0-0）
	if fileSize == 0 && encPath != nil {
		// Range 请求下 Content-Length 只是分片大小，不能用作总大小
		rangeHeader := r.Header.Get("Range")
		if rangeHeader == "" {
			if cl := resp.Header.Get("Content-Length"); cl != "" {
				if size, err := strconv.ParseInt(cl, 10, 64); err == nil && size > 0 {
					fileSize = size
					log.Infof("handleDownload: got fileSize from Content-Length: %d for path: %s", fileSize, filePath)
				}
			}
		}
		// 尝试从 Content-Range 获取总大小 (格式: bytes start-end/total)
		if fileSize == 0 {
			if cr := resp.Header.Get("Content-Range"); cr != "" {
				// Content-Range: bytes 0-1023/10240
				if idx := strings.LastIndex(cr, "/"); idx != -1 {
					totalStr := cr[idx+1:]
					if totalStr != "*" {
						if total, err := strconv.ParseInt(totalStr, 10, 64); err == nil && total > 0 {
							fileSize = total
							log.Infof("handleDownload: got fileSize from Content-Range: %d for path: %s", fileSize, filePath)
						}
					}
				}
			}
		}
		if fileSize == 0 {
			// try probe
			probed := p.probeRemoteFileSize(p.getAlistURL()+actualURLPath, req.Header)
			if probed > 0 {
				fileSize = probed
				log.Infof("handleDownload: probed remote fileSize=%d for path: %s", fileSize, filePath)
				// re-request resource to ensure fresh stream with streamClient
				resp.Body.Close()
				req2, _ := http.NewRequest(r.Method, p.getAlistURL()+actualURLPath, nil)
				for key, values := range r.Header {
					if key != "Host" {
						for _, value := range values {
							req2.Header.Add(key, value)
						}
					}
				}
				resp, err = p.streamClient.Do(req2)
				if err != nil {
					http.Error(w, err.Error(), http.StatusBadGateway)
					return
				}
				defer resp.Body.Close()
			}
		}
	}

	statusCode := resp.StatusCode
	if resp.StatusCode == http.StatusOK && resp.Header.Get("Content-Range") != "" {
		statusCode = http.StatusPartialContent
	}

	// 复制响应头
	for key, values := range resp.Header {
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}

	// 下载时解密文件名（修改 Content-Disposition，与 alist-encrypt 一致）
	if encPath != nil && encPath.EncName && resp.StatusCode == http.StatusOK {
		fileName := path.Base(filePath)
		if decoded, err := url.PathUnescape(fileName); err == nil {
			fileName = decoded
		}
		ext := path.Ext(fileName)
		baseName := strings.TrimSuffix(fileName, ext)
		decryptedName := DecodeName(encPath.Password, encPath.EncType, baseName)
		if decryptedName != "" {
			// 清除旧的 filename 参数，设置解密后的文件名
			cd := w.Header().Get("Content-Disposition")
			// 移除现有的 filename 和 filename* 参数
			if cd != "" {
				// 简单的正则替换：移除 filename=xxx 或 filename*=xxx
				cd = regexp.MustCompile(`filename\*?=[^;]*;?\s*`).ReplaceAllString(cd, "")
			}
			if cd == "" {
				cd = "attachment; "
			} else if !strings.HasSuffix(cd, "; ") && !strings.HasSuffix(cd, ";") {
				cd += "; "
			}
			w.Header().Set("Content-Disposition", cd+fmt.Sprintf("filename*=UTF-8''%s", url.PathEscape(decryptedName)))
			log.Debugf("Decrypted filename in Content-Disposition: %s -> %s", fileName, decryptedName)
		}
	}

	// 获取 Range 信息
	var startPos int64 = 0
	rangeHeader := r.Header.Get("Range")
	if rangeHeader != "" {
		if strings.HasPrefix(rangeHeader, "bytes=") {
			rangeParts := strings.Split(strings.TrimPrefix(rangeHeader, "bytes="), "-")
			if len(rangeParts) >= 1 {
				startPos, _ = strconv.ParseInt(rangeParts[0], 10, 64)
			}
		}
	}

	// 只有响应状态码是 2xx 时才尝试解密
	// 非 2xx 状态码（如 4xx、5xx 错误）直接透传，不尝试解密
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		log.Debugf("handleDownload: non-2xx response: status=%d, skip decryption", resp.StatusCode)
		w.WriteHeader(statusCode)
		copyWithBuffer(w, resp.Body)
		return
	}

	// 如果需要解密
	if encPath != nil && fileSize > 0 {
		log.Infof("handleDownload: decrypting with fileSize=%d for path: %s", fileSize, filePath)

		encryptor, err := NewFlowEncryptor(encPath.Password, encPath.EncType, fileSize)
		if err != nil {
			log.Errorf("handleDownload: failed to create encryptor: %v", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		if startPos > 0 {
			encryptor.SetPosition(startPos)
		}

		decryptReader := NewDecryptReader(resp.Body, encryptor)
		w.WriteHeader(statusCode)
		copyWithBuffer(w, decryptReader)
	} else if encPath != nil && fileSize == 0 {
		// fileSize 为 0 时无法正确解密（因为 fileSize 参与密钥生成）
		// 直接透传原始数据，让客户端知道这是加密的文件
		log.Warnf("handleDownload: cannot decrypt, fileSize is 0 for encrypted path: %s. Passing through raw data.", filePath)
		w.WriteHeader(statusCode)
		copyWithBuffer(w, resp.Body)
	} else {
		w.WriteHeader(statusCode)
		copyWithBuffer(w, resp.Body)
	}
}

// handleWebDAV 处理 WebDAV 请求
func (p *ProxyServer) handleWebDAV(w http.ResponseWriter, r *http.Request) {
	// 1. 查找加密配置
	filePath := r.URL.Path
	matchPath := filePath
	if strings.HasPrefix(matchPath, "/dav/") {
		matchPath = strings.TrimPrefix(matchPath, "/dav")
	} else if matchPath == "/dav" {
		matchPath = "/"
	}

	encPath := p.findEncryptPath(matchPath)
	if encPath == nil && matchPath != filePath {
		encPath = p.findEncryptPath(filePath)
	}

	// 记录 WebDAV 请求关键日志
	if encPath != nil {
		log.Infof("WebDAV: method=%s path=%s match=%s encName=%v", r.Method, filePath, matchPath, encPath.EncName)
	}

	// 2. 转换请求路径中的文件名 (Client明文 -> Server密文)
	targetURLPath := r.URL.Path
	fileName := path.Base(filePath)

	// 与 alist-encrypt 一致的逻辑：
	// - GET, PUT, DELETE, COPY, MOVE, HEAD, POST: 直接转换文件名
	// - PROPFIND: 只有当文件缓存中存在且不是目录时才转换
	//   这是因为 PROPFIND 既可能是请求目录列表，也可能是请求单个文件元数据
	//   alist-encrypt 使用 getFileInfo 查询缓存来判断
	methodNeedConvert := r.Method == "GET" || r.Method == "PUT" || r.Method == "DELETE" ||
		r.Method == "COPY" || r.Method == "MOVE" || r.Method == "HEAD" || r.Method == "POST"

	// PROPFIND 特殊处理：检查文件缓存来判断是否是文件
	if r.Method == "PROPFIND" && encPath != nil && encPath.EncName {
		// 先计算加密后的路径用于缓存查找
		// alist-encrypt: const realName = convertRealName(passwdInfo.password, passwdInfo.encType, url)
		//                const sourceUrl = path.dirname(url) + '/' + realName
		//                const sourceFileInfo = await getFileInfo(sourceUrl)
		if fileName != "/" && fileName != "." {
			realName := ConvertRealName(encPath.Password, encPath.EncType, filePath)
			// 缓存中存储的是完整路径（包含 /dav 前缀），所以查找时也用完整路径
			sourceUrl := path.Join(path.Dir(filePath), realName)
			if !strings.HasPrefix(sourceUrl, "/") {
				sourceUrl = "/" + sourceUrl
			}
			// 检查缓存：如果缓存中存在且不是目录，才转换 URL
			if cached, ok := p.loadFileCache(sourceUrl); ok && !cached.IsDir {
				log.Debugf("PROPFIND: found file in cache: %s (isDir=%v)", sourceUrl, cached.IsDir)
				methodNeedConvert = true
			} else {
				// 也尝试不带 /dav 前缀的路径
				sourceUrlNoPrefix := path.Join(path.Dir(matchPath), realName)
				if !strings.HasPrefix(sourceUrlNoPrefix, "/") {
					sourceUrlNoPrefix = "/" + sourceUrlNoPrefix
				}
				if cached, ok := p.loadFileCache(sourceUrlNoPrefix); ok && !cached.IsDir {
					log.Debugf("PROPFIND: found file in cache (no /dav): %s (isDir=%v)", sourceUrlNoPrefix, cached.IsDir)
					methodNeedConvert = true
				} else {
					log.Debugf("PROPFIND: not in cache or is dir: %s or %s", sourceUrl, sourceUrlNoPrefix)
				}
			}
		}
	}

	if methodNeedConvert && encPath != nil && encPath.EncName {
		if fileName != "/" && fileName != "." {
			realName := ConvertRealName(encPath.Password, encPath.EncType, filePath)
			newPath := path.Join(path.Dir(filePath), realName)
			// 确保路径以 / 开头
			if !strings.HasPrefix(newPath, "/") {
				newPath = "/" + newPath
			}
			targetURLPath = newPath
			log.Debugf("Convert real name URL (%s): %s -> %s", r.Method, r.URL.Path, targetURLPath)
		}
	}

	targetURL := p.getAlistURL() + targetURLPath
	if r.URL.RawQuery != "" {
		targetURL += "?" + r.URL.RawQuery
	}

	var body io.Reader = nil
	if r.Body != nil {
		body = r.Body
	}

	// 3. 处理 PUT 加密上传
	if r.Method == "PUT" && encPath != nil {
		contentLength := r.ContentLength
		// 尝试从 header 获取长度 (兼容 chunked transfer)
		if contentLength <= 0 {
			if l := r.Header.Get("X-Expected-Entity-Length"); l != "" {
				contentLength, _ = strconv.ParseInt(l, 10, 64)
			}
		}
		if contentLength <= 0 {
			if l := r.Header.Get("Content-Length"); l != "" {
				contentLength, _ = strconv.ParseInt(l, 10, 64)
			}
		}

		if contentLength > 0 {
			encryptor, err := NewFlowEncryptor(encPath.Password, encPath.EncType, contentLength)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			body = NewEncryptReader(r.Body, encryptor)

			// 缓存原始文件信息（与 alist-encrypt 一致：上传前缓存，便于 rclone 的 PROPFIND）
			originalFileName := path.Base(filePath)
			p.storeFileCache(filePath, &FileInfo{
				Name:  originalFileName,
				Size:  contentLength,
				IsDir: false,
				Path:  filePath,
			})
			// 同时缓存不带 /dav 前缀的路径
			if strings.HasPrefix(filePath, "/dav/") {
				noDav := strings.TrimPrefix(filePath, "/dav")
				p.storeFileCache(noDav, &FileInfo{
					Name:  originalFileName,
					Size:  contentLength,
					IsDir: false,
					Path:  noDav,
				})
			}
		} else {
			log.Warnf("PUT request encryption skipped: missing content length for %s", r.URL.Path)
		}
	}

	req, err := http.NewRequest(r.Method, targetURL, body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// 复制请求头
	for key, values := range r.Header {
		if key != "Host" {
			for _, value := range values {
				req.Header.Add(key, value)
			}
		}
	}

	// 4. 处理 Destination 头 (COPY/MOVE)
	if (r.Method == "COPY" || r.Method == "MOVE") && r.Header.Get("Destination") != "" {
		dest := r.Header.Get("Destination")
		u, err := url.Parse(dest)
		if err == nil {
			destPath := u.Path
			// 同样尝试去前缀匹配配置
			destMatchPath := destPath
			if strings.HasPrefix(destMatchPath, "/dav/") {
				destMatchPath = strings.TrimPrefix(destMatchPath, "/dav")
			} else if destMatchPath == "/dav" {
				destMatchPath = "/"
			}
			destEncPath := p.findEncryptPath(destMatchPath)
			if destEncPath == nil && destMatchPath != destPath {
				destEncPath = p.findEncryptPath(destPath)
			}

			// 如果目标路径需要加密文件名
			if destEncPath != nil && destEncPath.EncName {
				destName := path.Base(destPath)
				if destName != "/" && destName != "." {
					realDestName := ConvertRealName(destEncPath.Password, destEncPath.EncType, destPath)
					newDestPath := path.Join(path.Dir(destPath), realDestName)
					if !strings.HasPrefix(newDestPath, "/") {
						newDestPath = "/" + newDestPath
					}
					destPath = newDestPath
					log.Debugf("Convert real name Destination: %s -> %s", u.Path, destPath)
				}
			}

			// 重组 Destination
			newDest := p.getAlistURL() + destPath
			req.Header.Set("Destination", newDest)
		}
	}

	// 备份 Body 以便可能的重试 (针对 PROPFIND)
	var reqBodyBytes []byte
	if r.Method == "PROPFIND" && r.Body != nil {
		reqBodyBytes, _ = io.ReadAll(r.Body)
		// 恢复原始 req 的 Body (如果之前读取过)
		// 注意：这里的 r.Body 已经被 upstream passed to NewRequest.
		// 我们需要确保 req.Body 是可读的。
		// 在 NewRequest 时如果传入了 body io.Reader，它会被赋给 req.Body.
		// 如果 body 之前是 r.Body (http.Request)，它可能只能读一次。
		// 我们前面: if r.Body != nil { body = r.Body }
		// 所以 req.Body 指向了 socket。如果读得动的话。
		// 为了安全，我们最好在这里用 bytes 重建 req.Body
		if len(reqBodyBytes) > 0 {
			req.Body = io.NopCloser(bytes.NewReader(reqBodyBytes))
		}
	}

	resp, err := p.httpClient.Do(req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}

	// 添加调试日志：记录后端响应状态码和内容长度
	log.Infof("WebDAV backend response: method=%s path=%s statusCode=%d contentLength=%s contentType=%s",
		r.Method, filePath, resp.StatusCode, resp.Header.Get("Content-Length"), resp.Header.Get("Content-Type"))

	// PROPFIND 404 重试机制 (因为我们不知道请求的是目录还是加密文件)
	// 如果默认透传 (当作目录) 失败，尝试加密文件名再试 (当作文件)
	if r.Method == "PROPFIND" && resp.StatusCode == 404 && encPath != nil && encPath.EncName {
		// 关闭旧响应体
		resp.Body.Close()

		// 重新计算加密路径
		fileName := path.Base(filePath)
		if fileName != "/" && fileName != "." {
			realName := ConvertRealName(encPath.Password, encPath.EncType, filePath)
			newPath := path.Join(path.Dir(filePath), realName)
			if !strings.HasPrefix(newPath, "/") {
				newPath = "/" + newPath
			}
			log.Debugf("PROPFIND 404 retry with encrypt path: %s -> %s", filePath, newPath)

			retryTargetURL := p.getAlistURL() + newPath
			if r.URL.RawQuery != "" {
				retryTargetURL += "?" + r.URL.RawQuery
			}

			var retryBody io.Reader
			if len(reqBodyBytes) > 0 {
				retryBody = bytes.NewReader(reqBodyBytes)
			}

			retryReq, _ := http.NewRequest(r.Method, retryTargetURL, retryBody)
			// Copy headers
			for key, values := range r.Header {
				if key != "Host" {
					for _, value := range values {
						retryReq.Header.Add(key, value)
					}
				}
			}

			resp, err = p.httpClient.Do(retryReq)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadGateway)
				return
			}
		}
	}
	defer resp.Body.Close()

	// 5. 处理 PROPFIND 响应 (文件名解密)
	if r.Method == "PROPFIND" && encPath != nil && encPath.EncName {
		// Remove Content-Length so Go will use chunked transfer when streaming the modified output.
		for key, values := range resp.Header {
			if strings.ToLower(key) == "content-length" {
				continue
			}
			for _, v := range values {
				w.Header().Add(key, v)
			}
		}
		w.WriteHeader(resp.StatusCode)

		if err := p.processPropfindResponse(resp.Body, w, encPath); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
		return
	}

	// 复制响应头（排除 Location，后面可能需要修改）
	for key, values := range resp.Header {
		lowerKey := strings.ToLower(key)
		// 暂不复制 Location，后面处理重定向时可能需要修改
		if lowerKey == "location" {
			continue
		}
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}

	statusCode := resp.StatusCode
	if resp.StatusCode == http.StatusOK && resp.Header.Get("Content-Range") != "" {
		statusCode = http.StatusPartialContent
	}

	// 处理 302/303 重定向：对于需要解密的路径，创建代理重定向
	// 这模拟了 alist-encrypt 的行为，拦截重定向并通过 /redirect/ 端点处理
	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		location := resp.Header.Get("Location")
		log.Infof("WebDAV backend redirect: method=%s path=%s statusCode=%d location=%s",
			r.Method, filePath, resp.StatusCode, location)

		if r.Method == "GET" && encPath != nil && encPath.Enable && location != "" {
			// 对于需要解密的 GET 请求，创建代理重定向
			// 尝试获取文件大小（从缓存或响应头）
			var fileSize int64 = 0
			if cached, ok := p.loadFileCache(filePath); ok && !cached.IsDir && cached.Size > 0 {
				fileSize = cached.Size
			} else if strings.HasPrefix(filePath, "/dav/") {
				noDav := strings.TrimPrefix(filePath, "/dav")
				if cached, ok := p.loadFileCache(noDav); ok && !cached.IsDir && cached.Size > 0 {
					fileSize = cached.Size
				}
			}
			// 也尝试用密文路径查缓存
			if fileSize == 0 && encPath.EncName {
				realName := ConvertRealName(encPath.Password, encPath.EncType, filePath)
				encPathFull := path.Join(path.Dir(filePath), realName)
				if !strings.HasPrefix(encPathFull, "/") {
					encPathFull = "/" + encPathFull
				}
				if cached, ok := p.loadFileCache(encPathFull); ok && !cached.IsDir && cached.Size > 0 {
					fileSize = cached.Size
				}
			}

			// 如果缓存中没有 fileSize，尝试通过 PROPFIND 获取（修复 WebDAV 播放问题）
			if fileSize == 0 {
				propfindURL := targetURL
				if size := p.fetchWebDAVFileSize(propfindURL, r.Header); size > 0 {
					fileSize = size
					log.Infof("WebDAV redirect: got fileSize from PROPFIND: %d for %s", fileSize, filePath)
					// 缓存文件大小
					p.storeFileCache(filePath, &FileInfo{Name: path.Base(filePath), Size: size, IsDir: false, Path: filePath})
					if strings.HasPrefix(filePath, "/dav/") {
						noDav := strings.TrimPrefix(filePath, "/dav")
						p.storeFileCache(noDav, &FileInfo{Name: path.Base(noDav), Size: size, IsDir: false, Path: noDav})
					}
				}
			}

			// 如果 PROPFIND 也获取不到，尝试探测远程文件大小
			if fileSize == 0 {
				probed := p.probeRemoteFileSize(location, r.Header)
				if probed > 0 {
					fileSize = probed
					log.Infof("WebDAV redirect: probed remote fileSize: %d for %s", fileSize, filePath)
				}
			}

			// 生成唯一的重定向 key
			redirectKey := fmt.Sprintf("%d-%s", time.Now().UnixNano(), path.Base(filePath))

			// 缓存重定向信息
			redirectInfo := &RedirectInfo{
				RedirectURL: location,
				PasswdInfo:  encPath,
				FileSize:    fileSize,
				OriginalURL: r.URL.String(),
				Headers:     r.Header.Clone(),
			}
			p.storeRedirectCache(redirectKey, redirectInfo)

			// 构建代理重定向 URL
			proxyLocation := fmt.Sprintf("/redirect/%s?decode=1&lastUrl=%s",
				redirectKey, url.QueryEscape(r.URL.Path))

			log.Infof("WebDAV proxy redirect: path=%s, original=%s, proxy=%s, fileSize=%d",
				filePath, location, proxyLocation, fileSize)

			// 返回修改后的重定向响应
			w.Header().Set("Location", proxyLocation)
			w.WriteHeader(resp.StatusCode)
			copyWithBuffer(w, resp.Body)
			return
		}

		// 对于不需要解密的请求，直接透传重定向
		w.Header().Set("Location", location)
		w.WriteHeader(statusCode)
		copyWithBuffer(w, resp.Body)
		return
	}

	// 6. 处理 GET 下载解密
	if r.Method == "GET" && encPath != nil {
		// 只有响应状态码是 2xx 时才尝试解密
		// 非 2xx 状态码（如 4xx、5xx 错误）直接透传，不尝试解密
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			log.Debugf("WebDAV GET non-2xx response: status=%d, skip decryption", resp.StatusCode)
			w.WriteHeader(statusCode)
			copyWithBuffer(w, resp.Body)
			return
		}

		// 检查 Content-Type，避免解密错误页面或目录列表
		contentType := resp.Header.Get("Content-Type")
		if strings.Contains(contentType, "text/html") ||
			strings.Contains(contentType, "application/json") ||
			strings.Contains(contentType, "application/xml") {
			w.WriteHeader(statusCode)
			copyWithBuffer(w, resp.Body)
			return
		}

		// 尝试从缓存获取文件大小（WebDAV PROPFIND 已缓存）
		var fileSize int64 = 0
		if cached, ok := p.loadFileCache(filePath); ok && !cached.IsDir && cached.Size > 0 {
			fileSize = cached.Size
		} else {
			// 兼容不带 /dav 前缀的缓存键
			if strings.HasPrefix(filePath, "/dav/") {
				noDav := strings.TrimPrefix(filePath, "/dav")
				if cached, ok := p.loadFileCache(noDav); ok && !cached.IsDir && cached.Size > 0 {
					fileSize = cached.Size
				}
			}
		}

		// 进一步尝试：使用密文路径查缓存（对齐 alist-encrypt 的重试逻辑）
		if fileSize == 0 && encPath != nil && encPath.EncName {
			realName := ConvertRealName(encPath.Password, encPath.EncType, filePath)
			encPathFull := path.Join(path.Dir(filePath), realName)
			if !strings.HasPrefix(encPathFull, "/") {
				encPathFull = "/" + encPathFull
			}
			if cached, ok := p.loadFileCache(encPathFull); ok && !cached.IsDir && cached.Size > 0 {
				fileSize = cached.Size
			} else if strings.HasPrefix(encPathFull, "/dav/") {
				noDav := strings.TrimPrefix(encPathFull, "/dav")
				if cached, ok := p.loadFileCache(noDav); ok && !cached.IsDir && cached.Size > 0 {
					fileSize = cached.Size
				}
			}
		}

		// 尝试获取文件大小
		contentRange := resp.Header.Get("Content-Range")
		if contentRange != "" {
			// 格式: bytes start-end/total
			parts := strings.Split(contentRange, "/")
			if len(parts) == 2 {
				if total, err := strconv.ParseInt(parts[1], 10, 64); err == nil {
					fileSize = total
				}
			}
		}

		// Range 请求下 Content-Length 只是分片大小，不能用作总大小
		rangeHeader := r.Header.Get("Range")
		if fileSize == 0 && rangeHeader == "" {
			if cl := resp.Header.Get("Content-Length"); cl != "" {
				fileSize, _ = strconv.ParseInt(cl, 10, 64)
			}
		}

		// 如果仍然未知，先尝试 WebDAV PROPFIND 获取大小
		if fileSize == 0 {
			if size := p.fetchWebDAVFileSize(targetURL, req.Header); size > 0 {
				fileSize = size
				p.storeFileCache(filePath, &FileInfo{Name: path.Base(filePath), Size: size, IsDir: false, Path: filePath})
				if strings.HasPrefix(filePath, "/dav/") {
					noDav := strings.TrimPrefix(filePath, "/dav")
					p.storeFileCache(noDav, &FileInfo{Name: path.Base(noDav), Size: size, IsDir: false, Path: noDav})
				}
				log.Infof("handleWebDAV: propfind fileSize=%d for %s", fileSize, targetURL)
			}
		}

		// 如果仍然未知，尝试探测远程总大小
		if fileSize == 0 && p.config != nil && p.config.ProbeOnDownload {
			probed := p.probeRemoteFileSize(targetURL, req.Header)
			if probed > 0 {
				fileSize = probed
				log.Infof("handleWebDAV: probed remote fileSize=%d for %s", fileSize, targetURL)
			}
		}

		// 只有当服务端返回了内容，且知道大小，才解密
		if fileSize > 0 {
			var startPos int64 = 0
			if rangeHeader != "" {
				if strings.HasPrefix(rangeHeader, "bytes=") {
					rangeParts := strings.Split(strings.TrimPrefix(rangeHeader, "bytes="), "-")
					if len(rangeParts) >= 1 {
						startPos, _ = strconv.ParseInt(rangeParts[0], 10, 64)
					}
				}
			}

			log.Infof("WebDAV decrypt: path=%s range=%q content-range=%q content-length=%q fileSize=%d start=%d",
				filePath, rangeHeader, resp.Header.Get("Content-Range"), resp.Header.Get("Content-Length"), fileSize, startPos)

			encryptor, err := NewFlowEncryptor(encPath.Password, encPath.EncType, fileSize)
			if err != nil {
				// 无法创建解密器(如未知算法)，直接透传
				log.Warnf("Failed to create encryptor for download: %v", err)
				w.WriteHeader(statusCode)
				copyWithBuffer(w, resp.Body)
				return
			}

			if startPos > 0 {
				encryptor.SetPosition(startPos)
			}

			decryptReader := NewDecryptReader(resp.Body, encryptor)
			w.WriteHeader(statusCode)
			copyWithBuffer(w, decryptReader)
			return
		}
	}

	w.WriteHeader(statusCode)
	copyWithBuffer(w, resp.Body)
}

// handleProxy 处理通用代理请求
func (p *ProxyServer) handleProxy(w http.ResponseWriter, r *http.Request) {
	targetURL := p.getAlistURL() + r.URL.Path
	if r.URL.RawQuery != "" {
		targetURL += "?" + r.URL.RawQuery
	}

	log.Debugf("Proxying %s %s to %s", r.Method, r.URL.Path, targetURL)

	req, err := http.NewRequest(r.Method, targetURL, r.Body)
	if err != nil {
		log.Errorf("Failed to create request: %v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// 复制请求头
	for key, values := range r.Header {
		if key != "Host" && key != "Accept-Encoding" {
			for _, value := range values {
				req.Header.Add(key, value)
			}
		}
	}

	resp, err := p.httpClient.Do(req)
	if err != nil {
		log.Errorf("Proxy request failed: %v", err)
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	log.Debugf("Proxy response status: %d", resp.StatusCode)

	// 复制响应头
	for key, values := range resp.Header {
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}

	w.WriteHeader(resp.StatusCode)

	// 直接复制响应体，不做 HTML 注入（加密配置已移至 App 前端）
	copyWithBuffer(w, resp.Body)
}

// generateRedirectKey 生成重定向 key
func generateRedirectKey() string {
	return fmt.Sprintf("%d%d", time.Now().UnixNano(), time.Now().UnixNano()%1000000)
}
