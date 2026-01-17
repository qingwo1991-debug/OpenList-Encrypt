package encrypt

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/OpenListTeam/OpenList/v4/public"
	log "github.com/sirupsen/logrus"
)

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
}

// ProxyServer 加密代理服务器
type ProxyServer struct {
	config     *ProxyConfig
	httpClient *http.Client
	server     *http.Server
	running    bool
	mutex      sync.RWMutex
	fileCache  sync.Map // 文件信息缓存
}

// FileInfo 文件信息
type FileInfo struct {
	Name     string `json:"name"`
	Size     int64  `json:"size"`
	IsDir    bool   `json:"is_dir"`
	Modified string `json:"modified"`
	Path     string `json:"path"`
}

// RedirectInfo 重定向信息
type RedirectInfo struct {
	RedirectURL string       `json:"redirectUrl"`
	PasswdInfo  *EncryptPath `json:"passwdInfo"`
	FileSize    int64        `json:"fileSize"`
	ExpireAt    time.Time    `json:"expireAt"`
}

var (
	redirectCache sync.Map // 重定向缓存
)

// NewProxyServer 创建代理服务器
func NewProxyServer(config *ProxyConfig) (*ProxyServer, error) {
	if config == nil {
		return nil, errors.New("config cannot be nil")
	}

	// 编译路径正则表达式
	for _, ep := range config.EncryptPaths {
		if ep.Path != "" {
			// 转换简单通配符为正则表达式
			pattern := ep.Path
			// 特殊处理 /* 结尾，使其匹配目录本身和子文件
			if strings.HasSuffix(pattern, "/*") {
				base := strings.TrimSuffix(pattern, "/*")
				pattern = "^" + regexp.QuoteMeta(base) + "(/.*)?$"
			} else {
				pattern = strings.ReplaceAll(pattern, "*", ".*")
				pattern = strings.ReplaceAll(pattern, "?", ".")
				if !strings.HasPrefix(pattern, "^") {
					pattern = "^" + pattern
				}
			}

			regex, err := regexp.Compile(pattern)
			if err != nil {
				log.Warnf("Invalid path pattern: %s, error: %v", ep.Path, err)
				continue
			}
			ep.regex = regex
		}
	}

	return &ProxyServer{
		config: config,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
			Transport: &http.Transport{
				MaxIdleConns:        100,
				MaxIdleConnsPerHost: 20,
				IdleConnTimeout:     90 * time.Second,
			},
		},
	}, nil
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
	mux.HandleFunc("/index", p.handleIndex) // 管理页面快捷入口
	mux.HandleFunc("/public/", p.handleStatic)
	mux.HandleFunc("/static/", p.handleStatic)
	mux.HandleFunc("/favicon.ico", p.handleStatic)
	mux.HandleFunc("/logo.png", p.handleStatic)
	mux.HandleFunc("/enc-api/getAlistConfig", p.handleConfig)
	mux.HandleFunc("/enc-api/saveAlistConfig", p.handleConfig)
	mux.HandleFunc("/enc-api/getUserInfo", p.handleUserInfo)
	mux.HandleFunc("/api/encrypt/restart", p.handleRestart)
	mux.HandleFunc("/redirect/", p.handleRedirect)
	mux.HandleFunc("/api/fs/list", p.handleFsList)
	mux.HandleFunc("/api/fs/get", p.handleFsGet)
	mux.HandleFunc("/api/fs/put", p.handleFsPut) // 网页端上传
	mux.HandleFunc("/d/", p.handleDownload)
	mux.HandleFunc("/p/", p.handleDownload)
	mux.HandleFunc("/dav/", p.handleWebDAV)
	mux.HandleFunc("/", p.handleRoot) // 根路径处理

	p.server = &http.Server{
		Addr:         fmt.Sprintf(":%d", p.config.ProxyPort),
		Handler:      mux,
		ReadTimeout:  0, // 视频流需要长连接
		WriteTimeout: 0,
		IdleTimeout:  120 * time.Second,
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

	if p.server != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		if err := p.server.Shutdown(ctx); err != nil {
			log.Errorf("Error shutting down proxy server: %v", err)
			return err
		}
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

	// Re-compile regex first
	for _, ep := range config.EncryptPaths {
		log.Infof("Compiling regex for path: %s", ep.Path)
		if ep.Path != "" {
			pattern := ep.Path
			if strings.HasSuffix(pattern, "/*") {
				base := strings.TrimSuffix(pattern, "/*")
				pattern = "^" + regexp.QuoteMeta(base) + "(/.*)?$"
			} else {
				pattern = strings.ReplaceAll(pattern, "*", ".*")
				pattern = strings.ReplaceAll(pattern, "?", ".")
				if !strings.HasPrefix(pattern, "^") {
					pattern = "^" + pattern
				}
			}
			reg, err := regexp.Compile(pattern)
			if err != nil {
				log.Warnf("Invalid path pattern update: %s, error: %v", ep.Path, err)
				continue
			}
			ep.regex = reg
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

// findEncryptPath 查找匹配的加密路径配置
func (p *ProxyServer) findEncryptPath(filePath string) *EncryptPath {
	p.mutex.RLock()
	defer p.mutex.RUnlock()

	log.Infof("Checking encryption path for: %s", filePath)

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
			if ep.regex.MatchString(filePath) {
				log.Infof("Matched rule (raw): %s for %s", ep.Path, filePath)
				return ep
			}
			if filePath != decodedPath && ep.regex.MatchString(decodedPath) {
				log.Infof("Matched rule (decoded): %s for %s", ep.Path, decodedPath)
				return ep
			}
			// 更详细的 Debug 日志
			log.Debugf("Rule %s (regex: %s) did not match %s or %s", ep.Path, ep.regex.String(), filePath, decodedPath)
		} else {
			log.Warnf("Rule %s has nil regex", ep.Path)
		}
	}
	log.Infof("No encryption path matched for: %s (decoded: %s)", filePath, decodedPath)
	return nil
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

// handleIndex 管理页面快捷入口
func (p *ProxyServer) handleIndex(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, "/public/index.html", http.StatusFound)
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
	// 直接代理到 Alist，不显示中间导航页
	p.handleProxy(w, r)
}

// handleStatic 处理静态文件和管理页面
func (p *ProxyServer) handleStatic(w http.ResponseWriter, r *http.Request) {
	log.Debugf("Handling static request: %s", r.URL.Path)
	urlPath := r.URL.Path
	var relPath string

	if strings.HasPrefix(urlPath, "/public/") {
		relPath = strings.TrimPrefix(urlPath, "/public/")
	} else if strings.HasPrefix(urlPath, "/static/") {
		relPath = strings.TrimPrefix(urlPath, "/")
	} else if urlPath == "/favicon.ico" || urlPath == "/logo.png" {
		relPath = strings.TrimPrefix(urlPath, "/")
	} else {
		http.NotFound(w, r)
		return
	}

	if relPath == "" || relPath == "index.html" {
		relPath = "index.html"
	}

	// 从 embed FS 读取文件 (public.Public 的根是 .)
	// dist 是 public.Public 的子目录
	// 我们将 enc-webui 放在 dist/enc 下
	fsPath := path.Join("dist", "enc", relPath)

	f, err := public.Public.Open(fsPath)
	if err != nil {
		// 如果找不到文件，且是 HTML 请求，返回 index.html (支持 history mode 路由)
		if !strings.Contains(relPath, ".") {
			f, err = public.Public.Open(path.Join("dist", "enc", "index.html"))
		}
		if err != nil {
			log.Warnf("Static file not found: %s", fsPath)
			http.NotFound(w, r)
			return
		}
	}
	defer f.Close()

	// 获取文件信息
	stat, err := f.Stat()
	if err != nil {
		log.Errorf("Failed to stat file %s: %v", fsPath, err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	// 手动设置 Content-Type，防止 Android/Go 环境下无法识别导致 JS 无法执行
	ext := path.Ext(relPath)
	switch ext {
	case ".html":
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
	case ".css":
		w.Header().Set("Content-Type", "text/css; charset=utf-8")
	case ".js":
		w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
	case ".json":
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
	case ".png":
		w.Header().Set("Content-Type", "image/png")
	case ".jpg", ".jpeg":
		w.Header().Set("Content-Type", "image/jpeg")
	case ".gif":
		w.Header().Set("Content-Type", "image/gif")
	case ".svg":
		w.Header().Set("Content-Type", "image/svg+xml")
	case ".ico":
		w.Header().Set("Content-Type", "image/x-icon")
	}

	// 使用 http.ServeContent 处理 Range 请求和 Content-Type
	http.ServeContent(w, r, stat.Name(), stat.ModTime(), f.(io.ReadSeeker))
}

// handleUserInfo 处理用户信息请求
func (p *ProxyServer) handleUserInfo(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"code": 200,
		"data": map[string]interface{}{
			"username": "admin",
			"roleId":   "[13]",
		},
	})
}

// handleConfig 处理配置 API
func (p *ProxyServer) handleConfig(w http.ResponseWriter, r *http.Request) {
	// 根据路径判断是获取还是保存，或者通过 Method（但 getAlistConfig 用的是 POST）
	if strings.Contains(r.URL.Path, "getAlistConfig") {
		// 转换为前端期望的格式 (alist-encrypt 兼容)
		passwdList := make([]map[string]interface{}, 0)
		for _, ep := range p.config.EncryptPaths {
			// 转换加密类型
			encType := string(ep.EncType)
			if encType == "aes-ctr" {
				encType = "aesctr"
			} else if encType == "rc4md5" {
				encType = "rc4"
			}

			passwdList = append(passwdList, map[string]interface{}{
				"encPath":  []string{ep.Path}, // 前端期望数组
				"password": ep.Password,       // 返回密码以便前端回显
				"encType":  encType,
				"encName":  ep.EncName,
				"enable":   ep.Enable,
				"describe": "", // Go配置中没有备注字段，留空
			})
		}

		json.NewEncoder(w).Encode(map[string]interface{}{
			"code": 200,
			"data": map[string]interface{}{
				"alistHost":  p.config.AlistHost,
				"alistPort":  p.config.AlistPort,
				"https":      p.config.AlistHttps,
				"proxyPort":  p.config.ProxyPort,
				"passwdList": passwdList,
			},
		})
		return
	}

	if strings.Contains(r.URL.Path, "saveAlistConfig") {
		// 解析前端发来的配置
		var reqData struct {
			AlistHost  string `json:"alistHost"`
			AlistPort  string `json:"alistPort"` // 前端可能是字符串
			Https      bool   `json:"https"`
			ProxyPort  string `json:"proxyPort"` // 前端可能是字符串
			PasswdList []struct {
				EncPath  interface{} `json:"encPath"` // 可能是 string 或 []string
				Password string      `json:"password"`
				EncType  string      `json:"encType"`
				EncName  bool        `json:"encName"`
				Enable   bool        `json:"enable"`
			} `json:"passwdList"`
		}

		if err := json.NewDecoder(r.Body).Decode(&reqData); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		p.mutex.Lock()
		p.config.AlistHost = reqData.AlistHost
		if port, err := strconv.Atoi(reqData.AlistPort); err == nil {
			p.config.AlistPort = port
		}
		p.config.AlistHttps = reqData.Https
		if port, err := strconv.Atoi(reqData.ProxyPort); err == nil {
			p.config.ProxyPort = port
		}

		// 重建 EncryptPaths
		var newPaths []*EncryptPath
		for _, item := range reqData.PasswdList {
			// 处理 encType 转换
			var encType EncryptionType
			switch item.EncType {
			case "aesctr":
				encType = EncTypeAESCTR
			case "rc4":
				encType = EncTypeRC4
			case "mix":
				encType = EncTypeMix
			default:
				encType = EncryptionType(item.EncType)
			}

			// 处理 encPath (支持逗号分隔字符串或数组)
			var paths []string
			switch v := item.EncPath.(type) {
			case string:
				// 逗号分隔
				parts := strings.Split(v, ",")
				for _, part := range parts {
					if strings.TrimSpace(part) != "" {
						paths = append(paths, strings.TrimSpace(part))
					}
				}
			case []interface{}:
				for _, p := range v {
					if s, ok := p.(string); ok && strings.TrimSpace(s) != "" {
						paths = append(paths, strings.TrimSpace(s))
					}
				}
			}

			// 为每个路径创建 Entry
			for _, pathStr := range paths {
				pwd := item.Password

				epa := &EncryptPath{
					Path:     pathStr,
					Password: pwd,
					EncType:  encType,
					EncName:  item.EncName,
					Enable:   item.Enable,
				}
				newPaths = append(newPaths, epa)
			}
		}
		p.config.EncryptPaths = newPaths

		// Re-compile regex
		for _, ep := range p.config.EncryptPaths {
			if ep.Path != "" {
				pattern := ep.Path
				if strings.HasSuffix(pattern, "/*") {
					base := strings.TrimSuffix(pattern, "/*")
					pattern = "^" + regexp.QuoteMeta(base) + "(/.*)?$"
				} else {
					pattern = strings.ReplaceAll(pattern, "*", ".*")
					pattern = strings.ReplaceAll(pattern, "?", ".")
					if !strings.HasPrefix(pattern, "^") {
						pattern = "^" + pattern
					}
				}
				reg, err := regexp.Compile(pattern)
				if err != nil {
					log.Warnf("Invalid path pattern update: %s, error: %v", ep.Path, err)
					continue
				}
				ep.regex = reg
			}
		}
		p.mutex.Unlock()

		json.NewEncoder(w).Encode(map[string]interface{}{
			"code":    200,
			"message": "Config updated",
		})
		return
	}

	http.Error(w, "Method not allowed or Unknown action", http.StatusNotFound)
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

	// 从缓存获取重定向信息
	value, ok := redirectCache.Load(key)
	if !ok {
		http.Error(w, "Redirect key not found or expired", http.StatusNotFound)
		return
	}

	info := value.(*RedirectInfo)
	if time.Now().After(info.ExpireAt) {
		redirectCache.Delete(key)
		http.Error(w, "Redirect key expired", http.StatusNotFound)
		return
	}

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
	}

	// 创建到实际资源的请求
	req, err := http.NewRequest("GET", info.RedirectURL, nil)
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

	// 发送请求
	resp, err := p.httpClient.Do(req)
	if err != nil {
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

	// 检查是否需要解密
	decode := r.URL.Query().Get("decode")
	if decode != "0" && info.PasswdInfo != nil {
		// 创建解密器
		encryptor, err := NewFlowEncryptor(info.PasswdInfo.Password, info.PasswdInfo.EncType, info.FileSize)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		if startPos > 0 {
			encryptor.SetPosition(startPos)
		}

		// 创建解密读取器
		decryptReader := NewDecryptReader(resp.Body, encryptor)

		w.WriteHeader(resp.StatusCode)
		io.Copy(w, decryptReader)
	} else {
		w.WriteHeader(resp.StatusCode)
		io.Copy(w, resp.Body)
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

	// 读取响应
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// 解析响应
	var result map[string]interface{}
	if err := json.Unmarshal(respBody, &result); err == nil {
		if code, ok := result["code"].(float64); ok && code == 200 {
			if data, ok := result["data"].(map[string]interface{}); ok {
				if content, ok := data["content"].([]interface{}); ok {
					var reqData map[string]string
					json.Unmarshal(body, &reqData)
					dirPath := reqData["path"]

					log.Infof("Handling fs list for path: %s", dirPath)

					// 查找加密路径配置
					encPath := p.findEncryptPath(dirPath)

					for _, item := range content {
						if fileMap, ok := item.(map[string]interface{}); ok {
							name, _ := fileMap["name"].(string)
							size, _ := fileMap["size"].(float64)
							isDir, _ := fileMap["is_dir"].(bool)
							filePath := path.Join(dirPath, name)

							// 缓存文件信息
							p.fileCache.Store(filePath, &FileInfo{
								Name:  name,
								Size:  int64(size),
								IsDir: isDir,
								Path:  filePath,
							})

							// 如果需要加密文件名且不是目录
							if encPath != nil && encPath.EncName && !isDir {
								// 将加密的文件名转换为显示名
								showName := ConvertShowName(encPath.Password, encPath.EncType, name)
								if showName != name && !strings.HasPrefix(showName, "orig_") {
									log.Infof("Decrypt filename: %s -> %s", name, showName)
								}
								fileMap["name"] = showName
							}
						}
					}

					result["data"] = data
					respBody, _ = json.Marshal(result)
				}
			}
		}
	}

	// 返回响应
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(resp.StatusCode)
	w.Write(respBody)
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
		// 尝试将显示名转换为真实加密名
		fileName := path.Base(filePath)
		if !strings.HasPrefix(fileName, "orig_") {
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

				// 如果开启了文件名加密，将加密名转换为显示名
				if encPath.EncName {
					if name, ok := data["name"].(string); ok {
						showName := ConvertShowName(encPath.Password, encPath.EncType, name)
						data["name"] = showName
					}
				}

				// 创建重定向缓存
				key := generateRedirectKey()
				redirectCache.Store(key, &RedirectInfo{
					RedirectURL: rawURL,
					PasswdInfo:  encPath,
					FileSize:    int64(size),
					ExpireAt:    time.Now().Add(72 * time.Hour),
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
	io.Copy(w, resp.Body)
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
		if !strings.HasPrefix(fileName, "orig_") {
			realName := ConvertRealName(encPath.Password, encPath.EncType, filePath)
			newFilePath := path.Join(path.Dir(filePath), realName)
			if strings.HasPrefix(originalPath, "/d/") {
				actualURLPath = "/d" + newFilePath
			} else {
				actualURLPath = "/p" + newFilePath
			}
		}
	}

	// 获取文件大小
	var fileSize int64 = 0
	if cached, ok := p.fileCache.Load(filePath); ok {
		fileSize = cached.(*FileInfo).Size
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

	// 复制响应头
	for key, values := range resp.Header {
		for _, value := range values {
			w.Header().Add(key, value)
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

	// 如果需要解密
	if encPath != nil && fileSize > 0 {
		encryptor, err := NewFlowEncryptor(encPath.Password, encPath.EncType, fileSize)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		if startPos > 0 {
			encryptor.SetPosition(startPos)
		}

		decryptReader := NewDecryptReader(resp.Body, encryptor)
		w.WriteHeader(resp.StatusCode)
		io.Copy(w, decryptReader)
	} else {
		w.WriteHeader(resp.StatusCode)
		io.Copy(w, resp.Body)
	}
}

// handleWebDAV 处理 WebDAV 请求
func (p *ProxyServer) handleWebDAV(w http.ResponseWriter, r *http.Request) {
	// 创建到 Alist 的请求
	targetURL := p.getAlistURL() + r.URL.Path
	if r.URL.RawQuery != "" {
		targetURL += "?" + r.URL.RawQuery
	}

	var body io.Reader = nil
	if r.Body != nil {
		body = r.Body
	}

	// 检查是否是上传请求
	if r.Method == "PUT" {
		filePath := r.URL.Path
		encPath := p.findEncryptPath(filePath)

		if encPath != nil {
			contentLength := r.ContentLength
			if contentLength > 0 {
				encryptor, err := NewFlowEncryptor(encPath.Password, encPath.EncType, contentLength)
				if err != nil {
					http.Error(w, err.Error(), http.StatusInternalServerError)
					return
				}
				body = NewEncryptReader(r.Body, encryptor)
			}
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

	// 修正 Destination 头
	if dest := r.Header.Get("Destination"); dest != "" {
		parsedDest, err := url.Parse(dest)
		if err == nil {
			newDest := p.getAlistURL() + parsedDest.Path
			req.Header.Set("Destination", newDest)
		}
	}

	resp, err := p.httpClient.Do(req)
	if err != nil {
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

	// 检查是否是下载请求需要解密
	if r.Method == "GET" {
		filePath := r.URL.Path
		encPath := p.findEncryptPath(filePath)

		if encPath != nil {
			// 尝试获取文件大小
			var fileSize int64 = 0
			if cl := resp.Header.Get("Content-Length"); cl != "" {
				fileSize, _ = strconv.ParseInt(cl, 10, 64)
			}

			if fileSize > 0 {
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

				encryptor, err := NewFlowEncryptor(encPath.Password, encPath.EncType, fileSize)
				if err != nil {
					http.Error(w, err.Error(), http.StatusInternalServerError)
					return
				}

				if startPos > 0 {
					encryptor.SetPosition(startPos)
				}

				decryptReader := NewDecryptReader(resp.Body, encryptor)
				w.WriteHeader(resp.StatusCode)
				io.Copy(w, decryptReader)
				return
			}
		}
	}

	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
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

	// 如果是 HTML 页面，注入版本信息
	contentType := resp.Header.Get("Content-Type")
	if strings.Contains(contentType, "text/html") {
		body, _ := io.ReadAll(resp.Body)
		html := string(body)

		// 注入版本标识
		injection := `<body>
<div style="position: fixed;z-index:10010; top:7px; margin-left: 50%">
  <a target="_blank" href="/public/index.html">
    <div style="width:40px;height:40px;margin-left: -20px">
      <span style="color:gray;font-size:11px">🔐 Enc</span>
    </div>
  </a>
</div>`
		html = strings.Replace(html, "<body>", injection, 1)
		w.Write([]byte(html))
	} else {
		io.Copy(w, resp.Body)
	}
}

// generateRedirectKey 生成重定向 key
func generateRedirectKey() string {
	return fmt.Sprintf("%d%d", time.Now().UnixNano(), time.Now().UnixNano()%1000000)
}
