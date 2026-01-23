package encrypt

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/xml"
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
	// ProbeOnDownload: attempt HEAD or Range=0-0 to discover remote file size when missing
	ProbeOnDownload bool `json:"probeOnDownload"`
}

// ProxyServer 加密代理服务器
type ProxyServer struct {
	config       *ProxyConfig
	httpClient   *http.Client
	streamClient *http.Client
	transport    *http.Transport
	server       *http.Server
	running      bool
	mutex        sync.RWMutex
	fileCache    sync.Map // 文件信息缓存
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
			pattern = "^" + converted
		} else {
			pattern = "^/?" + converted
		}
		if reg, err := regexp.Compile(pattern); err == nil {
			ep.regex = reg
		} else {
			log.Warnf("Invalid path pattern: %s, error: %v", ep.Path, err)
		}
	}

	// ProbeOnDownload is controlled by configuration / frontend; do not override here.

	transport := &http.Transport{
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 20,
		IdleConnTimeout:     90 * time.Second,
	}

	return &ProxyServer{
		config:     config,
		transport:  transport,
		httpClient: &http.Client{Timeout: 30 * time.Second, Transport: transport},
		// streamClient is used for long-running download / webdav stream requests (no timeout)
		// Reuse the same Transport to share connection pool.
		streamClient: &http.Client{Timeout: 0, Transport: transport},
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

// processPropfindResponse 解析并替换 PROPFIND XML 中的 href/displayname，并缓存文件信息
func (p *ProxyServer) processPropfindResponse(body io.Reader, w io.Writer, encPath *EncryptPath) error {
	dec := xml.NewDecoder(body)
	enc := xml.NewEncoder(w)

	inResponse := false
	var curHref string
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
						fileName := path.Base(decodedPath)
						if fileName != "/" && fileName != "." && !strings.HasPrefix(fileName, "orig_") {
							showName := ConvertShowName(encPath.Password, encPath.EncType, fileName)
							if showName != fileName && !strings.HasPrefix(showName, "orig_") {
								newPath := path.Join(path.Dir(decodedPath), showName)
								content = (&url.URL{Path: newPath}).EscapedPath()
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
					p.fileCache.Store(curHref, &FileInfo{Name: name, Size: size, IsDir: isDir, Path: curHref})
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
	// Use streamClient for downloads to avoid client-side timeouts for large/long streams
	resp, err := p.streamClient.Do(req)
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

	// 获取文件大小 - 首先尝试从缓存获取
	var fileSize int64 = 0
	if cached, ok := p.fileCache.Load(filePath); ok {
		fileSize = cached.(*FileInfo).Size
		log.Debugf("handleDownload: got fileSize from cache: %d for path: %s", fileSize, filePath)
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

	// 如果缓存中没有文件大小，尝试从响应头获取；如果仍然未知，探测远程总大小（HEAD 或 Range=0-0）
	if fileSize == 0 && encPath != nil {
		// 尝试从 Content-Length 获取
		if cl := resp.Header.Get("Content-Length"); cl != "" {
			if size, err := strconv.ParseInt(cl, 10, 64); err == nil && size > 0 {
				fileSize = size
				log.Infof("handleDownload: got fileSize from Content-Length: %d for path: %s", fileSize, filePath)
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
		w.WriteHeader(resp.StatusCode)
		io.Copy(w, decryptReader)
	} else if encPath != nil && fileSize == 0 {
		// fileSize 为 0 时无法正确解密（因为 fileSize 参与密钥生成）
		// 直接透传原始数据，让客户端知道这是加密的文件
		log.Warnf("handleDownload: cannot decrypt, fileSize is 0 for encrypted path: %s. Passing through raw data.", filePath)
		w.WriteHeader(resp.StatusCode)
		io.Copy(w, resp.Body)
	} else {
		w.WriteHeader(resp.StatusCode)
		io.Copy(w, resp.Body)
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

	// 2. 转换请求路径中的文件名 (Client明文 -> Server密文)
	targetURLPath := r.URL.Path
	// 仅对特定方法进行文件名转换。PROPFIND (列目录) 不需要转换（因为目录名是明文），
	// 且必须保持明文以供 Alist 识别。
	// node.js 版只转换 GET, PUT, DELETE。我们也加上 COPY, MOVE, HEAD。
	methodNeedConvert := r.Method == "GET" || r.Method == "PUT" || r.Method == "DELETE" ||
		r.Method == "COPY" || r.Method == "MOVE" || r.Method == "HEAD" || r.Method == "POST"

	if methodNeedConvert && encPath != nil && encPath.EncName {
		fileName := path.Base(filePath)
		if fileName != "/" && fileName != "." && !strings.HasPrefix(fileName, "orig_") {
			realName := ConvertRealName(encPath.Password, encPath.EncType, filePath)
			newPath := path.Join(path.Dir(filePath), realName)
			// 确保路径以 / 开头
			if !strings.HasPrefix(newPath, "/") {
				newPath = "/" + newPath
			}
			// 特殊处理：如果是根路径的子文件，path.Dir可能返回 /dav，Join后是 /dav/xxx
			// 如果是 /dav/foo.txt -> Dir: /dav -> Join: /dav/xxx.txt
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

		if contentLength > 0 {
			encryptor, err := NewFlowEncryptor(encPath.Password, encPath.EncType, contentLength)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			body = NewEncryptReader(r.Body, encryptor)
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
				if destName != "/" && destName != "." && !strings.HasPrefix(destName, "orig_") {
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

	// PROPFIND 404 重试机制 (因为我们不知道请求的是目录还是加密文件)
	// 如果默认透传 (当作目录) 失败，尝试加密文件名再试 (当作文件)
	if r.Method == "PROPFIND" && resp.StatusCode == 404 && encPath != nil && encPath.EncName {
		// 关闭旧响应体
		resp.Body.Close()

		// 重新计算加密路径
		fileName := path.Base(filePath)
		if fileName != "/" && fileName != "." && !strings.HasPrefix(fileName, "orig_") {
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

	// 复制响应头
	for key, values := range resp.Header {
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}

	// 6. 处理 GET 下载解密
	if r.Method == "GET" && encPath != nil {
		// 检查 Content-Type，避免解密错误页面或目录列表
		contentType := resp.Header.Get("Content-Type")
		if strings.Contains(contentType, "text/html") ||
			strings.Contains(contentType, "application/json") ||
			strings.Contains(contentType, "application/xml") {
			w.WriteHeader(resp.StatusCode)
			io.Copy(w, resp.Body)
			return
		}

		// 尝试获取文件大小
		var fileSize int64 = 0
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

		if fileSize == 0 {
			if cl := resp.Header.Get("Content-Length"); cl != "" {
				fileSize, _ = strconv.ParseInt(cl, 10, 64)
			}
		}

		// 只有当服务端返回了内容，且知道大小，才解密
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
				// 无法创建解密器(如未知算法)，直接透传
				log.Warnf("Failed to create encryptor for download: %v", err)
				w.WriteHeader(resp.StatusCode)
				io.Copy(w, resp.Body)
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

	// 直接复制响应体，不做 HTML 注入（加密配置已移至 App 前端）
	io.Copy(w, resp.Body)
}

// generateRedirectKey 生成重定向 key
func generateRedirectKey() string {
	return fmt.Sprintf("%d%d", time.Now().UnixNano(), time.Now().UnixNano()%1000000)
}
