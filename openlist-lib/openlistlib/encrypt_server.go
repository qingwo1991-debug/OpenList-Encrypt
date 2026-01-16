package openlistlib

import (
	"encoding/json"
	"errors"
	"os"
	"sync"

	"github.com/OpenListTeam/OpenList/v4/openlistlib/encrypt"
	log "github.com/sirupsen/logrus"
)

func init() {
	// 将日志输出到标准错误，以便在 Android logcat 中查看（通常 tag 为 GoLog）
	log.SetOutput(os.Stderr)
	log.SetLevel(log.DebugLevel)
	log.SetFormatter(&log.TextFormatter{
		DisableColors: true,
		FullTimestamp: true,
	})
}

// EncryptProxyManager 加密代理管理器
type EncryptProxyManager struct {
	configManager *encrypt.ConfigManager
	proxyServer   *encrypt.ProxyServer
	mutex         sync.Mutex
	initialized   bool
}

var (
	encryptManager *EncryptProxyManager
	encryptOnce    sync.Once
)

// GetEncryptManager 获取加密管理器单例
func GetEncryptManager() *EncryptProxyManager {
	encryptOnce.Do(func() {
		encryptManager = &EncryptProxyManager{}
	})
	return encryptManager
}

// Initialize 初始化加密代理管理器
func (m *EncryptProxyManager) Initialize(configPath string) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	if m.initialized {
		return nil
	}

	// 创建配置管理器
	m.configManager = encrypt.NewConfigManager(configPath)
	if err := m.configManager.Load(); err != nil {
		log.Warnf("Failed to load encrypt config, using default: %v", err)
	}

	m.initialized = true
	log.Info("Encrypt proxy manager initialized")
	return nil
}

// StartProxy 启动加密代理服务器
func (m *EncryptProxyManager) StartProxy() error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	if !m.initialized {
		return errors.New("encrypt manager not initialized")
	}

	if m.proxyServer != nil && m.proxyServer.IsRunning() {
		return errors.New("proxy server is already running")
	}

	config := m.configManager.GetConfig()
	server, err := encrypt.NewProxyServer(config)
	if err != nil {
		return err
	}

	if err := server.Start(); err != nil {
		return err
	}

	m.proxyServer = server
	log.Info("Encrypt proxy server started")
	return nil
}

// StopProxy 停止加密代理服务器
func (m *EncryptProxyManager) StopProxy() error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	if m.proxyServer == nil {
		return nil
	}

	if err := m.proxyServer.Stop(); err != nil {
		return err
	}

	m.proxyServer = nil
	log.Info("Encrypt proxy server stopped")
	return nil
}

// IsProxyRunning 检查代理服务器是否运行中
func (m *EncryptProxyManager) IsProxyRunning() bool {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	if m.proxyServer == nil {
		return false
	}
	return m.proxyServer.IsRunning()
}

// RestartProxy 重启代理服务器
func (m *EncryptProxyManager) RestartProxy() error {
	if err := m.StopProxy(); err != nil {
		log.Warnf("Error stopping proxy: %v", err)
	}
	return m.StartProxy()
}

// GetConfig 获取配置
func (m *EncryptProxyManager) GetConfig() *encrypt.ProxyConfig {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	if m.configManager == nil {
		return nil
	}
	return m.configManager.GetConfig()
}

// updateProxyServerConfig 更新代理服务器配置（内部方法）
func (m *EncryptProxyManager) updateProxyServerConfig() {
	if m.proxyServer != nil && m.proxyServer.IsRunning() {
		config := m.configManager.GetConfig()
		m.proxyServer.UpdateConfig(config)
	}
}

// SetAlistHost 设置 Alist 主机
func (m *EncryptProxyManager) SetAlistHost(host string, port int, https bool) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	if m.configManager == nil {
		return errors.New("config manager not initialized")
	}
	err := m.configManager.SetAlistHost(host, port, https)
	if err == nil {
		m.updateProxyServerConfig()
	}
	return err
}

// SetProxyPort 设置代理端口
func (m *EncryptProxyManager) SetProxyPort(port int) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	if m.configManager == nil {
		return errors.New("config manager not initialized")
	}
	err := m.configManager.SetProxyPort(port)
	if err == nil {
		m.updateProxyServerConfig()
	}
	return err
}

// AddEncryptPath 添加加密路径
func (m *EncryptProxyManager) AddEncryptPath(path, password string, encType string, encName bool) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	if m.configManager == nil {
		return errors.New("config manager not initialized")
	}
	err := m.configManager.AddEncryptPath(path, password, encrypt.EncryptionType(encType), encName)
	if err == nil {
		m.updateProxyServerConfig()
	}
	return err
}

// UpdateEncryptPath 更新加密路径
func (m *EncryptProxyManager) UpdateEncryptPath(index int, path, password string, encType string, encName, enable bool) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	if m.configManager == nil {
		return errors.New("config manager not initialized")
	}
	err := m.configManager.UpdateEncryptPath(index, path, password, encrypt.EncryptionType(encType), encName, enable)
	if err == nil {
		m.updateProxyServerConfig()
	}
	return err
}

// RemoveEncryptPath 删除加密路径
func (m *EncryptProxyManager) RemoveEncryptPath(index int) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	if m.configManager == nil {
		return errors.New("config manager not initialized")
	}
	err := m.configManager.RemoveEncryptPath(index)
	if err == nil {
		m.updateProxyServerConfig()
	}
	return err
}

// GetEncryptPaths 获取加密路径列表
func (m *EncryptProxyManager) GetEncryptPaths() []*encrypt.EncryptPath {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	if m.configManager == nil {
		return nil
	}
	return m.configManager.GetEncryptPaths()
}

// VerifyAdminPassword 验证管理密码
func (m *EncryptProxyManager) VerifyAdminPassword(password string) bool {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	if m.configManager == nil {
		return false
	}
	return m.configManager.VerifyAdminPassword(password)
}

// SetAdminPassword 设置管理密码
func (m *EncryptProxyManager) SetAdminPassword(password string) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	if m.configManager == nil {
		return errors.New("config manager not initialized")
	}
	err := m.configManager.SetAdminPassword(password)
	if err == nil {
		m.updateProxyServerConfig()
	}
	return err
}

// === 以下是为 gomobile 导出的函数 ===

// InitEncryptProxy 初始化加密代理（供 gomobile 调用）
func InitEncryptProxy(configPath string) error {
	return GetEncryptManager().Initialize(configPath)
}

// StartEncryptProxy 启动加密代理（供 gomobile 调用）
func StartEncryptProxy() error {
	return GetEncryptManager().StartProxy()
}

// StopEncryptProxy 停止加密代理（供 gomobile 调用）
func StopEncryptProxy() error {
	return GetEncryptManager().StopProxy()
}

// IsEncryptProxyRunning 检查加密代理是否运行中（供 gomobile 调用）
func IsEncryptProxyRunning() bool {
	return GetEncryptManager().IsProxyRunning()
}

// RestartEncryptProxy 重启加密代理（供 gomobile 调用）
func RestartEncryptProxy() error {
	return GetEncryptManager().RestartProxy()
}

// GetEncryptProxyPort 获取代理端口（供 gomobile 调用）
func GetEncryptProxyPort() int64 {
	config := GetEncryptManager().GetConfig()
	if config == nil {
		return 5344
	}
	return int64(config.ProxyPort)
}

// SetEncryptAlistHost 设置 Alist 主机（供 gomobile 调用）
func SetEncryptAlistHost(host string, port int64, https bool) error {
	return GetEncryptManager().SetAlistHost(host, int(port), https)
}

// SetEncryptProxyPort 设置代理端口（供 gomobile 调用）
func SetEncryptProxyPort(port int64) error {
	return GetEncryptManager().SetProxyPort(int(port))
}

// AddEncryptPathConfig 添加加密路径配置（供 gomobile 调用）
func AddEncryptPathConfig(path, password, encType string, encName bool) error {
	return GetEncryptManager().AddEncryptPath(path, password, encType, encName)
}

// RemoveEncryptPathConfig 删除加密路径配置（供 gomobile 调用）
func RemoveEncryptPathConfig(index int64) error {
	return GetEncryptManager().RemoveEncryptPath(int(index))
}

// VerifyEncryptAdminPassword 验证管理密码（供 gomobile 调用）
func VerifyEncryptAdminPassword(password string) bool {
	return GetEncryptManager().VerifyAdminPassword(password)
}

// SetEncryptAdminPassword 设置管理密码（供 gomobile 调用）
func SetEncryptAdminPassword(password string) error {
	return GetEncryptManager().SetAdminPassword(password)
}

// GetEncryptPathsJson 获取加密路径列表 JSON（供 gomobile 调用）
func GetEncryptPathsJson() string {
	paths := GetEncryptManager().GetEncryptPaths()
	if paths == nil {
		return "[]"
	}

	type PathInfo struct {
		Path    string `json:"path"`
		EncType string `json:"encType"`
		EncName bool   `json:"encName"`
		Enable  bool   `json:"enable"`
	}

	infos := make([]PathInfo, len(paths))
	for i, p := range paths {
		infos[i] = PathInfo{
			Path:    p.Path,
			EncType: string(p.EncType),
			EncName: p.EncName,
			Enable:  p.Enable,
		}
	}

	data, err := json.Marshal(infos)
	if err != nil {
		return "[]"
	}
	return string(data)
}

// GetEncryptConfigJson 获取完整配置 JSON（供 gomobile 调用）
func GetEncryptConfigJson() string {
	config := GetEncryptManager().GetConfig()
	if config == nil {
		return "{}"
	}

	type PathInfo struct {
		Path    string `json:"path"`
		EncType string `json:"encType"`
		EncName bool   `json:"encName"`
		Enable  bool   `json:"enable"`
	}

	type ConfigInfo struct {
		AlistHost    string     `json:"alistHost"`
		AlistPort    int        `json:"alistPort"`
		AlistHttps   bool       `json:"alistHttps"`
		ProxyPort    int        `json:"proxyPort"`
		EncryptPaths []PathInfo `json:"encryptPaths"`
	}

	paths := make([]PathInfo, len(config.EncryptPaths))
	for i, p := range config.EncryptPaths {
		paths[i] = PathInfo{
			Path:    p.Path,
			EncType: string(p.EncType),
			EncName: p.EncName,
			Enable:  p.Enable,
		}
	}

	info := ConfigInfo{
		AlistHost:    config.AlistHost,
		AlistPort:    config.AlistPort,
		AlistHttps:   config.AlistHttps,
		ProxyPort:    config.ProxyPort,
		EncryptPaths: paths,
	}

	data, err := json.Marshal(info)
	if err != nil {
		return "{}"
	}
	return string(data)
}

// UpdateEncryptPathConfig 更新加密路径配置（供 gomobile 调用）
func UpdateEncryptPathConfig(index int64, path, password, encType string, encName, enable bool) error {
	return GetEncryptManager().UpdateEncryptPath(int(index), path, password, encType, encName, enable)
}
