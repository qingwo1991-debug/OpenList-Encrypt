package encrypt

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"

	log "github.com/sirupsen/logrus"
)

// ConfigManager 配置管理器
type ConfigManager struct {
	configPath string
	config     *ProxyConfig
	mutex      sync.RWMutex
}

// DefaultConfig 默认配置
func DefaultConfig() *ProxyConfig {
	return &ProxyConfig{
		AlistHost:       "127.0.0.1",
		AlistPort:       5244,
		AlistHttps:      false,
		ProxyPort:       5344,
		ProbeOnDownload: true,  // 默认开启，确保能正确获取文件大小以解密
		EnableH2C:       false, // H2C 默认关闭，需要后端 OpenList 也开启 enable_h2c 才有效
		EncryptPaths: []*EncryptPath{
			{
				Path:     "encrypt_folder/*",
				Password: "123456",
				EncType:  EncTypeAESCTR,
				EncName:  false,
				Enable:   true,
			},
			{
				Path:     "movie_encrypt/*",
				Password: "123456",
				EncType:  EncTypeAESCTR,
				EncName:  false,
				Enable:   true,
			},
		},
		AdminPassword: "123456",
	}
}

// NewConfigManager 创建配置管理器
func NewConfigManager(configPath string) *ConfigManager {
	return &ConfigManager{
		configPath: configPath,
		config:     DefaultConfig(),
	}
}

// Load 加载配置
func (m *ConfigManager) Load() error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	// 检查配置文件是否存在
	if _, err := os.Stat(m.configPath); os.IsNotExist(err) {
		// 创建默认配置
		return m.saveConfigLocked()
	}

	// 读取配置文件
	data, err := os.ReadFile(m.configPath)
	if err != nil {
		log.Errorf("Failed to read config file: %v", err)
		return err
	}

	// 解析配置
	var config ProxyConfig
	if err := json.Unmarshal(data, &config); err != nil {
		log.Errorf("Failed to parse config: %v", err)
		return err
	}

	m.config = &config
	log.Info("Config loaded successfully")
	return nil
}

// Save 保存配置
func (m *ConfigManager) Save() error {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	return m.saveConfigLocked()
}

// saveConfigLocked 保存配置（内部方法，需要持有锁）
func (m *ConfigManager) saveConfigLocked() error {
	// 确保目录存在
	dir := filepath.Dir(m.configPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}

	// 序列化配置
	data, err := json.MarshalIndent(m.config, "", "  ")
	if err != nil {
		return err
	}

	// 写入文件
	if err := os.WriteFile(m.configPath, data, 0644); err != nil {
		return err
	}

	log.Info("Config saved successfully")
	return nil
}

// GetConfig 获取配置副本
func (m *ConfigManager) GetConfig() *ProxyConfig {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	// 返回配置副本
	configCopy := *m.config
	pathsCopy := make([]*EncryptPath, len(m.config.EncryptPaths))
	for i, p := range m.config.EncryptPaths {
		pathCopy := *p
		pathsCopy[i] = &pathCopy
	}
	configCopy.EncryptPaths = pathsCopy

	return &configCopy
}

// SetAlistHost 设置 Alist 主机
func (m *ConfigManager) SetAlistHost(host string, port int, https bool) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	m.config.AlistHost = host
	m.config.AlistPort = port
	m.config.AlistHttps = https

	return m.saveConfigLocked()
}

// SetProxyPort 设置代理端口
func (m *ConfigManager) SetProxyPort(port int) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	if port < 1 || port > 65535 {
		return errors.New("invalid port number")
	}

	m.config.ProxyPort = port
	return m.saveConfigLocked()
}

// SetEnableH2C 设置 H2C 开关
func (m *ConfigManager) SetEnableH2C(enable bool) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	m.config.EnableH2C = enable
	return m.saveConfigLocked()
}

// AddEncryptPath 添加加密路径
func (m *ConfigManager) AddEncryptPath(pathVal, password string, encType EncryptionType, encName bool) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	// 支持逗号分隔的多个路径
	paths := strings.Split(pathVal, ",")
	for _, pStr := range paths {
		rawPath := strings.TrimSpace(pStr)
		if rawPath == "" {
			continue
		}

		// 检查是否已存在
		exists := false
		for _, p := range m.config.EncryptPaths {
			if p.Path == rawPath {
				exists = true
				break
			}
		}
		if exists {
			continue
		}

		m.config.EncryptPaths = append(m.config.EncryptPaths, &EncryptPath{
			Path:     rawPath,
			Password: password,
			EncType:  encType,
			EncName:  encName,
			Enable:   true,
		})
	}

	return m.saveConfigLocked()
}

// UpdateEncryptPath 更新加密路径
func (m *ConfigManager) UpdateEncryptPath(index int, path, password string, encType EncryptionType, encName, enable bool) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	if index < 0 || index >= len(m.config.EncryptPaths) {
		return errors.New("index out of range")
	}

	m.config.EncryptPaths[index] = &EncryptPath{
		Path:     path,
		Password: password,
		EncType:  encType,
		EncName:  encName,
		Enable:   enable,
	}

	return m.saveConfigLocked()
}

// RemoveEncryptPath 删除加密路径
func (m *ConfigManager) RemoveEncryptPath(index int) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	if index < 0 || index >= len(m.config.EncryptPaths) {
		return errors.New("index out of range")
	}

	m.config.EncryptPaths = append(
		m.config.EncryptPaths[:index],
		m.config.EncryptPaths[index+1:]...,
	)

	return m.saveConfigLocked()
}

// SetAdminPassword 设置管理密码
func (m *ConfigManager) SetAdminPassword(password string) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	if len(password) < 4 {
		return errors.New("password too short")
	}

	m.config.AdminPassword = password
	return m.saveConfigLocked()
}

// VerifyAdminPassword 验证管理密码
func (m *ConfigManager) VerifyAdminPassword(password string) bool {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	return m.config.AdminPassword == password
}

// GetEncryptPaths 获取加密路径列表（不含密码）
func (m *ConfigManager) GetEncryptPaths() []*EncryptPath {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	paths := make([]*EncryptPath, len(m.config.EncryptPaths))
	for i, p := range m.config.EncryptPaths {
		paths[i] = &EncryptPath{
			Path:    p.Path,
			EncType: p.EncType,
			EncName: p.EncName,
			Enable:  p.Enable,
		}
	}

	return paths
}
