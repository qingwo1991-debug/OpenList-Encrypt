package encrypt

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rc4"
	"errors"
	"io"
	"path"
	"strings"
)

// EncryptionType 加密类型
type EncryptionType string

const (
	EncTypeAESCTR EncryptionType = "aes-ctr"
	EncTypeRC4    EncryptionType = "rc4md5"
	EncTypeMix    EncryptionType = "mix"
)

// 缓存密码外部密钥
var passwdOutwardCache = make(map[string]string)

// CRC6 实例
var crc6 = NewCRC6()

// FlowEncryptor 流加密器接口
type FlowEncryptor interface {
	// Encrypt 加密数据
	Encrypt(data []byte) ([]byte, error)
	// Decrypt 解密数据
	Decrypt(data []byte) ([]byte, error)
	// SetPosition 设置流位置（用于随机访问）
	SetPosition(position int64) error
	// GetPosition 获取当前位置
	GetPosition() int64
}

// AESCTREncryptor AES-CTR 加密器
type AESCTREncryptor struct {
	key      []byte
	nonce    []byte
	position int64
	fileSize int64
}

// NewAESCTREncryptor 创建 AES-CTR 加密器
func NewAESCTREncryptor(password string, fileSize int64) (*AESCTREncryptor, error) {
	// 从密码派生密钥和 nonce
	key := deriveKey(password, 32)    // AES-256
	nonce := deriveKey(password+"nonce", 16) // CTR nonce

	return &AESCTREncryptor{
		key:      key,
		nonce:    nonce,
		position: 0,
		fileSize: fileSize,
	}, nil
}

// deriveKey 从密码派生密钥
func deriveKey(password string, length int) []byte {
	result := make([]byte, 0, length)
	data := []byte(password)
	
	for len(result) < length {
		hash := md5.Sum(data)
		result = append(result, hash[:]...)
		data = append(hash[:], []byte(password)...)
	}
	
	return result[:length]
}

// createStream 创建 AES-CTR 流
func (e *AESCTREncryptor) createStream() (cipher.Stream, error) {
	block, err := aes.NewCipher(e.key)
	if err != nil {
		return nil, err
	}

	// 计算基于位置的 IV
	iv := e.calculateIV()
	
	return cipher.NewCTR(block, iv), nil
}

// calculateIV 计算基于位置的 IV
func (e *AESCTREncryptor) calculateIV() []byte {
	iv := make([]byte, 16)
	copy(iv, e.nonce)
	
	// 将位置编码到 IV 中（用于随机访问）
	blockNum := e.position / 16
	for i := 15; i >= 8; i-- {
		iv[i] ^= byte(blockNum & 0xff)
		blockNum >>= 8
	}
	
	return iv
}

// SetPosition 设置流位置
func (e *AESCTREncryptor) SetPosition(position int64) error {
	e.position = position
	return nil
}

// GetPosition 获取当前位置
func (e *AESCTREncryptor) GetPosition() int64 {
	return e.position
}

// Encrypt 加密数据
func (e *AESCTREncryptor) Encrypt(data []byte) ([]byte, error) {
	stream, err := e.createStream()
	if err != nil {
		return nil, err
	}

	// 处理块内偏移
	offset := int(e.position % 16)
	if offset > 0 {
		// 需要跳过一些字节来对齐
		skip := make([]byte, offset)
		stream.XORKeyStream(skip, skip)
	}

	encrypted := make([]byte, len(data))
	stream.XORKeyStream(encrypted, data)
	
	e.position += int64(len(data))
	return encrypted, nil
}

// Decrypt 解密数据（AES-CTR 加解密是对称的）
func (e *AESCTREncryptor) Decrypt(data []byte) ([]byte, error) {
	return e.Encrypt(data)
}

// RC4MD5Encryptor RC4-MD5 加密器
type RC4MD5Encryptor struct {
	password string
	position int64
	fileSize int64
	cipher   *rc4.Cipher
}

// NewRC4MD5Encryptor 创建 RC4-MD5 加密器
func NewRC4MD5Encryptor(password string, fileSize int64) (*RC4MD5Encryptor, error) {
	enc := &RC4MD5Encryptor{
		password: password,
		position: 0,
		fileSize: fileSize,
	}
	
	if err := enc.initCipher(); err != nil {
		return nil, err
	}
	
	return enc, nil
}

// initCipher 初始化 RC4 密码器
func (e *RC4MD5Encryptor) initCipher() error {
	// 使用密码的 MD5 作为 RC4 密钥
	hash := md5.Sum([]byte(e.password))
	
	cipher, err := rc4.NewCipher(hash[:])
	if err != nil {
		return err
	}
	
	e.cipher = cipher
	return nil
}

// SetPosition 设置流位置
func (e *RC4MD5Encryptor) SetPosition(position int64) error {
	// RC4 需要重新初始化并跳过指定字节
	if err := e.initCipher(); err != nil {
		return err
	}
	
	// 跳过 position 个字节
	if position > 0 {
		skip := make([]byte, position)
		e.cipher.XORKeyStream(skip, skip)
	}
	
	e.position = position
	return nil
}

// GetPosition 获取当前位置
func (e *RC4MD5Encryptor) GetPosition() int64 {
	return e.position
}

// Encrypt 加密数据
func (e *RC4MD5Encryptor) Encrypt(data []byte) ([]byte, error) {
	if e.cipher == nil {
		return nil, errors.New("cipher not initialized")
	}
	
	encrypted := make([]byte, len(data))
	e.cipher.XORKeyStream(encrypted, data)
	
	e.position += int64(len(data))
	return encrypted, nil
}

// Decrypt 解密数据（RC4 加解密是对称的）
func (e *RC4MD5Encryptor) Decrypt(data []byte) ([]byte, error) {
	return e.Encrypt(data)
}

// NewFlowEncryptor 创建流加密器
func NewFlowEncryptor(password string, encType EncryptionType, fileSize int64) (FlowEncryptor, error) {
	switch encType {
	case EncTypeAESCTR, "aesctr":
		return NewAESCTREncryptor(password, fileSize)
	case EncTypeRC4, "rc4":
		return NewRC4MD5Encryptor(password, fileSize)
	case EncTypeMix:
		return NewMixEncryptor(password, fileSize)
	default:
		return nil, errors.New("unsupported encryption type: " + string(encType))
	}
}

// GetPasswdOutward 获取外部密码（用于文件名加密）
func GetPasswdOutward(password string, encType EncryptionType) string {
	key := password + string(encType)
	if cached, ok := passwdOutwardCache[key]; ok {
		return cached
	}

	var passwdOutward string
	switch encType {
	case EncTypeMix:
		enc, _ := NewMixEncryptor(password, 1)
		if enc != nil {
			passwdOutward = enc.GetPasswdOutward()
		}
	case EncTypeRC4, "rc4":
		if len(password) != 32 {
			passwdOutward = deriveKeyHex(password, "RC4", 16)
		} else {
			passwdOutward = password
		}
	case EncTypeAESCTR, "aesctr":
		if len(password) != 32 {
			passwdOutward = deriveKeyHex(password, "AES-CTR", 16)
		} else {
			passwdOutward = password
		}
	default:
		passwdOutward = password
	}

	passwdOutwardCache[key] = passwdOutward
	return passwdOutward
}

// EncryptReader 加密读取器
type EncryptReader struct {
	reader    io.Reader
	encryptor FlowEncryptor
}

// NewEncryptReader 创建加密读取器
func NewEncryptReader(reader io.Reader, encryptor FlowEncryptor) *EncryptReader {
	return &EncryptReader{
		reader:    reader,
		encryptor: encryptor,
	}
}

// Read 读取并加密数据
func (r *EncryptReader) Read(p []byte) (int, error) {
	n, err := r.reader.Read(p)
	if n > 0 {
		encrypted, encErr := r.encryptor.Encrypt(p[:n])
		if encErr != nil {
			return 0, encErr
		}
		copy(p[:n], encrypted)
	}
	return n, err
}

// DecryptReader 解密读取器
type DecryptReader struct {
	reader    io.Reader
	encryptor FlowEncryptor
}

// NewDecryptReader 创建解密读取器
func NewDecryptReader(reader io.Reader, encryptor FlowEncryptor) *DecryptReader {
	return &DecryptReader{
		reader:    reader,
		encryptor: encryptor,
	}
}

// Read 读取并解密数据
func (r *DecryptReader) Read(p []byte) (int, error) {
	n, err := r.reader.Read(p)
	if n > 0 {
		decrypted, decErr := r.encryptor.Decrypt(p[:n])
		if decErr != nil {
			return 0, decErr
		}
		copy(p[:n], decrypted)
	}
	return n, err
}

// EncodeName 使用 MixBase64 编码文件名（兼容 alist-encrypt）
func EncodeName(password string, encType EncryptionType, plainName string) string {
	passwdOutward := GetPasswdOutward(password, encType)
	mix64 := NewMixBase64(passwdOutward, "")
	encodeName := mix64.Encode([]byte(plainName))
	// 添加 CRC6 校验位
	crc6Bit := crc6.Checksum([]byte(encodeName + passwdOutward))
	crc6Check := GetSourceChar(int(crc6Bit))
	return encodeName + string(crc6Check)
}

// DecodeName 使用 MixBase64 解码文件名（兼容 alist-encrypt）
func DecodeName(password string, encType EncryptionType, encodedName string) string {
	if len(encodedName) < 2 {
		return ""
	}
	
	crc6Check := encodedName[len(encodedName)-1]
	passwdOutward := GetPasswdOutward(password, encType)
	
	// 验证 CRC6
	subEncName := encodedName[:len(encodedName)-1]
	crc6Bit := crc6.Checksum([]byte(subEncName + passwdOutward))
	if GetSourceChar(int(crc6Bit)) != crc6Check {
		return ""
	}
	
	mix64 := NewMixBase64(passwdOutward, "")
	decoded, err := mix64.Decode(subEncName)
	if err != nil {
		return ""
	}
	
	return string(decoded)
}

// ConvertRealName 将显示名转换为真实加密名
func ConvertRealName(password string, encType EncryptionType, pathText string) string {
	fileName := path.Base(pathText)
	
	// 检查是否有 orig_ 前缀（表示原始未加密文件）
	if strings.HasPrefix(fileName, "orig_") {
		return strings.TrimPrefix(fileName, "orig_")
	}
	
	// 编码文件名
	ext := path.Ext(fileName)
	nameWithoutExt := strings.TrimSuffix(fileName, ext)
	encName := EncodeName(password, encType, nameWithoutExt)
	return encName + ext
}

// ConvertShowName 将加密名转换为显示名
func ConvertShowName(password string, encType EncryptionType, pathText string) string {
	fileName := path.Base(pathText)
	ext := path.Ext(fileName)
	encName := strings.TrimSuffix(fileName, ext)
	
	// 尝试解码
	showName := DecodeName(password, encType, encName)
	if showName == "" {
		// 解码失败，添加 orig_ 前缀表示原始文件
		return "orig_" + fileName
	}
	
	return showName + ext
}

// EncryptFilename 加密文件名（简单封装）
func EncryptFilename(password string, encType EncryptionType, filename string) (string, error) {
	return EncodeName(password, encType, filename), nil
}

// DecryptFilename 解密文件名（简单封装）
func DecryptFilename(password string, encType EncryptionType, encryptedName string) (string, error) {
	result := DecodeName(password, encType, encryptedName)
	if result == "" {
		return "", errors.New("failed to decrypt filename")
	}
	return result, nil
}