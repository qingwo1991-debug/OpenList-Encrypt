package encrypt

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rc4"
	"encoding/hex"
	"errors"
	"io"
)

// EncryptionType 加密类型
type EncryptionType string

const (
	EncTypeAESCTR EncryptionType = "aes-ctr"
	EncTypeRC4    EncryptionType = "rc4md5"
)

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
	case EncTypeAESCTR:
		return NewAESCTREncryptor(password, fileSize)
	case EncTypeRC4:
		return NewRC4MD5Encryptor(password, fileSize)
	default:
		return nil, errors.New("unsupported encryption type: " + string(encType))
	}
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

// EncryptFilename 加密文件名
func EncryptFilename(password string, encType EncryptionType, filename string) (string, error) {
	encryptor, err := NewFlowEncryptor(password, encType, int64(len(filename)))
	if err != nil {
		return "", err
	}
	
	encrypted, err := encryptor.Encrypt([]byte(filename))
	if err != nil {
		return "", err
	}
	
	return hex.EncodeToString(encrypted), nil
}

// DecryptFilename 解密文件名
func DecryptFilename(password string, encType EncryptionType, encryptedName string) (string, error) {
	data, err := hex.DecodeString(encryptedName)
	if err != nil {
		return "", err
	}
	
	encryptor, err := NewFlowEncryptor(password, encType, int64(len(data)))
	if err != nil {
		return "", err
	}
	
	decrypted, err := encryptor.Decrypt(data)
	if err != nil {
		return "", err
	}
	
	return string(decrypted), nil
}