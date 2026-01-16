package encrypt

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/url"
	"path"
	"strconv"
	"strings"

	"golang.org/x/crypto/pbkdf2"
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
	iv       []byte
	sourceIv []byte
	position int64
	cipher   cipher.Stream
}

// NewAESCTREncryptor 创建 AES-CTR 加密器 (Node.js compatible)
func NewAESCTREncryptor(password, passwdOutward string, fileSize int64) (*AESCTREncryptor, error) {
	sizeSalt := strconv.FormatInt(fileSize, 10)
	passwdSalt := passwdOutward + sizeSalt

	// create file aes-ctr key: md5(passwdSalt)
	hash := md5.Sum([]byte(passwdSalt))
	key := hash[:]

	// iv: md5(sizeSalt)
	hashIv := md5.Sum([]byte(sizeSalt))
	iv := hashIv[:]
	sourceIv := make([]byte, len(iv))
	copy(sourceIv, iv)

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	stream := cipher.NewCTR(block, iv)

	return &AESCTREncryptor{
		key:      key,
		iv:       iv,
		sourceIv: sourceIv,
		position: 0,
		cipher:   stream,
	}, nil
}

// incrementIV 增加 IV
func (e *AESCTREncryptor) incrementIV(increment int64) {
	// copy sourceIv to iv
	iv := make([]byte, len(e.sourceIv))
	copy(iv, e.sourceIv)
	e.iv = iv

	// logic from Node.js incrementIV
	// Node.js uses 4 uint32 big endian
	// increment is passed as number (int in Go)
	// Node.js:
	// const MAX_UINT32 = 0xffffffff
	// const incrementBig = ~~(increment / MAX_UINT32)
	// const incrementLittle = (increment % MAX_UINT32) - incrementBig
	// Careful with negative values? increment should be positive.

	// Since Go int64 is large enough, we can implement simpler addition on 128-bit integer if we treat it as such.
	// But to matching exactly Node.js behavior (overflow/wrapping):
	// Node.js splits into 4 uint32s.

	// Be careful: Javascript numbers are doubles. MAX_UINT32 is 4294967295.
	// increment is int64.
	// 4294967295 matches math.MaxUint32.

	// Go implementation:
	// Treat IV as 128 bit integer (big endian). Add increment.
	// Or follow Node.js 4 chunks logic.

	// Let's implement generic 128-bit counter increment.
	// Since AES-CTR is just counter mode, we add increment to the counter.
	// IV is 16 bytes.
	// Treat as BigEndian uint128.

	// We can use math/big or just loop.
	carry := increment
	for i := 15; i >= 0; i-- {
		val := int64(e.iv[i]) + (carry & 0xFF)
		e.iv[i] = byte(val)
		carry = (carry >> 8) + (val >> 8)
	}
	// Note: Node.js implementation "incrementIV" does weird things with splitting 4 chunks.
	// "const incrementBig = ~~(increment / MAX_UINT32)"
	// "const incrementLittle = (increment % MAX_UINT32) - incrementBig"
	// Wait, (increment % MAX) - incrementBig ?? That seems wrong in JS logic unless incrementBig is small?
	// Actually (increment % MAX_UINT32) is the lower 32 bits.
	// If increment < MAX_UINT32, incrementBig is 0. incrementLittle = increment.
	// It seems Node.js implementation tries to handle > 32 bit increments.

	// Given standard CTR mode, we just add the offset (in blocks) to the IV.
	// My loop implementation above does standard addition.
	// Let's stick with standard addition which AES-CTR expects.
}

// SetPosition 设置流位置
func (e *AESCTREncryptor) SetPosition(position int64) error {
	increment := position / 16
	e.incrementIV(increment)

	block, err := aes.NewCipher(e.key)
	if err != nil {
		return err
	}
	e.cipher = cipher.NewCTR(block, e.iv)

	offset := int(position % 16)
	if offset > 0 {
		skip := make([]byte, offset)
		e.Encrypt(skip) // consumes keystream, output ignored
	}

	e.position = position // e.Encrypt updates this? No, e.Encrypt updates internal state?
	// e.Encrypt updates e.position if I modify it to do so.
	// Node.js doesn't seem to track position in property, but "this.encrypt" updates "this.cipher".
	// In Go, Encrypt calls XORKeyStream.
	// "e.Encrypt(skip)" below will update stream state.

	e.position = position
	return nil
}

// GetPosition 获取当前位置
func (e *AESCTREncryptor) GetPosition() int64 {
	return e.position
}

// Encrypt 加密数据
func (e *AESCTREncryptor) Encrypt(data []byte) ([]byte, error) {
	encrypted := make([]byte, len(data))
	e.cipher.XORKeyStream(encrypted, data)
	e.position += int64(len(data))
	return encrypted, nil
}

// Decrypt 解密数据
func (e *AESCTREncryptor) Decrypt(data []byte) ([]byte, error) {
	return e.Encrypt(data)
}

// RC4MD5Encryptor RC4-MD5 加密器 (Wrapper for CustomRC4)
type RC4MD5Encryptor struct {
	customRC4 *CustomRC4
}

// NewRC4MD5Encryptor 创建 RC4-MD5 加密器
func NewRC4MD5Encryptor(password, passwdOutward string, fileSize int64) (*RC4MD5Encryptor, error) {
	sizeSalt := strconv.FormatInt(fileSize, 10)
	cRC4 := NewCustomRC4(password, sizeSalt, passwdOutward)
	return &RC4MD5Encryptor{customRC4: cRC4}, nil
}

func (e *RC4MD5Encryptor) SetPosition(position int64) error {
	e.customRC4.SetPosition(position)
	return nil
}

func (e *RC4MD5Encryptor) GetPosition() int64 {
	return e.customRC4.position
}

func (e *RC4MD5Encryptor) Encrypt(data []byte) ([]byte, error) {
	dst := make([]byte, len(data))
	e.customRC4.XORKeyStream(dst, data)
	return dst, nil
}

func (e *RC4MD5Encryptor) Decrypt(data []byte) ([]byte, error) {
	return e.Encrypt(data)
}

// NewFlowEncryptor 创建流加密器
func NewFlowEncryptor(password string, encType EncryptionType, fileSize int64) (FlowEncryptor, error) {
	passwdOutward := GetPasswdOutward(password, encType)
	switch encType {
	case EncTypeAESCTR, "aesctr":
		return NewAESCTREncryptor(password, passwdOutward, fileSize)
	case EncTypeRC4, "rc4":
		return NewRC4MD5Encryptor(password, passwdOutward, fileSize)
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

	// Logic from Node.js (mixEnc.js, aesCTR.js, rc4Md5.js)
	// If password length != 32, use PBKDF2.
	// Salt depends on encryption type.

	salt := ""
	switch encType {
	case EncTypeMix:
		salt = "MIX"
	case EncTypeAESCTR, "aesctr":
		salt = "AES-CTR"
	case EncTypeRC4, "rc4":
		salt = "RC4"
	default:
		// Unknown type, assume password is raw? Or MIX default?
		salt = "MIX"
	}

	if len(password) != 32 {
		dk := pbkdf2.Key([]byte(password), []byte(salt), 1000, 16, sha256.New)
		passwdOutward = hex.EncodeToString(dk)
	} else {
		passwdOutward = password
	}

	passwdOutwardCache[key] = passwdOutward
	return passwdOutward
}

// deriveKeyHex is removed as it's no longer used, replaced by PBKDF2 logic inline or verify.

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
		fmt.Printf("Decode error: %v\n", err)
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

	// URL 解码
	if decoded, err := url.PathUnescape(nameWithoutExt); err == nil {
		nameWithoutExt = decoded
	}

	encName := EncodeName(password, encType, nameWithoutExt)
	return encName + ext
}

// ConvertShowName 将加密名转换为显示名
func ConvertShowName(password string, encType EncryptionType, pathText string) string {
	fileName := path.Base(pathText)

	// URL 解码
	if decoded, err := url.PathUnescape(fileName); err == nil {
		fileName = decoded
	}
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
