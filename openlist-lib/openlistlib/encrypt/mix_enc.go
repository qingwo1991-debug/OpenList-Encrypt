package encrypt

import (
	"crypto/md5"
	"crypto/sha256"
)

// MixEncryptor Mix 混淆加密器
// 加密强度较低，容易因为文件特征被破解，但速度快
type MixEncryptor struct {
	password      string
	passwdOutward string
	encode        []byte
	decode        []byte
	position      int64
	fileSize      int64
}

// NewMixEncryptor 创建 Mix 加密器
func NewMixEncryptor(password string, fileSize int64) (*MixEncryptor, error) {
	e := &MixEncryptor{
		password: password,
		position: 0,
		fileSize: fileSize,
	}

	// 创建对外密码
	if len(password) != 32 {
		e.passwdOutward = deriveKeyHex(password, "MIX", 16)
	} else {
		e.passwdOutward = password
	}

	// 创建编码表
	hash := sha256.Sum256([]byte(e.passwdOutward))
	encode := make([]byte, 32)
	copy(encode, hash[:])

	length := len(encode)
	decode := make([]byte, length)
	decodeCheck := make(map[int]byte)

	for i := 0; i < length; i++ {
		enc := int(encode[i]) ^ i
		if _, exists := decodeCheck[enc%length]; !exists {
			decode[enc%length] = encode[i] & 0xff
			decodeCheck[enc%length] = encode[i]
		} else {
			// 处理冲突
			for j := 0; j < length; j++ {
				if _, exists := decodeCheck[j]; !exists {
					encode[i] = (encode[i] & byte(length)) | byte(j^i)
					decode[j] = encode[i] & 0xff
					decodeCheck[j] = encode[i]
					break
				}
			}
		}
	}

	e.encode = encode
	e.decode = decode

	return e, nil
}

// deriveKeyHex 从密码派生密钥并返回十六进制字符串
func deriveKeyHex(password, salt string, length int) string {
	result := make([]byte, 0, length*2)
	data := []byte(password + salt)

	iterations := 1000
	for i := 0; i < iterations && len(result) < length*2; i++ {
		hash := md5.Sum(data)
		for _, b := range hash[:] {
			if len(result) >= length*2 {
				break
			}
			result = append(result, "0123456789abcdef"[b>>4])
			result = append(result, "0123456789abcdef"[b&0x0f])
		}
		data = append(hash[:], []byte(password+salt)...)
	}

	return string(result[:length*2])
}

// SetPosition 设置流位置
func (e *MixEncryptor) SetPosition(position int64) error {
	e.position = position
	return nil
}

// GetPosition 获取当前位置
func (e *MixEncryptor) GetPosition() int64 {
	return e.position
}

// Encrypt 加密数据
func (e *MixEncryptor) Encrypt(data []byte) ([]byte, error) {
	result := make([]byte, len(data))
	copy(result, data)

	for i := len(result) - 1; i >= 0; i-- {
		result[i] ^= e.encode[result[i]%32]
	}

	e.position += int64(len(data))
	return result, nil
}

// Decrypt 解密数据
func (e *MixEncryptor) Decrypt(data []byte) ([]byte, error) {
	result := make([]byte, len(data))
	copy(result, data)

	for i := len(result) - 1; i >= 0; i-- {
		result[i] ^= e.decode[result[i]%32]
	}

	e.position += int64(len(data))
	return result, nil
}

// GetPasswdOutward 获取外部密码
func (e *MixEncryptor) GetPasswdOutward() string {
	return e.passwdOutward
}