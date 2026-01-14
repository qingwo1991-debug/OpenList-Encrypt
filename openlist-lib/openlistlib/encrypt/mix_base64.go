package encrypt

import (
	"crypto/sha256"
)

const base64Source = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-~+"

// MixBase64 自定义的 Base64 编码器
type MixBase64 struct {
	chars    []byte
	mapChars map[byte]int
}

// NewMixBase64 创建 MixBase64 编码器
func NewMixBase64(password string, salt string) *MixBase64 {
	if salt == "" {
		salt = "mix64"
	}

	var secret string
	if len(password) == 64 {
		secret = password
	} else {
		secret = initKSA(password + salt)
	}

	chars := []byte(secret)
	mapChars := make(map[byte]int)
	for i, c := range chars {
		mapChars[c] = i
	}

	return &MixBase64{
		chars:    chars,
		mapChars: mapChars,
	}
}

// initKSA 使用 SHA256 初始化 KSA
func initKSA(passwd string) string {
	key := sha256.Sum256([]byte(passwd))

	K := make([]int, len(base64Source))
	sbox := make([]int, len(base64Source))
	sourceKey := []byte(base64Source)

	// 初始化 sbox
	for i := 0; i < len(base64Source); i++ {
		sbox[i] = i
	}

	// 用种子密钥对 K 表进行填充
	for i := 0; i < len(base64Source); i++ {
		K[i] = int(key[i%len(key)])
	}

	// 对 S 表进行置换
	j := 0
	for i := 0; i < len(base64Source); i++ {
		j = (j + sbox[i] + K[i]) % len(base64Source)
		sbox[i], sbox[j] = sbox[j], sbox[i]
	}

	secret := make([]byte, len(base64Source))
	for i, v := range sbox {
		secret[i] = sourceKey[v]
	}

	return string(secret)
}

// Encode 编码数据
func (m *MixBase64) Encode(data []byte) string {
	if len(data) == 0 {
		return ""
	}

	result := make([]byte, 0, (len(data)*4+2)/3)

	for i := 0; i < len(data); i += 3 {
		if i+3 > len(data) {
			// 处理末尾
			remaining := len(data) - i
			if remaining == 1 {
				result = append(result, m.chars[data[i]>>2])
				result = append(result, m.chars[(data[i]&3)<<4])
				result = append(result, m.chars[64])
				result = append(result, m.chars[64])
			} else if remaining == 2 {
				result = append(result, m.chars[data[i]>>2])
				result = append(result, m.chars[((data[i]&3)<<4)|(data[i+1]>>4)])
				result = append(result, m.chars[(data[i+1]&15)<<2])
				result = append(result, m.chars[64])
			}
		} else {
			b0, b1, b2 := data[i], data[i+1], data[i+2]
			result = append(result, m.chars[b0>>2])
			result = append(result, m.chars[((b0&3)<<4)|(b1>>4)])
			result = append(result, m.chars[((b1&15)<<2)|(b2>>6)])
			result = append(result, m.chars[b2&63])
		}
	}

	return string(result)
}

// Decode 解码数据
func (m *MixBase64) Decode(encoded string) ([]byte, error) {
	if len(encoded) == 0 {
		return nil, nil
	}

	// 计算输出大小
	size := (len(encoded) / 4) * 3
	padChar := m.chars[64]

	// 检查填充
	if len(encoded) >= 2 && encoded[len(encoded)-1] == padChar && encoded[len(encoded)-2] == padChar {
		size -= 2
	} else if len(encoded) >= 1 && encoded[len(encoded)-1] == padChar {
		size -= 1
	}

	result := make([]byte, 0, size)

	for i := 0; i < len(encoded); i += 4 {
		enc1 := m.mapChars[encoded[i]]
		enc2 := m.mapChars[encoded[i+1]]
		enc3 := m.mapChars[encoded[i+2]]
		enc4 := m.mapChars[encoded[i+3]]

		result = append(result, byte((enc1<<2)|(enc2>>4)))
		if enc3 != 64 {
			result = append(result, byte(((enc2&15)<<4)|(enc3>>2)))
		}
		if enc4 != 64 {
			result = append(result, byte(((enc3&3)<<6)|enc4))
		}
	}

	return result, nil
}

// GetSourceChar 获取源字符
func GetSourceChar(index int) byte {
	chars := []byte(base64Source)
	if index >= 0 && index < len(chars) {
		return chars[index]
	}
	return 0
}

// GetCheckBit 获取校验位
func GetCheckBit(text string) byte {
	data := []byte(text)
	count := 0
	for _, b := range data {
		count += int(b)
	}
	count %= 64
	return []byte(base64Source)[count]
}