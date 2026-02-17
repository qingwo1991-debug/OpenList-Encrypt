package encrypt

import (
	"crypto/md5"
	"encoding/binary"
	"strconv"
)

// ChaCha20Encryptor ChaCha20 流加密器
type ChaCha20Encryptor struct {
	key       []byte
	nonce     []byte
	counter   uint32
	keystream [64]byte
	position  int64
	byteIdx   int // 当前 keystream 中的位置
	param     [16]uint32
}

// sigma 是 ChaCha20 的常量 "expand 32-byte k"
var sigma = [4]uint32{0x61707865, 0x3320646e, 0x79622d32, 0x6b206574}

// NewChaCha20Encryptor 创建 ChaCha20 加密器 (兼容 alist-encrypt)
func NewChaCha20Encryptor(password, passwdOutward string, fileSize int64) (*ChaCha20Encryptor, error) {
	sizeSalt := strconv.FormatInt(fileSize, 10)
	passwdSalt := passwdOutward + sizeSalt

	// 生成 32 字节密钥: 使用两个 MD5
	hash1 := md5.Sum([]byte(passwdSalt))
	hash2 := md5.Sum([]byte(sizeSalt + passwdOutward))
	key := make([]byte, 32)
	copy(key[:16], hash1[:])
	copy(key[16:], hash2[:])

	// 生成 12 字节 nonce
	hashNonce := md5.Sum([]byte(sizeSalt))
	nonce := hashNonce[:12]

	enc := &ChaCha20Encryptor{
		key:     key,
		nonce:   nonce,
		counter: 0,
		byteIdx: 64, // 强制首次调用时生成 keystream
	}

	enc.initParam()
	return enc, nil
}

// initParam 初始化 ChaCha20 状态
func (c *ChaCha20Encryptor) initParam() {
	c.param[0] = sigma[0]
	c.param[1] = sigma[1]
	c.param[2] = sigma[2]
	c.param[3] = sigma[3]

	// key (8 个 uint32)
	c.param[4] = binary.LittleEndian.Uint32(c.key[0:4])
	c.param[5] = binary.LittleEndian.Uint32(c.key[4:8])
	c.param[6] = binary.LittleEndian.Uint32(c.key[8:12])
	c.param[7] = binary.LittleEndian.Uint32(c.key[12:16])
	c.param[8] = binary.LittleEndian.Uint32(c.key[16:20])
	c.param[9] = binary.LittleEndian.Uint32(c.key[20:24])
	c.param[10] = binary.LittleEndian.Uint32(c.key[24:28])
	c.param[11] = binary.LittleEndian.Uint32(c.key[28:32])

	// counter
	c.param[12] = c.counter

	// nonce (3 个 uint32)
	c.param[13] = binary.LittleEndian.Uint32(c.nonce[0:4])
	c.param[14] = binary.LittleEndian.Uint32(c.nonce[4:8])
	c.param[15] = binary.LittleEndian.Uint32(c.nonce[8:12])
}

// quarterRound ChaCha20 四分之一轮
func quarterRound(state *[16]uint32, a, b, c, d int) {
	state[a] += state[b]
	state[d] ^= state[a]
	state[d] = (state[d] << 16) | (state[d] >> 16)

	state[c] += state[d]
	state[b] ^= state[c]
	state[b] = (state[b] << 12) | (state[b] >> 20)

	state[a] += state[b]
	state[d] ^= state[a]
	state[d] = (state[d] << 8) | (state[d] >> 24)

	state[c] += state[d]
	state[b] ^= state[c]
	state[b] = (state[b] << 7) | (state[b] >> 25)
}

// chacha 生成 64 字节 keystream
func (c *ChaCha20Encryptor) chacha() {
	var mix [16]uint32
	copy(mix[:], c.param[:])

	// 20 轮
	for i := 0; i < 10; i++ {
		// 列轮
		quarterRound(&mix, 0, 4, 8, 12)
		quarterRound(&mix, 1, 5, 9, 13)
		quarterRound(&mix, 2, 6, 10, 14)
		quarterRound(&mix, 3, 7, 11, 15)
		// 对角轮
		quarterRound(&mix, 0, 5, 10, 15)
		quarterRound(&mix, 1, 6, 11, 12)
		quarterRound(&mix, 2, 7, 8, 13)
		quarterRound(&mix, 3, 4, 9, 14)
	}

	// 加上原始状态并存储 keystream
	for i := 0; i < 16; i++ {
		mix[i] += c.param[i]
		binary.LittleEndian.PutUint32(c.keystream[i*4:], mix[i])
	}
}

// Encrypt 加密数据
func (c *ChaCha20Encryptor) Encrypt(data []byte) ([]byte, error) {
	result := make([]byte, len(data))
	for i := range data {
		if c.byteIdx >= 64 {
			c.chacha()
			c.param[12]++ // 增加 counter
			c.byteIdx = 0
		}
		result[i] = data[i] ^ c.keystream[c.byteIdx]
		c.byteIdx++
	}
	c.position += int64(len(data))
	return result, nil
}

// Decrypt 解密数据 (ChaCha20 是对称的)
func (c *ChaCha20Encryptor) Decrypt(data []byte) ([]byte, error) {
	return c.Encrypt(data)
}

// EncryptInplace 原地加密，减少每块内存分配
func (c *ChaCha20Encryptor) EncryptInplace(data []byte) error {
	for i := range data {
		if c.byteIdx >= 64 {
			c.chacha()
			c.param[12]++
			c.byteIdx = 0
		}
		data[i] ^= c.keystream[c.byteIdx]
		c.byteIdx++
	}
	c.position += int64(len(data))
	return nil
}

// DecryptInplace 原地解密（ChaCha20 对称）
func (c *ChaCha20Encryptor) DecryptInplace(data []byte) error {
	return c.EncryptInplace(data)
}

// SetPosition 设置流位置
func (c *ChaCha20Encryptor) SetPosition(position int64) error {
	// 计算需要跳过的块数和块内偏移
	blockNum := position / 64
	blockOffset := int(position % 64)

	// 重置状态
	c.counter = uint32(blockNum)
	c.param[12] = c.counter
	c.byteIdx = 64 // 强制生成新 keystream

	// 如果有块内偏移，生成当前块并跳过
	if blockOffset > 0 {
		c.chacha()
		c.param[12]++
		c.byteIdx = blockOffset
	}

	c.position = position
	return nil
}

// GetPosition 获取当前位置
func (c *ChaCha20Encryptor) GetPosition() int64 {
	return c.position
}
