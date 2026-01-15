package encrypt

import (
	"crypto/md5"
	"encoding/binary"
	"encoding/hex"
)

// SegmentPosition 重置 S-box 的位置间隔 (1MB)
const SegmentPosition = 100 * 10000

// CustomRC4 实现兼容 Node.js 版本的 RC4 算法
type CustomRC4 struct {
	password      string
	sizeSalt      string
	passwdOutward string
	fileHexKey    string // string of hex
	
	sbox [256]int
	i    int
	j    int
	position int64
}

// NewCustomRC4 创建 CustomRC4 实例
func NewCustomRC4(password, sizeSalt, passwdOutward string) *CustomRC4 {
	// fileHexKey: md5(passwdOutward + sizeSalt)
	passwdSalt := passwdOutward + sizeSalt
	hash := md5.Sum([]byte(passwdSalt))
	fileHexKey := hex.EncodeToString(hash[:])

	rc4 := &CustomRC4{
		password:      password,
		sizeSalt:      sizeSalt,
		passwdOutward: passwdOutward,
		fileHexKey:    fileHexKey,
		position:      0,
	}
	rc4.resetKSA()
	return rc4
}

// initKSA 初始化 KSA
func (c *CustomRC4) initKSA(key []byte) {
	// Init sbox
	for i := 0; i < 256; i++ {
		c.sbox[i] = i
	}
	
	kLen := len(key)
	K := make([]int, 256)
	for i := 0; i < 256; i++ {
		K[i] = int(key[i%kLen])
	}

	j := 0
	for i := 0; i < 256; i++ {
		j = (j + c.sbox[i] + K[i]) % 256
		c.sbox[i], c.sbox[j] = c.sbox[j], c.sbox[i]
	}
	
	c.i = 0
	c.j = 0
}

// resetKSA 重置 S-box
func (c *CustomRC4) resetKSA() {
	offset := int(c.position / SegmentPosition) * SegmentPosition
	buf := make([]byte, 4)
	binary.BigEndian.PutUint32(buf, uint32(offset))
	
	// rc4Key = Buffer.from(fileHexKey, 'hex')
	rc4Key, _ := hex.DecodeString(c.fileHexKey)
	
	// XOR last bytes with offset
	j := len(rc4Key) - len(buf)
	for i := 0; i < len(buf); i++ {
		rc4Key[j] ^= buf[i]
		j++
	}
	
	c.initKSA(rc4Key)
}

// XORKeyStream 加密/解密数据
func (c *CustomRC4) XORKeyStream(dst, src []byte) {
	for k := 0; k < len(src); k++ {
		c.i = (c.i + 1) % 256
		c.j = (c.j + c.sbox[c.i]) % 256
		c.sbox[c.i], c.sbox[c.j] = c.sbox[c.j], c.sbox[c.i]
		
		val := src[k] ^ byte(c.sbox[(c.sbox[c.i]+c.sbox[c.j])%256])
		dst[k] = val
		
		c.position++
		if c.position%SegmentPosition == 0 {
			// Save current i, j ??
			// Node.js implementation:
			// if (++this.position % segmentPosition === 0) {
			//   this.resetKSA()
			//   i = this.i
			//   j = this.j
			//   S = this.sbox // But initKSA resets i=0, j=0!
			// }
			// Wait, let's check Node.js code carefully
			
			c.resetKSA()
			// Node.js:
			// resetKSA() -> calls initKSA() -> sets i=0, j=0.
			// Then: i = this.i; j = this.j; S = this.sbox;
			// So effectively, after reset at boundary, i and j are reset to 0 in local vars too?
			// Node.js loop uses local i, j. 
			// "i = this.i" where this.i is 0 from initKSA.
			// So yes, state resets completely (re-init KSA with new key derived from offset).
		}
	}
}

// SetPosition 设置位置
func (c *CustomRC4) SetPosition(pos int64) {
	c.position = pos
	c.resetKSA()
	
	// PRGAExecPostion(newPosition % segmentPosition)
	c.prgaExecPosition(int(pos % SegmentPosition))
}

// prgaExecPosition 空跑 PRGA 到指定偏移
func (c *CustomRC4) prgaExecPosition(plainLen int) {
	for k := 0; k < plainLen; k++ {
		c.i = (c.i + 1) % 256
		c.j = (c.j + c.sbox[c.i]) % 256
		c.sbox[c.i], c.sbox[c.j] = c.sbox[c.j], c.sbox[c.i]
	}
}