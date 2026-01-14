package encrypt

// CRC6 计算器
type CRC6 struct {
	table [256]byte
}

// NewCRC6 创建 CRC6 计算器
func NewCRC6() *CRC6 {
	c := &CRC6{}
	c.initTable()
	return c
}

// initTable 初始化 CRC 查找表
func (c *CRC6) initTable() {
	poly := byte(0x03) // CRC-6 多项式

	for i := 0; i < 256; i++ {
		crc := byte(i)
		for j := 0; j < 8; j++ {
			if crc&0x80 != 0 {
				crc = (crc << 1) ^ (poly << 2)
			} else {
				crc <<= 1
			}
		}
		c.table[i] = crc >> 2
	}
}

// Checksum 计算 CRC6 校验和
func (c *CRC6) Checksum(data []byte) byte {
	crc := byte(0)
	for _, b := range data {
		crc = c.table[crc^b]
	}
	return crc & 0x3F // 6 位
}

// CRC8 计算器
type CRC8 struct {
	table [256]byte
}

// NewCRC8 创建 CRC8 计算器
func NewCRC8() *CRC8 {
	c := &CRC8{}
	c.initTable()
	return c
}

// initTable 初始化 CRC 查找表
func (c *CRC8) initTable() {
	poly := byte(0x07) // CRC-8 多项式

	for i := 0; i < 256; i++ {
		crc := byte(i)
		for j := 0; j < 8; j++ {
			if crc&0x80 != 0 {
				crc = (crc << 1) ^ poly
			} else {
				crc <<= 1
			}
		}
		c.table[i] = crc
	}
}

// Checksum 计算 CRC8 校验和
func (c *CRC8) Checksum(data []byte) byte {
	crc := byte(0)
	for _, b := range data {
		crc = c.table[crc^b]
	}
	return crc
}