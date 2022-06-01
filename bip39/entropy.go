package bip39

import (
	"crypto/rand"
	"errors"
)

var ErrInvalidEntropyLength = errors.New("entropy length must be [128, 256] bits")

type Entropy struct {
	bits []byte
}

// NewEntropy returns a new Entropy instance.
func NewEntropy(bitSize int) *Entropy {
	// 校验长度
	err := validateEntropyBitLen(bitSize)
	if err != nil {
		return nil
	}

	// 生成随机熵
	entropy := make([]byte, bitSize/8)
	_, err = rand.Read(entropy)
	return &Entropy{entropy}
}

// validateEntropyBitLen returns an error if bitSize is not a valid entropy length. 常见的有 128, 160, 192, 224, 256
func validateEntropyBitLen(bitLen int) error {
	// 必须被 32 整除
	if bitLen%32 != 0 {
		return ErrInvalidEntropyLength
	}
	// 必须在 [128, 256] 之间
	if bitLen < 128 || bitLen > 256 {
		return ErrInvalidEntropyLength
	}
	return nil
}
