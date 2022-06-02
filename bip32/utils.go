package bip32

import (
	"crypto/sha256"
	"encoding/binary"
	"golang.org/x/crypto/ripemd160"
	"io"
)

// uint32ToBytes returns the big-endian encoding of the passed uint32 value as a byte slice.
// 也可以通过以下的方式：
// bytes := (*[4]byte)(unsafe.Pointer(&i))[:]
func uint32ToBytes(i uint32) []byte {
	bytes := make([]byte, 4)
	binary.BigEndian.PutUint32(bytes, i)
	return bytes
}

// hashSha256 returns the sha256 hash of the given data.
func hashSha256(data []byte) ([]byte, error) {
	hasher := sha256.New()
	_, err := hasher.Write(data)
	if err != nil {
		return nil, err
	}
	return hasher.Sum(nil), nil
}

// hashDoubleSha256 returns the double sha256 hash of the given data.
func hashDoubleSha256(data []byte) ([]byte, error) {
	hash1, err := hashSha256(data)
	if err != nil {
		return nil, err
	}

	hash2, err := hashSha256(hash1)
	if err != nil {
		return nil, err
	}
	return hash2, nil
}

// hashRipeMD160 returns the ripemd160 hash of the given data.
func hashRipeMD160(data []byte) ([]byte, error) {
	hasher := ripemd160.New()
	_, err := io.WriteString(hasher, string(data))
	if err != nil {
		return nil, err
	}
	return hasher.Sum(nil), nil
}

// hash160 returns the ripemd160 hash of the sha256 hash of the given data.
func hash160(data []byte) ([]byte, error) {
	hash1, err := hashSha256(data)
	if err != nil {
		return nil, err
	}

	hash2, err := hashRipeMD160(hash1)
	if err != nil {
		return nil, err
	}

	return hash2, nil
}
