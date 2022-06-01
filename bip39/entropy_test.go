package bip39

import "testing"

func TestValidateEntropyBitLen(t *testing.T) {
	length := 128
	err := validateEntropyBitLen(length)
	if err != nil {
		t.Errorf("Random entropy failed %s", err)
	}
}

func TestNewEntropy(t *testing.T) {
	length := 128
	entropy := NewEntropy(length)
	if len(entropy.bits) != length/8 {
		t.Errorf("Entropy length error")
	}
}
