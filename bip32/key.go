package bip32

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha512"
	"math/big"
)

// PublicKey is the structure layout for an extended public key.
type PublicKey struct {
	ChainCode  []byte
	ChildIndex uint32 // The index of the child key in the parent key.
	Data       []byte // The public key data.
	Level      uint8  // The level of the key. Depth.
	ParentFP   []byte // The parent fingerprint.
	Version    []byte // The version of the key.
}

// PrivateKey is the structure layout for an extended private key.
type PrivateKey struct {
	PublicKey
	Data    []byte
	Version []byte
}

// NewMasterKey creates a new master key.
func NewMasterKey(seed []byte) (*PrivateKey, error) {
	hmac := hmac.New(sha512.New, []byte("Bitcoin seed"))
	hmac.Write(seed)
	intermediary := hmac.Sum(nil)

	// Split the intermediary into the private key and chain code.
	privateKey := intermediary[:32]
	chainCode := intermediary[32:]

	// Create the public key.
	key, err := NewMasterKeyFromKeyAndChainCode(privateKey, chainCode)
	if err != nil {
		return nil, err
	}

	return key, nil
}

func NewMasterKeyFromKeyAndChainCode(privateKey, chainCode []byte) (*PrivateKey, error) {
	return &PrivateKey{PublicKey: PublicKey{ChainCode: chainCode}, Data: privateKey}, nil
}

func NewMasterKeyFromExtendKey(key *PublicKey) (*PrivateKey, error) {
	return nil, nil
}

// Derive CKD priv derives a private key from a parent private key and a child index.
func (k *PublicKey) Derive(path string) (*PublicKey, error) {
	return nil, nil
}

func (k *PublicKey) DeriveWithPath(path string) (*PublicKey, error) {
	return nil, nil
}

func (k *PublicKey) Serialize() []byte {
	return nil
}

func (k *PublicKey) String() string {
	return ""
}

func (k *PrivateKey) Derive(path string) (*PrivateKey, error) {
	return nil, nil
}

func (k *PrivateKey) DeriveWithPath(path string) (*PrivateKey, error) {
	return nil, nil
}

func (k *PrivateKey) Serialize() []byte {
	return nil
}

func (k *PrivateKey) String() string {
	return ""
}

func (k *PrivateKey) ToPublicKey() *PublicKey {
	// private key to public key
	return nil
}

func compressPublicKey(x *big.Int, y *big.Int) []byte {
	var key bytes.Buffer
	key.WriteByte(byte(0x2) + byte(y.Bit(0)))
	xBytes := x.Bytes()
	for i := 0; i < (33 - 1 - len(xBytes)); i++ {
		key.WriteByte(0x0)
	}
	key.Write(xBytes)
	return key.Bytes()
}
