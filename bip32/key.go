package bip32

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"github.com/mndrix/btcutil"
	"math/big"
)

var (
	// ErrInvalidKey is returned when a key is invalid.
	ErrInvalidKey  = errors.New("invalid key")
	ErrHardenedKey = errors.New("hardened key")
)

var (
	curve = btcutil.Secp256k1()
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
func (k *PublicKey) Derive(childIdx uint32) (*PublicKey, error) {
	// HardenedKey
	if childIdx >= HardenedKeyZeroIndex {
		return nil, ErrHardenedKey
	}
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

func (k *PrivateKey) getIntermediary(childIdx uint32) ([]byte, error) {
	// Create the data to be hashed.
	data := make([]byte, 37)
	// Prefix Version
	copy(data[:4], k.Version)
	if childIdx >= HardenedKeyZeroIndex {
		data = append([]byte{0x0}, k.Data...)
	} else {
		copy(data[4:34], k.Data)
	}
	copy(data[34:37], uint32ToBytes(childIdx))
	// Create the HMAC.
	hmacCode := hmac.New(sha512.New, k.ChainCode)
	hmacCode.Write(data)
	intermediary := hmacCode.Sum(nil)

	return intermediary, nil
}

func (k *PrivateKey) Derive(childIdx uint32) (*PrivateKey, error) {
	intermediary, err := k.getIntermediary(childIdx)
	if err != nil {
		return nil, err
	}

	// Create child Key with data common to all both scenarios
	childKey := &PrivateKey{
		PublicKey: PublicKey{
			ChainCode:  intermediary[32:],
			ChildIndex: childIdx,
			Level:      k.Level + 1,
			//ParentFP:   k.PublicKey.ParentFP,
			Version: k.PublicKey.Version,
		},
		Data:    intermediary[:32],
		Version: k.Version,
	}

	// int to []byte
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.LittleEndian, PrivateKeyPrefix)

	childKey.Version = buf.Bytes()
	fingerprint, err := hash160(publicKeyForPrivateKey(k.Data))
	if err != nil {
		return nil, err
	}
	childKey.ParentFP = fingerprint[:4]
		childKey.Data = addPrivateKeys(intermediary[:32], k.Data)
	return nil, nil
}

func (k *PrivateKey) DeriveWithPath(path string) (*PrivateKey, error) {
	return nil, nil
}

func (k *PrivateKey) Serialize() []byte {
	keyBytes := k.Data
	keyBytes = append([]byte{0x0}, keyBytes...)
	// Write fields to buffer in order
	buffer := new(bytes.Buffer)
	buffer.WriteByte(PrivateKeyPrefix)
	buffer.WriteByte(k.Level)
	buffer.Write(k.ParentFP)
	buffer.Write(uint32ToBytes(k.ChildIndex))
	buffer.Write(k.ChainCode)
	buffer.Write(keyBytes)

	// Append the standard double sha256 checksum
	serializedKey, err := addChecksumToBytes(buffer.Bytes())
	if err != nil {
		return nil
	}
	return serializedKey
}

func (k *PrivateKey) String() string {
	return ""
}

func (k *PrivateKey) ToPublicKey() *PublicKey {
	// private key to public key
	return nil
}

// addPrivateKeys adds two private keys together.
func addPrivateKeys(key1 []byte, key2 []byte) []byte {
	var key1Int big.Int
	var key2Int big.Int
	key1Int.SetBytes(key1)
	key2Int.SetBytes(key2)

	key1Int.Add(&key1Int, &key2Int)
	key1Int.Mod(&key1Int, curve.Params().N)

	b := key1Int.Bytes()
	if len(b) < 32 {
		extra := make([]byte, 32-len(b))
		b = append(extra, b...)
	}
	return b
}

// publicKeyForPrivateKey calculates the corresponding public key for a private key.
func publicKeyForPrivateKey(key []byte) []byte {
	// private key to public key
	return compressPublicKey(curve.ScalarBaseMult(key))
}

// compressPublicKey compresses a public key.
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

// checksum calculates the checksum for a key.
func checksum(data []byte) ([]byte, error) {
	hash, err := hashDoubleSha256(data)
	if err != nil {
		return nil, err
	}

	return hash[:4], nil
}

// addChecksumToBytes adds a checksum to a byte slice.
func addChecksumToBytes(data []byte) ([]byte, error) {
	checksum, err := checksum(data)
	if err != nil {
		return nil, err
	}
	return append(data, checksum...), nil
}
