package bip32

const (
	// PublicKeyPrefix is the type of public key
	PublicKeyPrefix = 0x0488b21e
	// PrivateKeyPrefix is the type of private key
	PrivateKeyPrefix = 0x0488ade4
)

// HardenedKeyZeroIndex 强化衍生起始索引
const HardenedKeyZeroIndex = 0x80000000
