package bip44

type Purpose uint32

const (
	BIP44Purpose Purpose = 44
)

type CoinType uint32

const (
	BitcoinCoinType CoinType = 0
	TestnetCoinType CoinType = 1
)

const (
	// MainNetPublic represents the main network public derivation path
	MainNetPublic = 0x0
	// MainNetPrivate represents the main network private derivation path
	MainNetPrivate = 0x80000000
	// TestNetPublic represents the test network public derivation path
	TestNetPublic = 0x80000001
	// TestNetPrivate represents the test network private derivation path
	TestNetPrivate = 0x80000002
)

type Network struct {
	SegwitEnabled bool
	Coin          CoinType
}
