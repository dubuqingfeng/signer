package bip32

type Key struct {
	PublicKey  []byte
	PrivateKey []byte
}

type BIP32Key struct {
}

func (k *BIP32Key) Derive(path string) (*Key, error) {
	return nil, nil
}

func (k *BIP32Key) DeriveWithPath(path string) (*Key, error) {
	return nil, nil
}
