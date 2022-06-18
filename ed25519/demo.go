package main

import (
	"crypto/sha512"
	"fmt"
	"log"

	edwards "filippo.io/edwards25519"
	"github.com/mr-tron/base58/base58"
)

const DigestSize = 32
const SignatureSize = 64

type Signature [SignatureSize]byte

func (s Signature) Bytes() []byte {
	out := make([]byte, len(s))
	copy(out, s[:])
	return out
}

var PRIVATE_KEY = "0171ecab8a308cd26fef99efb7ea02fa17ec9c210d8e9f6e32543694a6623ece"

var prefix = []byte{
	0xfe, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
}

func main() {
	PRIVATE_KEY = "6QhEoSnJ12QDgeEAt3HYkPDBiYe15BArgSKWrV3DUctG"
	sk, err := NewSecretKeyFromBase58(PRIVATE_KEY)
	if err != nil {
		log.Fatalf("import private key error: %v", err)
	}
	//pk := GeneratePublicKey(sk)
	//fmt.Println(pk.String())

	got, err := Sign(sk, []byte("hello"))
	fmt.Println(got)
}


func (s Signature) String() string {
	return base58.Encode(s[:])
}

func Sign(secretKey SecretKey, data []byte) (Signature, error) {
	var sig Signature
	sks, err := edwards.NewScalar().SetBytesWithClamping(secretKey[:])
	if err != nil {
		return sig, err
	}
	fmt.Println(sks.Bytes())
	pkp := new(edwards.Point).ScalarBaseMult(sks)
	pkb := pkp.Bytes()
	sf := pkb[31] & 0x80

	//random := make([]byte, sha512.Size)
	//if _, err := rand.Read(random); err != nil {
	//	return sig, err
	//}
	random := []byte("hello")


	md := make([]byte, 0, sha512.Size)
	h := sha512.New()
	if _, err := h.Write(prefix); err != nil {
		return sig, err
	}
	if _, err := h.Write(sks.Bytes()); err != nil {
		return sig, err
	}
	if _, err := h.Write(data); err != nil {
		return sig, err
	}
	if _, err := h.Write(random); err != nil {
		return sig, err
	}
	md = h.Sum(md)
	fmt.Println("md:", md)

	rs, err := edwards.NewScalar().SetUniformBytes(md)
	if err != nil {
		return sig, err
	}

	rp := new(edwards.Point).ScalarBaseMult(rs)

	hd := make([]byte, 0, sha512.Size)
	h.Reset()
	fmt.Println("out2", rs.Bytes())
	fmt.Println("Rb:", rp.Bytes())

	if _, err := h.Write(rp.Bytes()); err != nil {
		return sig, err
	}
	if _, err := h.Write(pkb); err != nil {
		return sig, err
	}
	if _, err := h.Write(data); err != nil {
		return sig, err
	}
	hd = h.Sum(hd)
	fmt.Println(hd)

	ks, err := edwards.NewScalar().SetUniformBytes(hd)
	if err != nil {
		return sig, err
	}
	fmt.Println(ks.Bytes())

	ss := edwards.NewScalar().MultiplyAdd(ks, sks, rs)

	copy(sig[:DigestSize], rp.Bytes())
	copy(sig[DigestSize:], ss.Bytes())
	fmt.Println(ss.Bytes())

	sig[63] &= 0x7f
	sig[63] |= sf
	return sig, nil
}

func (k PublicKey) String() string {
	return base58.Encode(k[:])
}

func array32FromBase58(s, name string) ([32]byte, error) {
	var r [32]byte
	b, err := base58.Decode(s)
	if err != nil {
		return r, err
	}
	if l := len(b); l != 32 {
		return r, fmt.Errorf("incorrect %s length %d, expected %d", name, l, 32)
	}
	copy(r[:], b[:32])
	return r, nil
}

func NewSecretKeyFromBase58(s string) (SecretKey, error) {
	return array32FromBase58(s, "SecretKey")
}

type SecretKey [32]byte
type PublicKey [32]byte

func GeneratePublicKey(sk SecretKey) PublicKey {
	s, err := new(edwards.Scalar).SetBytesWithClamping(sk[:])
	if err != nil { // The only possible error is on size check
		fmt.Errorf("%v", err)
		return PublicKey{}
	}
	p := new(edwards.Point).ScalarBaseMult(s)
	var pk PublicKey
	copy(pk[:], p.BytesMontgomery())
	return pk
}

