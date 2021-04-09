package edx

import (
	"math/big"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha512"
	"golang.org/x/crypto/curve25519"
)

var (
	xPrime, _ = new(big.Int).SetString(
		"57896044618658097711785492504343953926634992332820282019728792003956564819949",
		10,
	)
)

func GenerateKeyPair() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	return ed25519.GenerateKey(rand.Reader)
}

func SeedKeyPair(seed []byte) (ed25519.PublicKey, ed25519.PrivateKey) {
	if len(seed) != ed25519.PrivateKeySize {
		h := sha512.Sum512(seed)
		seed = make([]byte, ed25519.PrivateKeySize)
		copy(seed, h[:ed25519.PrivateKeySize])
	}
	priv := ed25519.NewKeyFromSeed(seed)
	return priv.Public().(ed25519.PublicKey), priv
}

func Sign(priv ed25519.PrivateKey, data []byte) []byte {
	return ed25519.Sign(priv, data)
}

func Verify(pub ed25519.PublicKey, data, signature []byte) bool {
	return ed25519.Verify(pub, data, signature)
}

func CalculateSharedKey(pub ed25519.PublicKey, priv ed25519.PrivateKey) []byte {
	k := [curve25519.ScalarSize]byte{}
	cpub := [curve25519.ScalarSize]byte{}
	cpriv := [curve25519.ScalarSize]byte{}
	copy(cpub[:], publicKeyToCurve(pub))
	copy(cpriv[:], privateKeyToCurve(priv))
	curve25519.ScalarMult(&k, &cpriv, &cpub)
	return k[:]
}

func publicKeyToCurve(pub ed25519.PublicKey) []byte {
	p := flip(pub)
	p[0] &= 0b0111_1111
	y := new(big.Int).SetBytes(p)
	d := big.NewInt(1)
	d.ModInverse(d.Sub(d, y), xPrime)
	u := y.Mul(y.Add(y, big.NewInt(1)), d)
	u.Mod(u, xPrime)
	return flip(u.Bytes()[:curve25519.ScalarSize])
}

func privateKeyToCurve(priv ed25519.PrivateKey) []byte {
	h := sha512.New()
	h.Write(priv.Seed())
	k := h.Sum(nil)
	k[0] &= 248
	k[31] &= 127
	k[31] |= 64
	return k[:curve25519.ScalarSize]
}

func flip(in []byte) []byte {
	r := make([]byte, len(in))
	for i, b := range in {
		r[len(in)-i-1] = b
	}
	return r
}
