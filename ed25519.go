package edx

import (
	"log"
	"math/big"
	"crypto/rand"
	"crypto/sha512"
	"crypto/ed25519"
)

type (
	// Ed25519PublicKey .
	Ed25519PublicKey ed25519.PublicKey
	// Ed25519PrivateKey .
	Ed25519PrivateKey ed25519.PrivateKey
	// Ed25519KeyPair .
	Ed25519KeyPair struct {
		Public Ed25519PublicKey
		Private Ed25519PrivateKey
	}
)

var (
	x25519P, _ = new(big.Int).SetString(
		"57896044618658097711785492504343953926634992332820282019728792003956564819949",
		10,
	)
)

// GenerateEd25519PrivateKey .
func GenerateEd25519PrivateKey() Ed25519PrivateKey {
	b := [32]byte{}
	_, err := rand.Read(b[:])
	if err != nil {
		log.Fatalln(err)
	}
	priv := ed25519.NewKeyFromSeed(b[:])
	return Ed25519PrivateKey(priv)
}

// ConvertToEd25519PublicKey .
func (priv Ed25519PrivateKey) ConvertToEd25519PublicKey() Ed25519PublicKey {
	p := ed25519.PrivateKey(priv)
	return Ed25519PublicKey(p.Public().(ed25519.PublicKey))
}

// ConvertToEd25519KeyPair .
func (priv Ed25519PrivateKey) ConvertToEd25519KeyPair() Ed25519KeyPair {
	return Ed25519KeyPair{
		Public: priv.ConvertToEd25519PublicKey(),
		Private: priv,
	}
}

// GenerateEd25519Pair .
func GenerateEd25519Pair() Ed25519KeyPair {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		log.Fatalln(err)
	}
	return Ed25519KeyPair{
		Public: Ed25519PublicKey(pub),
		Private: Ed25519PrivateKey(priv),
	}
}

// Ed25519PrivateSeed .
func Ed25519PrivateSeed(s [32]byte) Ed25519PrivateKey {
	priv := ed25519.NewKeyFromSeed(s[:])
	return Ed25519PrivateKey(priv)
}

// GenerateEd25519KeyPairFromSeed .
func GenerateEd25519KeyPairFromSeed(s [32]byte) Ed25519KeyPair {
	priv := Ed25519PrivateKey(ed25519.NewKeyFromSeed(s[:]))
	return Ed25519KeyPair{
		Public: priv.ConvertToEd25519PublicKey(),
		Private: priv,
	}
}

// ConvertToX25519KeyPair .
func (priv Ed25519PrivateKey) ConvertToX25519KeyPair() X25519KeyPair {
	pk := ed25519.PrivateKey(priv)
	b := sha512.Sum512(pk.Seed())
	prv := X25519PrivateKey{}
	copy(prv[:], b[:32])
	return X25519KeyPair{
		Private: prv,
		Public: prv.ConvertToX25519PublicKey(),
	}
}

// ConvertToX25519PrivateKey .
func (priv Ed25519PrivateKey) ConvertToX25519PrivateKey() X25519PrivateKey {
	pk := ed25519.PrivateKey(priv)
	b := sha512.Sum512(pk.Seed())
	pc := X25519PrivateKey{}
	copy(pc[:], b[:32])
	return pc
}

// ConvertToX25519PublicKey .
func (k Ed25519PublicKey) ConvertToX25519PublicKey() X25519PublicKey {
	p := reverseBytes(k)
	p[0] &= 0b0111_1111
	y := new(big.Int).SetBytes(p)
	d := big.NewInt(1)
	d.ModInverse(d.Sub(d, y), x25519P)
	u := y.Mul(y.Add(y, big.NewInt(1)), d)
	u.Mod(u, x25519P)
	pub := X25519PublicKey{}
	copy(pub[:32], reverseBytes(u.Bytes())[:32])
	return pub
}

func reverseBytes(in []byte) []byte {
	r := make([]byte, len(in))
	for i, b := range in {
		r[len(in)-i-1] = b
	}
	return r
}
