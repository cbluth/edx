package edx

import (
	"log"
	"crypto/rand"
	"crypto/sha256"
	"golang.org/x/crypto/curve25519"
)

type (
	// X25519Key is 32 bytes long
	X25519Key [32]byte
	// X25519PublicKey .
	X25519PublicKey X25519Key
	// X25519PrivateKey .
	X25519PrivateKey X25519Key
	// X25519KeyPair .
	X25519KeyPair struct {
		Public X25519PublicKey
		Private X25519PrivateKey
	}
)

// GenerateX25519PrivateKey .
func GenerateX25519PrivateKey() X25519PrivateKey {
	b := X25519PrivateKey([32]byte{})
	_, err := rand.Read(b[:])
	if err != nil {
		log.Fatalln(err)
	}
	return b
}

// ConvertToX25519PublicKey .
func (priv X25519PrivateKey) ConvertToX25519PublicKey() X25519PublicKey {
	pub := &[32]byte{}
	prv := &[32]byte{}
	copy(prv[:], priv[:])
	curve25519.ScalarBaseMult(pub, prv)
	return X25519PublicKey(*pub)
}

// ConvertToX25519KeyPair .
func (priv X25519PrivateKey) ConvertToX25519KeyPair() X25519KeyPair {
	return X25519KeyPair{
		Public: priv.ConvertToX25519PublicKey(),
		Private: priv,
	}
}

// GenerateX25519Pair .
func GenerateX25519Pair() X25519KeyPair {
	priv := GenerateX25519PrivateKey()
	return priv.ConvertToX25519KeyPair()
}

// GenerateX25519PrivateKeyFromSeed .
func GenerateX25519PrivateKeyFromSeed(s [32]byte) X25519PrivateKey {
	return X25519PrivateKey(s)
}

// GenerateX25519PrivateKeyFromSeedHash .
func GenerateX25519PrivateKeyFromSeedHash(s [32]byte) X25519PrivateKey {
	h := sha256.Sum256(s[:])
	return X25519PrivateKey(h)
}

// GenerateX25519KeyPairFromSeed .
func GenerateX25519KeyPairFromSeed(s [32]byte) X25519KeyPair {
	priv := GenerateX25519PrivateKeyFromSeed(s)
	return priv.ConvertToX25519KeyPair()
}
