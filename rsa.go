package virtualwebauthn

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
)

const (
	rsaSize       = 2048 // https://datatracker.ietf.org/doc/html/rfc8812#section-2
	rsaType       = 3    // https://datatracker.ietf.org/doc/html/rfc8230#section-4
	rsaSHA256Algo = -257 // https://datatracker.ietf.org/doc/html/rfc8812#section-2
)

type rsaSigningKey struct {
	Key  *rsa.PrivateKey `json:"key"`
	Data []byte          `json:"data"`
}

func newRSASigningKey() *rsaSigningKey {
	key, err := rsa.GenerateKey(rand.Reader, rsaSize)
	if err != nil {
		panic("Failed to generate signing key")
	}
	info := rasKeyInfo{
		Type:      rsaType,
		Algorithm: rsaSHA256Algo,
		Modulus:   key.N.Bytes(),
		Exponent:  []byte{byte(key.E>>16) & 0xFF, byte(key.E>>8) & 0xFF, byte(key.E) & 0xFF},
	}
	data := marshalCbor(info)
	return &rsaSigningKey{Key: key, Data: data}
}

func (k *rsaSigningKey) KeyData() []byte {
	return k.Data
}

func (k *rsaSigningKey) Sign(digest []byte) (signature []byte, err error) {
	return rsa.SignPKCS1v15(rand.Reader, k.Key, crypto.SHA256, digest)
}

type rasKeyInfo struct {
	Type      int64  `cbor:"1,keyasint"`
	Algorithm int64  `cbor:"3,keyasint"`
	Modulus   []byte `cbor:"-1,keyasint"`
	Exponent  []byte `cbor:"-2,keyasint"`
}
