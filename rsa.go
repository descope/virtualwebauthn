package virtualwebauthn

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
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
		panic("failed to generate signing key")
	}
	return newRSASigningKeyWithPrivateKey(key)
}

func importRSASigningKey(keyBytes []byte) *rsaSigningKey {
	parsed, err := x509.ParsePKCS8PrivateKey(keyBytes)
	if err != nil {
		panic("failed to parse PKCS8 RSA Private Key")
	}
	key, ok := parsed.(*rsa.PrivateKey)
	if !ok {
		panic("expected RSA key in imported data")
	}
	return newRSASigningKeyWithPrivateKey(key)
}

func newRSASigningKeyWithPrivateKey(key *rsa.PrivateKey) *rsaSigningKey {
	info := rasKeyInfo{
		Type:      rsaType,
		Algorithm: rsaSHA256Algo,
		Modulus:   key.N.Bytes(),
		Exponent:  bigEndianBytes(key.E, 3),
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
