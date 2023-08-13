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
	privateKey      *rsa.PrivateKey
	attestationData []byte
}

func newRSASigningKey() (*rsaSigningKey, []byte) {
	privateKey, err := rsa.GenerateKey(rand.Reader, rsaSize)
	if err != nil {
		panic("failed to generate private key")
	}
	keyData, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		panic("failed to export generated private key")
	}
	return newRSASigningKeyWithPrivateKey(privateKey), keyData
}

func importRSASigningKey(keyData []byte) *rsaSigningKey {
	parsed, err := x509.ParsePKCS8PrivateKey(keyData)
	if err != nil {
		panic("failed to parse PKCS8 RSA private Key")
	}
	privateKey, ok := parsed.(*rsa.PrivateKey)
	if !ok {
		panic("expected RSA key in imported data")
	}
	return newRSASigningKeyWithPrivateKey(privateKey)
}

func newRSASigningKeyWithPrivateKey(privateKey *rsa.PrivateKey) *rsaSigningKey {
	info := rasKeyInfo{
		Type:      rsaType,
		Algorithm: rsaSHA256Algo,
		Modulus:   privateKey.N.Bytes(),
		Exponent:  bigEndianBytes(privateKey.E, 3),
	}
	attestationData := marshalCbor(info)
	return &rsaSigningKey{privateKey: privateKey, attestationData: attestationData}
}

func (k *rsaSigningKey) AttestationData() []byte {
	return k.attestationData
}

func (k *rsaSigningKey) Sign(digest []byte) (signature []byte, err error) {
	return rsa.SignPKCS1v15(rand.Reader, k.privateKey, crypto.SHA256, digest)
}

type rasKeyInfo struct {
	Type      int64  `cbor:"1,keyasint"`
	Algorithm int64  `cbor:"3,keyasint"`
	Modulus   []byte `cbor:"-1,keyasint"`
	Exponent  []byte `cbor:"-2,keyasint"`
}
