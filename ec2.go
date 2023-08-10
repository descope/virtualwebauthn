package virtualwebauthn

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
)

const (
	ec2Type       = 2  // https://datatracker.ietf.org/doc/html/rfc8152#section-13
	ec2P256Curve  = 1  // https://datatracker.ietf.org/doc/html/rfc8152#section-13.1
	ec2SHA256Algo = -7 // https://datatracker.ietf.org/doc/html/rfc8152#section-8.1
)

type ec2SigningKey struct {
	Key  *ecdsa.PrivateKey `json:"key"`
	Data []byte            `json:"data"`
}

func newEC2SigningKey() *ec2SigningKey {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic("failed to generate signing key")
	}
	return newEC2SigningKeyWithPrivateKey(key)
}

func importEC2SigningKey(keyBytes []byte) *ec2SigningKey {
	parsed, err := x509.ParsePKCS8PrivateKey(keyBytes)
	if err != nil {
		panic("failed to parse PKCS8 ECDSA Private Key")
	}
	key, ok := parsed.(*ecdsa.PrivateKey)
	if !ok {
		panic("expected EC2 key in imported data")
	}
	return newEC2SigningKeyWithPrivateKey(key)
}

func newEC2SigningKeyWithPrivateKey(key *ecdsa.PrivateKey) *ec2SigningKey {
	info := ec2KeyInfo{
		Type:      ec2Type,
		Algorithm: ec2SHA256Algo,
		Curve:     ec2P256Curve,
		X:         key.X.Bytes(),
		Y:         key.Y.Bytes(),
	}
	data := marshalCbor(info)
	return &ec2SigningKey{Key: key, Data: data}
}

func (k *ec2SigningKey) KeyData() []byte {
	return k.Data
}

func (k *ec2SigningKey) Sign(digest []byte) (signature []byte, err error) {
	return k.Key.Sign(rand.Reader, digest, nil)
}

func (k *ec2SigningKey) ExportToPKCS8Key() (PKCS8Key []byte, err error) {
	return x509.MarshalPKCS8PrivateKey(k.Key)
}

type ec2KeyInfo struct {
	Type      int64  `cbor:"1,keyasint"`
	Algorithm int64  `cbor:"3,keyasint"`
	Curve     int64  `cbor:"-1,keyasint"`
	X         []byte `cbor:"-2,keyasint"`
	Y         []byte `cbor:"-3,keyasint"`
}
