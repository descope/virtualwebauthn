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
	privateKey      *ecdsa.PrivateKey
	attestationData []byte
}

func newEC2SigningKey() (*ec2SigningKey, []byte) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic("failed to generate private key")
	}
	keyData, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		panic("failed to export generated private key")
	}
	return newEC2SigningKeyWithPrivateKey(privateKey), keyData
}

func importEC2SigningKey(keyData []byte) *ec2SigningKey {
	parsed, err := x509.ParsePKCS8PrivateKey(keyData)
	if err != nil {
		panic("failed to parse PKCS8 ECDSA private Key")
	}
	privateKey, ok := parsed.(*ecdsa.PrivateKey)
	if !ok {
		panic("expected EC2 key in imported data")
	}
	return newEC2SigningKeyWithPrivateKey(privateKey)
}

func newEC2SigningKeyWithPrivateKey(privateKey *ecdsa.PrivateKey) *ec2SigningKey {
	info := ec2KeyInfo{
		Type:      ec2Type,
		Algorithm: ec2SHA256Algo,
		Curve:     ec2P256Curve,
		X:         privateKey.X.Bytes(),
		Y:         privateKey.Y.Bytes(),
	}
	attestationData := marshalCbor(info)
	return &ec2SigningKey{privateKey: privateKey, attestationData: attestationData}
}

func (k *ec2SigningKey) AttestationData() []byte {
	return k.attestationData
}

func (k *ec2SigningKey) Sign(digest []byte) (signature []byte, err error) {
	return k.privateKey.Sign(rand.Reader, digest, nil)
}

type ec2KeyInfo struct {
	Type      int64  `cbor:"1,keyasint"`
	Algorithm int64  `cbor:"3,keyasint"`
	Curve     int64  `cbor:"-1,keyasint"`
	X         []byte `cbor:"-2,keyasint"`
	Y         []byte `cbor:"-3,keyasint"`
}
