package test

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"testing"

	"github.com/descope/virtualwebauthn"
	_ "github.com/fxamacker/webauthn/packed"
	"github.com/stretchr/testify/require"
)

const secret = "My Super Secret!!!"

func TestExportedEC2Key(t *testing.T) {

	portableCred := createEC2PortableCredential(t)

	cred := portableCred.ToCredential()

	exportedPortableCred := cred.ExportToPortableCredential()

	require.Equal(t, portableCred, exportedPortableCred)
}

func TestExportedRSAKey(t *testing.T) {

	portableCred := createRSAPortableCredential(t)

	cred := portableCred.ToCredential()

	exportedPortableCred := cred.ExportToPortableCredential()

	require.Equal(t, portableCred, exportedPortableCred)
}

func TestExportedGeneratedEC2Key(t *testing.T) {

	cred := virtualwebauthn.NewCredential(virtualwebauthn.KeyTypeEC2)

	hasher := crypto.SHA256.New()
	hasher.Write([]byte(secret))
	digest := hasher.Sum(nil)

	sign, err := cred.Key.SigningKey.Sign(digest)
	require.NoError(t, err)

	exportedPortableCred := cred.ExportToPortableCredential()

	key := parseEc2Key(t, exportedPortableCred)

	publicKey, ok := key.Public().(*ecdsa.PublicKey)
	require.True(t, ok)

	success := ecdsa.VerifyASN1(publicKey, digest, sign)
	require.True(t, success)

}

func TestExportedGeneratedRSAKey(t *testing.T) {
	cred := virtualwebauthn.NewCredential(virtualwebauthn.KeyTypeRSA)

	hasher := crypto.SHA256.New()
	hasher.Write([]byte(secret))
	digest := hasher.Sum(nil)

	sign, err := cred.Key.SigningKey.Sign(digest)
	require.NoError(t, err)

	exportedPortableCred := cred.ExportToPortableCredential()

	key := parseRsaKey(t, exportedPortableCred)

	publicKey, ok := key.Public().(*rsa.PublicKey)
	require.True(t, ok)

	err = rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, digest, sign)
	require.Nil(t, err)
}

func parseEc2Key(t *testing.T, cred virtualwebauthn.PortableCredential) *ecdsa.PrivateKey {
	parsed, err := x509.ParsePKCS8PrivateKey(cred.PKCS8Key)
	require.NoError(t, err)

	key, ok := parsed.(*ecdsa.PrivateKey)
	require.True(t, ok)

	return key
}

func parseRsaKey(t *testing.T, cred virtualwebauthn.PortableCredential) *rsa.PrivateKey {
	parsed, err := x509.ParsePKCS8PrivateKey(cred.PKCS8Key)
	require.NoError(t, err)

	key, ok := parsed.(*rsa.PrivateKey)
	require.True(t, ok)

	return key
}
