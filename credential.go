package virtualwebauthn

import (
	"encoding/base64"
)

type Credential struct {
	ID      []byte `json:"id"`
	Key     Key    `json:"key"`
	Counter uint32 `json:"counter,omitempty"`
}

func NewCredential(keyType KeyType) Credential {
	cred := Credential{}
	cred.ID = randomBytes(32)
	cred.Key = keyType.newKey()
	return cred
}

func (c *Credential) IsExcludedForAttestation(options AttestationOptions) bool {
	encodedID := base64.RawURLEncoding.EncodeToString(c.ID)
	for _, excludedID := range options.ExcludeCredentials {
		if excludedID == encodedID {
			return true
		}
	}
	return false
}

func (c *Credential) IsAllowedForAssertion(options AssertionOptions) bool {
	encodedID := base64.RawURLEncoding.EncodeToString(c.ID)
	for _, allowedID := range options.AllowCredentials {
		if allowedID == encodedID {
			return true
		}
	}
	return false
}

func (c *Credential) ExportToPortableCredential() PortableCredential {

	portableCred := PortableCredential{
		ID:      c.ID,
		KeyType: c.Key.Type,
		Counter: c.Counter,
	}

	PKCS8Key, err := c.Key.SigningKey.ExportToPKCS8Key()

	if err != nil {

		if c.Key.Type == KeyTypeEC2 {
			panic("Could not export private key to PKCS8 format, for type EC2")
		}
		if c.Key.Type == KeyTypeRSA {
			panic("Could not export private key to PKCS8 format, for type RSA")
		}

	}

	portableCred.PKCS8Key = PKCS8Key

	return portableCred
}
