package virtualwebauthn

import "encoding/base64"

type Credential struct {
	ID      []byte `json:"id"`
	Key     Key    `json:"key"`
	Counter uint32 `json:"counter,omitempty"`
}

func NewCredential(keyType KeyType) Credential {
	cred := Credential{}
	cred.ID = randomBytes(32)
	if keyType == KeyTypeEC2 {
		cred.Key = Key{Type: keyType, SigningKey: newEC2SigningKey()}
	} else if keyType == KeyTypeRSA {
		cred.Key = Key{Type: keyType, SigningKey: newRSASigningKey()}
	} else {
		panic("Invalid credential key type")
	}
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
