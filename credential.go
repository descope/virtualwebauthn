package virtualwebauthn

import "encoding/base64"

type Credential struct {
	ID      []byte `json:"id"`
	Key     *Key   `json:"key"`
	Counter uint32 `json:"counter,omitempty"`
}

func NewCredential(keyType KeyType) Credential {
	return newCredential(keyType.newKey())
}

func NewCredentialWithImportedKey(keyType KeyType, keyData []byte) Credential {
	return newCredential(keyType.importKey(keyData))
}

func newCredential(key *Key) Credential {
	cred := Credential{}
	cred.ID = randomBytes(32)
	cred.Key = key
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
