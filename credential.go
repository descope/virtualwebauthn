package virtualwebauthn

import "encoding/base64"

type Credential struct {
	ID      []byte `json:"id"`
	Key     Key    `json:"key"`
	Counter uint32 `json:"counter,omitempty"`
}

func NewCredential(keyType KeyType) Credential {

	key := Key{}
	if keyType == KeyTypeEC2 {
		key = Key{Type: keyType, SigningKey: newEC2SigningKey()}
	} else if keyType == KeyTypeRSA {
		key = Key{Type: keyType, SigningKey: newRSASigningKey()}
	} else {
		panic("Invalid credential key type")
	}

	return createCredential(key)
}

func NewCredentialWithImportedKey(keyType KeyType, PKCS8PrivateKey []byte) Credential {
	key := Key{}
	if keyType == KeyTypeEC2 {
		key = Key{Type: keyType, SigningKey: importPKCS8EC2SigningKey(PKCS8PrivateKey)}
	} else if keyType == KeyTypeRSA {
		key = Key{Type: keyType, SigningKey: importPKCS8RSASigningKey(PKCS8PrivateKey)}
	} else {
		panic("Invalid credential key type")
	}
	return createCredential(key)
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

func createCredential(key Key) Credential {
	cred := Credential{}
	cred.ID = randomBytes(32)
	cred.Key = key
	return cred
}
