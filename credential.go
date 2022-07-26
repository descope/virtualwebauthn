package virtualwebauthn

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
