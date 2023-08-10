package virtualwebauthn

type PortableCredential struct {
	ID       []byte  `json:"id"`
	PKCS8Key []byte  `json:"key"`
	KeyType  KeyType `json:"keyType,omitempty"`
	Counter  uint32  `json:"counter,omitempty"`
}

func (p *PortableCredential) ToCredential() Credential {
	key := Key{}
	if p.KeyType == KeyTypeEC2 {
		key = Key{Type: p.KeyType, SigningKey: importEC2SigningKey(p.PKCS8Key)}
	} else if p.KeyType == KeyTypeRSA {
		key = Key{Type: p.KeyType, SigningKey: importRSASigningKey(p.PKCS8Key)}
	} else {
		panic("Invalid credential key type")
	}

	cred := Credential{
		ID:      p.ID,
		Key:     key,
		Counter: p.Counter,
	}

	return cred
}
