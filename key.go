package virtualwebauthn

type Key struct {
	Type KeyType `json:"type"`
	Data []byte  `json:"data"`
	signingKey
}

func (k *Key) AttestationData() []byte {
	k.ensureSigningKey()
	return k.signingKey.AttestationData()
}

func (k *Key) Sign(digest []byte) (signature []byte, err error) {
	k.ensureSigningKey()
	return k.signingKey.Sign(digest)
}

func (k *Key) ensureSigningKey() {
	switch k.Type {
	case KeyTypeEC2:
		k.signingKey = importEC2SigningKey(k.Data)
	case KeyTypeRSA:
		k.signingKey = importRSASigningKey(k.Data)
	default:
		panic("invalid key type")
	}
}

type KeyType string

const (
	KeyTypeEC2 KeyType = "ec2"
	KeyTypeRSA KeyType = "rsa"
)

func (keyType KeyType) newKey() *Key {
	key := &Key{Type: keyType}
	switch keyType {
	case KeyTypeEC2:
		key.signingKey, key.Data = newEC2SigningKey()
	case KeyTypeRSA:
		key.signingKey, key.Data = newRSASigningKey()
	default:
		panic("invalid key type")
	}
	return key
}

func (keyType KeyType) importKey(keyData []byte) *Key {
	return &Key{Type: keyType, Data: keyData}
}

type signingKey interface {
	AttestationData() []byte
	Sign(digest []byte) (signature []byte, err error)
}
