package virtualwebauthn

type Key struct {
	Type       KeyType    `json:"type"`
	SigningKey SigningKey `json:"signingKey"`
}

type KeyType int

const (
	KeyTypeEC2 KeyType = iota
	KeyTypeRSA
)

type SigningKey interface {
	KeyData() []byte
	Sign(digest []byte) (signature []byte, err error)
}

func (keyType KeyType) newKey() Key {
	switch keyType {
	case KeyTypeEC2:
		return Key{Type: keyType, SigningKey: newEC2SigningKey()}
	case KeyTypeRSA:
		return Key{Type: keyType, SigningKey: newRSASigningKey()}
	default:
		panic("invalid key type")
	}
}

func (keyType KeyType) importKey(keyBytes []byte) Key {
	switch keyType {
	case KeyTypeEC2:
		return Key{Type: keyType, SigningKey: importEC2SigningKey(keyBytes)}
	case KeyTypeRSA:
		return Key{Type: keyType, SigningKey: importRSASigningKey(keyBytes)}
	default:
		panic("invalid key type")
	}
}
