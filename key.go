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
