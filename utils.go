package virtualwebauthn

import (
	"crypto/rand"

	"github.com/fxamacker/cbor/v2"
)

type clientData struct {
	Type      string `json:"type"`
	Challenge string `json:"challenge"`
	Origin    string `json:"origin"`
}

func marshalCbor(v any) []byte {
	encoder, err := cbor.CTAP2EncOptions().EncMode()
	if err != nil {
		panic("Failed to instantiate cbor encoder")
	}
	bytes, err := encoder.Marshal(v)
	if err != nil {
		panic("Failed to encode to cbor")
	}
	return bytes
}

func randomBytes(length int) []byte {
	bytes := make([]byte, length)
	num, err := rand.Read(bytes)
	if err != nil || num != length {
		panic("Failed to generate random bytes")
	}
	return bytes
}

func bigEndianBytes[T interface{ int | uint32 }](value T, length int) []byte {
	bytes := make([]byte, length)
	for i := 0; i < length; i++ {
		shift := (length - i - 1) * 8
		bytes[i] = byte(value >> shift & 0xFF)
	}
	return bytes
}
