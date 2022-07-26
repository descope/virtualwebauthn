package virtualwebauthn

import (
	"crypto"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
)

/// Options

type AttestationOptions struct {
	Challenge          []byte   `json:"challenge,omitempty"`
	ExcludeCredentials []string `json:"excludeCredentials,omitempty"`
}

func ParseAttestationOptions(str string) (attestationOptions *AttestationOptions, err error) {
	values := attestationOptionsValues{}
	err = json.Unmarshal([]byte(str), &values)
	if err != nil {
		return nil, err
	}
	if values.PublicKey != nil {
		values = *values.PublicKey
	}

	attestationOptions = &AttestationOptions{}

	if len(values.Challenge) == 0 {
		return nil, errors.New("failed to find challenge in response")
	}
	challenge, err := base64.StdEncoding.DecodeString(values.Challenge)
	if err != nil {
		return nil, err
	}
	attestationOptions.Challenge = challenge

	for _, cred := range values.ExcludeCredentials {
		if len(cred.ID) == 0 {
			return nil, errors.New("allowed credential has an empty id")
		}
		attestationOptions.ExcludeCredentials = append(attestationOptions.ExcludeCredentials, cred.ID)
	}

	return attestationOptions, nil
}

/// Response

func CreateAttestationResponse(rp RelyingParty, auth Authenticator, cred Credential, options AttestationOptions) string {
	clientData := clientData{
		Type:      "webauthn.create",
		Challenge: base64.RawURLEncoding.EncodeToString(options.Challenge),
		Origin:    rp.Origin,
	}
	clientDataJSON, err := json.Marshal(clientData)
	if err != nil {
		panic("failed to marshal json")
	}
	clientDataJSONEncoded := base64.RawURLEncoding.EncodeToString(clientDataJSON)

	keyDataBytes := cred.Key.SigningKey.KeyData()

	credData := []byte{}
	credData = append(credData, auth.Aaguid[:]...)
	credData = append(credData, bigEndianBytes(len(cred.ID), 2)...)
	credData = append(credData, cred.ID...)
	credData = append(credData, keyDataBytes...)

	rpIDHash := sha256.Sum256([]byte(rp.ID))

	authData := []byte{}
	authData = append(authData, rpIDHash[:]...)
	authData = append(authData, 0b_0100_0101)       // bits 0, 2 and 7 - see: https://www.w3.org/TR/webauthn/#flags
	authData = append(authData, bigEndianBytes(cred.Counter, 4)...)
	authData = append(authData, credData...)

	clientDataJSONHashed := sha256.Sum256(clientDataJSON)
	verifyData := append(authData, clientDataJSONHashed[:]...)

	hasher := crypto.SHA256.New()
	hasher.Write(verifyData)
	digest := hasher.Sum(nil)

	sig, err := cred.Key.SigningKey.Sign(digest)
	if err != nil {
		panic("failed to sign digest")
	}

	var algo int
	if cred.Key.Type == KeyTypeEC2 {
		algo = ec2SHA256Algo
	} else if cred.Key.Type == KeyTypeRSA {
		algo = rsaSHA256Algo
	}

	attestationObject := attestationObject{
		Format:   "packed",
		AuthData: authData,
		Statement: attestationStatement{
			Algorithm: algo,
			Signature: sig,
		},
	}
	attestationObjectBytes := marshalCbor(attestationObject)
	attestationObjectEncoded := base64.RawURLEncoding.EncodeToString(attestationObjectBytes)

	credIDEncoded := base64.RawURLEncoding.EncodeToString(cred.ID)

	attestationResponse := attestationResponse{
		AttestationObject: attestationObjectEncoded,
		ClientDataJSON:    clientDataJSONEncoded,
	}

	attestationResult := attestationResult{
		Type:     "public-key",
		ID:       credIDEncoded,
		RawID:    credIDEncoded,
		Response: attestationResponse,
	}

	attestationResultBytes, err := json.Marshal(attestationResult)
	if err != nil {
		panic("failed to marshal json")
	}

	return string(attestationResultBytes)
}

/// Helpers

type attestationOptionsValues struct {
	Challenge          string                                `json:"challenge,omitempty"`
	ExcludeCredentials []attestationOptionsExcludeCredential `json:"excludeCredentials,omitempty"`
	PublicKey          *attestationOptionsValues             `json:"publicKey,omitempty"`
}

type attestationOptionsExcludeCredential struct {
	Type string `json:"type,omitempty"`
	ID   string `json:"id,omitempty"`
}

type attestationStatement struct {
	Algorithm int    `json:"alg"`
	Signature []byte `json:"sig"`
}

type attestationObject struct {
	Format    string               `json:"fmt"`
	Statement attestationStatement `json:"attStmt"`
	AuthData  []byte               `json:"authData"`
}

type attestationResponse struct {
	AttestationObject string `json:"attestationObject"`
	ClientDataJSON    string `json:"clientDataJSON"`
}

type attestationResult struct {
	Type     string              `json:"type"`
	ID       string              `json:"id"`
	RawID    string              `json:"rawId"`
	Response attestationResponse `json:"response"`
}
