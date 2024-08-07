package virtualwebauthn

import (
	"crypto"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
)

/// Options

type AssertionOptions struct {
	Challenge        []byte   `json:"challenge,omitempty"`
	AllowCredentials []string `json:"allowCredentials,omitempty"`
	RelyingPartyID   string   `json:"rpId,omitempty"`
}

func ParseAssertionOptions(str string) (assertionOptions *AssertionOptions, err error) {
	values := assertionOptionsValues{}
	err = json.Unmarshal([]byte(str), &values)
	if err != nil {
		return nil, err
	}
	if values.PublicKey != nil {
		values = *values.PublicKey
	}

	assertionOptions = &AssertionOptions{
		RelyingPartyID: values.RelyingPartyID,
	}

	if len(values.Challenge) == 0 {
		return nil, errors.New("failed to find challenge in options")
	}
	challenge, err := base64.RawURLEncoding.DecodeString(values.Challenge)
	if err != nil {
		return nil, err
	}
	assertionOptions.Challenge = challenge

	for _, cred := range values.AllowCredentials {
		if len(cred.ID) == 0 {
			return nil, errors.New("allowed credential has an empty id")
		}
		assertionOptions.AllowCredentials = append(assertionOptions.AllowCredentials, cred.ID)
	}

	return assertionOptions, nil
}

/// Response

func CreateAssertionResponse(rp RelyingParty, auth Authenticator, cred Credential, options AssertionOptions) string {
	clientData := clientData{
		Type:      "webauthn.get",
		Challenge: base64.RawURLEncoding.EncodeToString(options.Challenge),
		Origin:    rp.Origin,
	}
	clientDataJSON, err := json.Marshal(clientData)
	if err != nil {
		panic("failed to marshal json")
	}
	clientDataJSONEncoded := base64.RawURLEncoding.EncodeToString(clientDataJSON)

	rpIDHash := sha256.Sum256([]byte(rp.ID))
	flags := authenticatorDataFlags(
		!auth.Options.UserNotPresent,
		!auth.Options.UserNotVerified,
		auth.Options.BackupEligible,
		auth.Options.BackupState,
		false,
		false,
	)

	authData := []byte{}
	authData = append(authData, rpIDHash[:]...)
	authData = append(authData, flags)
	authData = append(authData, bigEndianBytes(cred.Counter, 4)...)
	authDataEncoded := base64.RawURLEncoding.EncodeToString(authData)

	clientDataJSONHashed := sha256.Sum256(clientDataJSON)
	verifyData := append(authData, clientDataJSONHashed[:]...)

	hasher := crypto.SHA256.New()
	hasher.Write(verifyData)
	digest := hasher.Sum(nil)

	sig, err := cred.Key.Sign(digest)
	if err != nil {
		panic("failed to sign digest")
	}

	credIDEncoded := base64.RawURLEncoding.EncodeToString(cred.ID)

	assertionResponse := assertionResponse{
		AuthenticatorData: authDataEncoded,
		ClientDataJSON:    clientDataJSONEncoded,
		Signature:         base64.RawURLEncoding.EncodeToString(sig),
		UserHandle:        base64.RawURLEncoding.EncodeToString(auth.Options.UserHandle),
	}

	assertionResult := assertionResult{
		Type:     "public-key",
		ID:       credIDEncoded,
		RawID:    credIDEncoded,
		Response: assertionResponse,
	}

	assertionResultBytes, err := json.Marshal(assertionResult)
	if err != nil {
		panic("failed to marshal json")
	}

	return string(assertionResultBytes)
}

/// Helpers

type assertionOptionsValues struct {
	Challenge        string                            `json:"challenge,omitempty"`
	AllowCredentials []assertionOptionsAllowCredential `json:"allowCredentials,omitempty"`
	RelyingPartyID   string                            `json:"rpId,omitempty"`
	PublicKey        *assertionOptionsValues           `json:"publicKey,omitempty"`
}

type assertionOptionsAllowCredential struct {
	Type string `json:"type"`
	ID   string `json:"id"`
}

type assertionResponse struct {
	AuthenticatorData string `json:"authenticatorData"`
	ClientDataJSON    string `json:"clientDataJSON"`
	Signature         string `json:"signature"`
	UserHandle        string `json:"userHandle,omitempty"`
}

type assertionResult struct {
	Type     string            `json:"type"`
	ID       string            `json:"id"`
	RawID    string            `json:"rawId"`
	Response assertionResponse `json:"response"`
}
