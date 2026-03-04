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
	RelyingPartyID     string   `json:"rpId,omitempty"`
	RelyingPartyName   string   `json:"rpName,omitempty"`
	UserID             string   `json:"user,omitempty"`
	UserName           string   `json:"userName,omitempty"`
	UserDisplayName    string   `json:"userDisplayName,omitempty"`
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

	attestationOptions = &AttestationOptions{
		RelyingPartyID:   values.RP.ID,
		RelyingPartyName: values.RP.Name,
	}

	decodedUserID, err := base64.RawURLEncoding.DecodeString(values.User.ID)
	if err != nil {
		return nil, errors.New("failed to decode user id in response")
	}

	attestationOptions.UserID = string(decodedUserID)
	attestationOptions.UserName = values.User.Name
	attestationOptions.UserDisplayName = values.User.DisplayName

	if len(values.Challenge) == 0 {
		return nil, errors.New("failed to find challenge in response")
	}
	challenge, err := base64.RawURLEncoding.DecodeString(values.Challenge)
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

	publicKeyData := cred.Key.AttestationData()

	credData := []byte{}
	credData = append(credData, auth.Aaguid[:]...)
	credData = append(credData, bigEndianBytes(len(cred.ID), 2)...)
	credData = append(credData, cred.ID...)
	credData = append(credData, publicKeyData...)

	rpIDHash := sha256.Sum256([]byte(rp.ID))
	flags := authenticatorDataFlags(
		!auth.Options.UserNotPresent,
		!auth.Options.UserNotVerified,
		auth.Options.BackupEligible,
		auth.Options.BackupState,
		true,
		false,
	)

	authData := []byte{}
	authData = append(authData, rpIDHash[:]...)
	authData = append(authData, flags)
	authData = append(authData, bigEndianBytes(cred.Counter, 4)...)
	authData = append(authData, credData...)

	clientDataJSONHashed := sha256.Sum256(clientDataJSON)
	verifyData := append(authData, clientDataJSONHashed[:]...)

	hasher := crypto.SHA256.New()
	hasher.Write(verifyData)
	digest := hasher.Sum(nil)

	sig, err := cred.Key.Sign(digest)
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

	transports := auth.Options.Transports
	if len(transports) == 0 {
		transports = []Transport{TransportInternal}
	}
	translatedTransports := translateTransports(transports)

	clientExtensionResults := auth.Options.ClientExtensionResults
	if clientExtensionResults == nil {
		clientExtensionResults = map[string]any{}
	}

	attestationResponse := attestationResponse{
		AttestationObject: attestationObjectEncoded,
		ClientDataJSON:    clientDataJSONEncoded,
		Transports:        translatedTransports,
	}

	attestationResult := attestationResult{
		Type:                   "public-key",
		ID:                     credIDEncoded,
		RawID:                  credIDEncoded,
		Response:               attestationResponse,
		ClientExtensionResults: clientExtensionResults,
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
	RP                 attestationOptionsRelyingParty        `json:"rp,omitempty"`
	User               attestationOptionsUser                `json:"user,omitempty"`
	PublicKey          *attestationOptionsValues             `json:"publicKey,omitempty"`
}

type attestationOptionsRelyingParty struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type attestationOptionsUser struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	DisplayName string `json:"displayName"`
}

type attestationOptionsExcludeCredential struct {
	Type string `json:"type"`
	ID   string `json:"id"`
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
	AttestationObject string   `json:"attestationObject"`
	ClientDataJSON    string   `json:"clientDataJSON"`
	Transports        []string `json:"transports"`
}

type attestationResult struct {
	Type                   string              `json:"type"`
	ID                     string              `json:"id"`
	RawID                  string              `json:"rawId"`
	Response               attestationResponse `json:"response"`
	ClientExtensionResults map[string]any      `json:"clientExtensionResults"`
}
