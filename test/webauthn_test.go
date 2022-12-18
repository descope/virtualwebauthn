package test

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/descope/virtualwebauthn"
	"github.com/fxamacker/webauthn"
	_ "github.com/fxamacker/webauthn/packed"
	"github.com/stretchr/testify/require"
)

const (
	WebauthnDisplayName = "Example"
	WebauthnDomain      = "example.com"
	WebauthnOrigin      = "https://example.com"
	UserID              = "a987z"
	UserName            = "jappleseed"
	UserDisplayName     = "John Appleseed"
)

func TestWebauthn(t *testing.T) {
	// Create a mock relying party, mock authenticator and a mock EC2 credential
	rp := virtualwebauthn.RelyingParty{Name: WebauthnDisplayName, ID: WebauthnDomain, Origin: WebauthnOrigin}
	authenticator := virtualwebauthn.NewAuthenticator()
	ec2Cred := virtualwebauthn.NewCredential(virtualwebauthn.KeyTypeEC2)

	// Register

	// Start an attestation request with the relying party to register a new webauthn authenticator.
	// In this test we run an instance of fxamacker/webauthn locally, but we could just as well get
	// this from an an actual server.
	attestation := startWebauthnRegister(t)

	// Parses the attestation options we got from the relying party to ensure they're valid
	attestationOptions, err := virtualwebauthn.ParseAttestationOptions(attestation.Options)
	require.NoError(t, err)
	require.NotNil(t, attestationOptions)

	// Ensure that the mock credential isn't excluded by the attestation options
	isExcluded := ec2Cred.IsExcludedForAttestation(*attestationOptions)
	require.False(t, isExcluded)

	// Ensure that the Relying Party details match
	require.Equal(t, WebauthnDomain, attestationOptions.RelyingPartyID)
	require.Equal(t, WebauthnDisplayName, attestationOptions.RelyingPartyName)

	// Ensure that the user details match
	require.Equal(t, UserID, attestationOptions.UserID)
	require.Equal(t, UserName, attestationOptions.UserName)
	require.Equal(t, UserDisplayName, attestationOptions.UserDisplayName)

	// Creates an attestation response that we can send to the relying party as if it came from
	// an actual browser and authenticator.
	attestationResponse := virtualwebauthn.CreateAttestationResponse(rp, authenticator, ec2Cred, *attestationOptions)

	// Finish the register operation by sending the attestation response. An actual relying party
	// would keep all the data related to the user, but in this test we need to hold onto the
	// credential object for later usage.
	webauthnEC2Credential := finishWebauthnRegister(t, attestation, attestationResponse)

	// Add the userID to the mock authenticator so it can return it in assertion responses.
	authenticator.Options.UserHandle = []byte(UserID)

	// Add the EC2 credential to the mock authenticator
	authenticator.AddCredential(ec2Cred)

	// Login

	// Start an assertion request with the relying party to perform a login. As above, this would
	// typically call to an actual server or some other relying party implementation.
	assertion := startWebauthnLogin(t, webauthnEC2Credential, ec2Cred.ID)

	// Parses the attestation options we got from the relying party to ensure they're valid
	assertionOptions, err := virtualwebauthn.ParseAssertionOptions(assertion.Options)
	require.NoError(t, err)
	require.NotNil(t, assertionOptions)

	// Ensure that the mock authenticator has a valid credential that was requested by the assertion
	// options specifically, and ensure it's the one we created above
	foundCredential := authenticator.FindAllowedCredential(*assertionOptions)
	require.NotNil(t, foundCredential)
	require.Equal(t, ec2Cred, *foundCredential)

	// Ensure that the Relying Party details match
	require.Equal(t, WebauthnDomain, assertionOptions.RelyingPartyID)

	// Creates an assertion response that we can send to the relying party to finish the login as if
	// it came from an actual browser and authenticator.
	assertionResponse := virtualwebauthn.CreateAssertionResponse(rp, authenticator, ec2Cred, *assertionOptions)
	require.NotEmpty(t, assertionResponse)

	// Finish the login operation by sending the assertion response.
	finishWebauthnLogin(t, assertion, assertionResponse)
}

/// Register

type WebauthnAttestation struct {
	User      *webauthn.User
	Challenge []byte
	Options   string
}

func startWebauthnRegister(t *testing.T) *WebauthnAttestation {
	user := newWebauthnUser()

	options, err := webauthn.NewAttestationOptions(webauthnConfig, user)
	require.NoError(t, err)

	optionsJSON, err := json.Marshal(options)
	require.NoError(t, err)

	return &WebauthnAttestation{User: user, Challenge: options.Challenge, Options: string(optionsJSON)}
}

func finishWebauthnRegister(t *testing.T, attestation *WebauthnAttestation, response string) *webauthn.Credential {
	parsedAttestation, err := webauthn.ParseAttestation(strings.NewReader(response))
	require.NoError(t, err)

	_, _, err = webauthn.VerifyAttestation(parsedAttestation, &webauthn.AttestationExpectedData{
		Origin:           WebauthnOrigin,
		RPID:             WebauthnDomain,
		CredentialAlgs:   []int{webauthn.COSEAlgES256},
		Challenge:        base64.RawURLEncoding.EncodeToString(attestation.Challenge),
		UserVerification: webauthn.UserVerificationPreferred,
	})
	require.NoError(t, err)

	return parsedAttestation.AuthnData.Credential
}

/// Login

type WebauthnAssertion struct {
	User         *webauthn.User
	Credential   *webauthn.Credential
	CredentialID []byte
	Challenge    []byte
	Options      string
}

func startWebauthnLogin(t *testing.T, cred *webauthn.Credential, credID []byte) *WebauthnAssertion {
	user := newWebauthnUser()

	user.CredentialIDs = append(user.CredentialIDs, credID)

	options, err := webauthn.NewAssertionOptions(webauthnConfig, user)
	require.NoError(t, err)

	optionsJSON, err := json.Marshal(options)
	require.NoError(t, err)

	return &WebauthnAssertion{User: user, Credential: cred, CredentialID: credID, Challenge: options.Challenge, Options: string(optionsJSON)}
}

func finishWebauthnLogin(t *testing.T, assertion *WebauthnAssertion, response string) {
	parsedAssertion, err := webauthn.ParseAssertion(strings.NewReader(response))
	require.NoError(t, err)

	err = webauthn.VerifyAssertion(parsedAssertion, &webauthn.AssertionExpectedData{
		Origin:            WebauthnOrigin,
		RPID:              WebauthnDomain,
		Challenge:         base64.RawURLEncoding.EncodeToString(assertion.Challenge),
		UserVerification:  webauthn.UserVerificationPreferred,
		UserID:            []byte(UserID),
		UserCredentialIDs: assertion.User.CredentialIDs,
		PrevCounter:       uint32(0),
		Credential:        assertion.Credential,
	})
	require.NoError(t, err)
}

/// Utils

func newWebauthnUser() *webauthn.User {
	return &webauthn.User{
		ID:          []byte(UserID),
		Name:        UserName,
		DisplayName: UserDisplayName,
	}
}

var webauthnConfig = &webauthn.Config{
	RPID:             WebauthnDomain,
	RPName:           WebauthnDisplayName,
	Timeout:          uint64(60000),
	ChallengeLength:  32,
	ResidentKey:      webauthn.ResidentKeyDiscouraged,
	UserVerification: webauthn.UserVerificationDiscouraged,
	Attestation:      webauthn.AttestationNone,
	CredentialAlgs:   []int{webauthn.COSEAlgES256, webauthn.COSEAlgRS256},
}
