package test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/descope/virtualwebauthn"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEC2KeyAlt(t *testing.T) {
	cred := virtualwebauthn.NewCredential(virtualwebauthn.KeyTypeEC2)
	testCredentialAlt(t, cred)
}

func TestRSAKeyAlt(t *testing.T) {
	cred := virtualwebauthn.NewCredential(virtualwebauthn.KeyTypeRSA)
	testCredentialAlt(t, cred)
}

func testCredentialAlt(t *testing.T, cred virtualwebauthn.Credential) {
	// Create a mock relying party, mock authenticator and a mock EC2 credential
	rp := virtualwebauthn.RelyingParty{Name: WebauthnDisplayName, ID: WebauthnDomain, Origin: WebauthnOrigin}
	authenticator := virtualwebauthn.NewAuthenticator()

	web, err := webauthn.New(webauthnConfigAlt)
	require.NoError(t, err)

	// Register

	// Start an attestation request with the relying party to register a new webauthn authenticator.
	// In this test we run an instance of go-webauthn locally, but we could just as well get
	// this from an an actual server.
	attestation := startWebauthnRegisterAlt(t, web)

	// Parses the attestation options we got from the relying party to ensure they're valid
	attestationOptions, err := virtualwebauthn.ParseAttestationOptions(attestation.Options)
	require.NoError(t, err)
	require.NotNil(t, attestationOptions)

	// Ensure that the mock credential isn't excluded by the attestation options
	isExcluded := cred.IsExcludedForAttestation(*attestationOptions)
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
	attestationResponse := virtualwebauthn.CreateAttestationResponse(rp, authenticator, cred, *attestationOptions)

	// Finish the register operation by sending the attestation response. An actual relying party
	// would keep all the data related to the user, but in this test we need to hold onto the
	// credential object for later usage.
	webauthnEC2Credential := finishWebauthnRegisterAlt(t, web, attestation, attestationResponse)

	// Add the userID to the mock authenticator so it can return it in assertion responses.
	authenticator.Options.UserHandle = []byte(UserID)

	// Add the EC2 credential to the mock authenticator
	authenticator.AddCredential(cred)

	// Login

	// Start an assertion request with the relying party to perform a login. As above, this would
	// typically call to an actual server or some other relying party implementation.
	assertion := startWebauthnLoginAlt(t, web, webauthnEC2Credential, cred.ID)

	// Parses the attestation options we got from the relying party to ensure they're valid
	assertionOptions, err := virtualwebauthn.ParseAssertionOptions(assertion.Options)
	require.NoError(t, err)
	require.NotNil(t, assertionOptions)

	// Ensure that the mock authenticator has a valid credential that was requested by the assertion
	// options specifically, and ensure it's the one we created above
	foundCredential := authenticator.FindAllowedCredential(*assertionOptions)
	require.NotNil(t, foundCredential)
	require.Equal(t, cred, *foundCredential)

	// Ensure that the Relying Party details match
	require.Equal(t, WebauthnDomain, assertionOptions.RelyingPartyID)

	// Creates an assertion response that we can send to the relying party to finish the login as if
	// it came from an actual browser and authenticator.
	assertionResponse := virtualwebauthn.CreateAssertionResponse(rp, authenticator, cred, *assertionOptions)
	require.NotEmpty(t, assertionResponse)

	// Finish the login operation by sending the assertion response.
	finishWebauthnLoginAlt(t, web, assertion, assertionResponse)
}

/// Register

type webauthnAttestationAlt struct {
	User    webauthn.User
	Session *webauthn.SessionData
	Options string
}

func startWebauthnRegisterAlt(t *testing.T, web *webauthn.WebAuthn) *webauthnAttestationAlt {
	user := newWebauthnAltUser()

	options, session, err := web.BeginRegistration(user)
	require.NoError(t, err)

	optionsJSON, err := json.Marshal(options)
	require.NoError(t, err)

	return &webauthnAttestationAlt{User: user, Session: session, Options: string(optionsJSON)}
}

func finishWebauthnRegisterAlt(t *testing.T, web *webauthn.WebAuthn, attestation *webauthnAttestationAlt, response string) *webauthn.Credential {
	parsedResponse, err := protocol.ParseCredentialCreationResponseBody(strings.NewReader(response))
	assert.NoError(t, err)
	credential, err := web.CreateCredential(attestation.User, *attestation.Session, parsedResponse)
	require.NoError(t, err)
	return credential
}

/// Login

type webauthnAssertionAlt struct {
	User    *webauthnUserAlt
	Session *webauthn.SessionData
	Options string
}

func startWebauthnLoginAlt(t *testing.T, web *webauthn.WebAuthn, cred *webauthn.Credential, credID []byte) *webauthnAssertionAlt {
	user := newWebauthnAltUser()
	user.Credentials = []webauthn.Credential{*cred}

	options, session, err := web.BeginLogin(user)
	require.NoError(t, err)

	optionsJSON, err := json.Marshal(options)
	require.NoError(t, err)

	return &webauthnAssertionAlt{User: user, Session: session, Options: string(optionsJSON)}
}

func finishWebauthnLoginAlt(t *testing.T, web *webauthn.WebAuthn, assertion *webauthnAssertionAlt, response string) {
	parsedResponse, err := protocol.ParseCredentialRequestResponseBody(strings.NewReader(response))
	assert.NoError(t, err)
	_, err = web.ValidateLogin(assertion.User, *assertion.Session, parsedResponse)
	assert.NoError(t, err)
}

/// Utils

type webauthnUserAlt struct {
	ID          []byte
	Name        string
	DisplayName string
	Credentials []webauthn.Credential
}

func (u *webauthnUserAlt) WebAuthnID() []byte {
	return u.ID
}

func (u *webauthnUserAlt) WebAuthnName() string {
	return u.Name
}

func (u *webauthnUserAlt) WebAuthnDisplayName() string {
	return u.DisplayName
}

func (u *webauthnUserAlt) WebAuthnCredentials() []webauthn.Credential {
	return u.Credentials
}

func (u *webauthnUserAlt) WebAuthnIcon() string {
	return ""
}

func newWebauthnAltUser() *webauthnUserAlt {
	return &webauthnUserAlt{
		ID:          []byte(UserID),
		Name:        UserName,
		DisplayName: UserDisplayName,
	}
}

var webauthnConfigAlt = &webauthn.Config{
	RPID:                  WebauthnDomain,
	RPDisplayName:         WebauthnDisplayName,
	RPOrigins:             []string{WebauthnOrigin},
	AttestationPreference: protocol.PreferNoAttestation,
	AuthenticatorSelection: protocol.AuthenticatorSelection{
		UserVerification: protocol.VerificationDiscouraged,
	},
}
