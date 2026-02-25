package test

import (
	"encoding/json"
	"testing"

	"github.com/descope/virtualwebauthn"
	"github.com/stretchr/testify/require"
)

func TestDefaultClientExtensionResultsAndTransports(t *testing.T) {
	rp := virtualwebauthn.RelyingParty{Name: WebauthnDisplayName, ID: WebauthnDomain, Origin: WebauthnOrigin}
	authenticator := virtualwebauthn.NewAuthenticator()
	cred := virtualwebauthn.NewCredential(virtualwebauthn.KeyTypeEC2)

	attestation := startWebauthnRegister(t)
	attestationOptions, err := virtualwebauthn.ParseAttestationOptions(attestation.Options)
	require.NoError(t, err)

	attestationResponse := virtualwebauthn.CreateAttestationResponse(rp, authenticator, cred, *attestationOptions)
	var attestationJSON map[string]any
	require.NoError(t, json.Unmarshal([]byte(attestationResponse), &attestationJSON))

	clientExtensionResults, exists := attestationJSON["clientExtensionResults"]
	require.True(t, exists)
	require.Equal(t, map[string]any{}, clientExtensionResults)

	transports, exists := attestationJSON["response"].(map[string]any)["transports"]
	require.True(t, exists)
	require.Equal(t, []any{"internal"}, transports)

	webauthnCredential := finishWebauthnRegister(t, attestation, attestationResponse)
	authenticator.Options.UserHandle = []byte(UserID)
	authenticator.AddCredential(cred)

	assertion := startWebauthnLogin(t, webauthnCredential, cred.ID)
	assertionOptions, err := virtualwebauthn.ParseAssertionOptions(assertion.Options)
	require.NoError(t, err)

	assertionResponse := virtualwebauthn.CreateAssertionResponse(rp, authenticator, cred, *assertionOptions)
	var assertionJSON map[string]any
	require.NoError(t, json.Unmarshal([]byte(assertionResponse), &assertionJSON))

	clientExtensionResults, exists = assertionJSON["clientExtensionResults"]
	require.True(t, exists)
	require.Equal(t, map[string]any{}, clientExtensionResults)
}

func TestCustomClientExtensionResults(t *testing.T) {
	rp := virtualwebauthn.RelyingParty{Name: WebauthnDisplayName, ID: WebauthnDomain, Origin: WebauthnOrigin}
	authenticator := virtualwebauthn.NewAuthenticatorWithOptions(virtualwebauthn.AuthenticatorOptions{
		ClientExtensionResults: map[string]any{
			"credProps": map[string]any{"rk": true},
		},
	})
	cred := virtualwebauthn.NewCredential(virtualwebauthn.KeyTypeEC2)

	attestation := startWebauthnRegister(t)
	attestationOptions, err := virtualwebauthn.ParseAttestationOptions(attestation.Options)
	require.NoError(t, err)

	attestationResponse := virtualwebauthn.CreateAttestationResponse(rp, authenticator, cred, *attestationOptions)
	var attestationJSON map[string]any
	require.NoError(t, json.Unmarshal([]byte(attestationResponse), &attestationJSON))

	credProps := attestationJSON["clientExtensionResults"].(map[string]any)["credProps"].(map[string]any)
	require.Equal(t, true, credProps["rk"])

	webauthnCredential := finishWebauthnRegister(t, attestation, attestationResponse)
	authenticator.Options.UserHandle = []byte(UserID)
	authenticator.AddCredential(cred)

	assertion := startWebauthnLogin(t, webauthnCredential, cred.ID)
	assertionOptions, err := virtualwebauthn.ParseAssertionOptions(assertion.Options)
	require.NoError(t, err)

	assertionResponse := virtualwebauthn.CreateAssertionResponse(rp, authenticator, cred, *assertionOptions)
	var assertionJSON map[string]any
	require.NoError(t, json.Unmarshal([]byte(assertionResponse), &assertionJSON))

	credProps = assertionJSON["clientExtensionResults"].(map[string]any)["credProps"].(map[string]any)
	require.Equal(t, true, credProps["rk"])
}

func TestCustomTransports(t *testing.T) {
	rp := virtualwebauthn.RelyingParty{Name: WebauthnDisplayName, ID: WebauthnDomain, Origin: WebauthnOrigin}
	authenticator := virtualwebauthn.NewAuthenticatorWithOptions(virtualwebauthn.AuthenticatorOptions{
		Transports: []virtualwebauthn.Transport{virtualwebauthn.TransportUSB, virtualwebauthn.TransportInternal},
	})
	cred := virtualwebauthn.NewCredential(virtualwebauthn.KeyTypeEC2)

	attestation := startWebauthnRegister(t)
	attestationOptions, err := virtualwebauthn.ParseAttestationOptions(attestation.Options)
	require.NoError(t, err)

	attestationResponse := virtualwebauthn.CreateAttestationResponse(rp, authenticator, cred, *attestationOptions)
	var attestationJSON map[string]any
	require.NoError(t, json.Unmarshal([]byte(attestationResponse), &attestationJSON))

	transports := attestationJSON["response"].(map[string]any)["transports"].([]any)
	require.Equal(t, []any{"usb", "internal"}, transports)

	webauthnCredential := finishWebauthnRegister(t, attestation, attestationResponse)
	authenticator.Options.UserHandle = []byte(UserID)
	authenticator.AddCredential(cred)

	assertion := startWebauthnLogin(t, webauthnCredential, cred.ID)
	assertionOptions, err := virtualwebauthn.ParseAssertionOptions(assertion.Options)
	require.NoError(t, err)

	assertionResponse := virtualwebauthn.CreateAssertionResponse(rp, authenticator, cred, *assertionOptions)
	var assertionJSON map[string]any
	require.NoError(t, json.Unmarshal([]byte(assertionResponse), &assertionJSON))

	_, exists := assertionJSON["response"].(map[string]any)["transports"]
	require.False(t, exists, "transports should not appear in assertion responses")
}
