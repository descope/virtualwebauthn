package test

import (
	"encoding/json"
	"testing"

	"github.com/descope/virtualwebauthn"
	"github.com/stretchr/testify/require"
)

// TestAttestationClientExtensionResults verifies that attestation responses include
// an empty clientExtensionResults map
func TestAttestationClientExtensionResults(t *testing.T) {
	// Create a mock relying party, mock authenticator and a mock credential
	rp := virtualwebauthn.RelyingParty{Name: WebauthnDisplayName, ID: WebauthnDomain, Origin: WebauthnOrigin}
	authenticator := virtualwebauthn.NewAuthenticator()
	cred := virtualwebauthn.NewCredential(virtualwebauthn.KeyTypeEC2)

	// Start an attestation request
	attestation := startWebauthnRegister(t)

	// Parse the attestation options
	attestationOptions, err := virtualwebauthn.ParseAttestationOptions(attestation.Options)
	require.NoError(t, err)
	require.NotNil(t, attestationOptions)

	// Create an attestation response
	attestationResponse := virtualwebauthn.CreateAttestationResponse(rp, authenticator, cred, *attestationOptions)
	require.NotEmpty(t, attestationResponse)

	// Parse the response to verify clientExtensionResults
	var response map[string]interface{}
	err = json.Unmarshal([]byte(attestationResponse), &response)
	require.NoError(t, err)

	// Verify clientExtensionResults exists
	clientExtensionResults, exists := response["clientExtensionResults"]
	require.True(t, exists, "clientExtensionResults should exist in attestation response")
	require.NotNil(t, clientExtensionResults, "clientExtensionResults should not be nil")

	// Verify clientExtensionResults is an empty map
	clientExtensionResultsMap, ok := clientExtensionResults.(map[string]interface{})
	require.True(t, ok, "clientExtensionResults should be a map")
	require.Empty(t, clientExtensionResultsMap, "clientExtensionResults should be an empty map")
}

// TestAssertionClientExtensionResults verifies that assertion responses include
// the empty clientExtensionResults map
func TestAssertionClientExtensionResults(t *testing.T) {
	// Create a mock relying party, mock authenticator and a mock credential
	rp := virtualwebauthn.RelyingParty{Name: WebauthnDisplayName, ID: WebauthnDomain, Origin: WebauthnOrigin}
	authenticator := virtualwebauthn.NewAuthenticator()
	cred := virtualwebauthn.NewCredential(virtualwebauthn.KeyTypeEC2)

	// Register the credential first
	attestation := startWebauthnRegister(t)
	attestationOptions, err := virtualwebauthn.ParseAttestationOptions(attestation.Options)
	require.NoError(t, err)

	attestationResponse := virtualwebauthn.CreateAttestationResponse(rp, authenticator, cred, *attestationOptions)
	webauthnCredential := finishWebauthnRegister(t, attestation, attestationResponse)

	authenticator.Options.UserHandle = []byte(UserID)
	authenticator.AddCredential(cred)

	// Start an assertion request
	assertion := startWebauthnLogin(t, webauthnCredential, cred.ID)

	// Parse the assertion options
	assertionOptions, err := virtualwebauthn.ParseAssertionOptions(assertion.Options)
	require.NoError(t, err)
	require.NotNil(t, assertionOptions)

	// Create an assertion response
	assertionResponse := virtualwebauthn.CreateAssertionResponse(rp, authenticator, cred, *assertionOptions)
	require.NotEmpty(t, assertionResponse)

	// Parse the response to verify clientExtensionResults
	var response map[string]interface{}
	err = json.Unmarshal([]byte(assertionResponse), &response)
	require.NoError(t, err)

	// Verify clientExtensionResults exists
	clientExtensionResults, exists := response["clientExtensionResults"]
	require.True(t, exists, "clientExtensionResults should exist in assertion response")
	require.NotNil(t, clientExtensionResults, "clientExtensionResults should not be nil")

	// Verify clientExtensionResults is an empty map
	clientExtensionResultsMap, ok := clientExtensionResults.(map[string]interface{})
	require.True(t, ok, "clientExtensionResults should be a map")
	require.Empty(t, clientExtensionResultsMap, "clientExtensionResults should be an empty map")
}

// TestBothKeyTypesWithClientExtensionResults verifies that both EC2 and RSA key types
// work correctly with clientExtensionResults
func TestBothKeyTypesWithClientExtensionResults(t *testing.T) {
	// Test EC2 key
	t.Run("EC2 Key", func(t *testing.T) {
		testKeyTypeWithClientExtensionResults(t, virtualwebauthn.KeyTypeEC2)
	})

	// Test RSA key
	t.Run("RSA Key", func(t *testing.T) {
		testKeyTypeWithClientExtensionResults(t, virtualwebauthn.KeyTypeRSA)
	})
}

func testKeyTypeWithClientExtensionResults(t *testing.T, keyType virtualwebauthn.KeyType) {
	// Create a mock relying party, mock authenticator and a mock credential
	rp := virtualwebauthn.RelyingParty{Name: WebauthnDisplayName, ID: WebauthnDomain, Origin: WebauthnOrigin}
	authenticator := virtualwebauthn.NewAuthenticator()
	cred := virtualwebauthn.NewCredential(keyType)

	// Test attestation
	attestation := startWebauthnRegister(t)
	attestationOptions, err := virtualwebauthn.ParseAttestationOptions(attestation.Options)
	require.NoError(t, err)

	attestationResponse := virtualwebauthn.CreateAttestationResponse(rp, authenticator, cred, *attestationOptions)
	webauthnCredential := finishWebauthnRegister(t, attestation, attestationResponse)

	// Verify attestation response has clientExtensionResults
	var attestationResponseMap map[string]interface{}
	err = json.Unmarshal([]byte(attestationResponse), &attestationResponseMap)
	require.NoError(t, err)
	require.Contains(t, attestationResponseMap, "clientExtensionResults")

	// Test assertion
	authenticator.Options.UserHandle = []byte(UserID)
	authenticator.AddCredential(cred)

	assertion := startWebauthnLogin(t, webauthnCredential, cred.ID)
	assertionOptions, err := virtualwebauthn.ParseAssertionOptions(assertion.Options)
	require.NoError(t, err)

	assertionResponse := virtualwebauthn.CreateAssertionResponse(rp, authenticator, cred, *assertionOptions)
	finishWebauthnLogin(t, assertion, assertionResponse)

	// Verify assertion response has clientExtensionResults
	var assertionResponseMap map[string]interface{}
	err = json.Unmarshal([]byte(assertionResponse), &assertionResponseMap)
	require.NoError(t, err)
	require.Contains(t, assertionResponseMap, "clientExtensionResults")
}
