
# Virtual WebAuthn

The Go package `virtualwebauthn` provides a set of helper tools for testing full [WebAuthn](https://fidoalliance.org/fido2-2/fido2-web-authentication-webauthn) authentication flows in a [relying party](https://www.w3.org/TR/webauthn-2/#webauthn-relying-party) WebAuthn server implementation without requiring a browser or an actual authenticator.

Check the [test](test/webauthn_test.go) for a working example on how to use this library.

## Features

- Test both register/attestation and login/assertion flows
- Validate credential [creation](https://www.w3.org/TR/webauthn-2/#sctn-credentialcreationoptions-extension) and [request](https://www.w3.org/TR/webauthn-2/#sctn-credentialrequestoptions-extension) options
- Generate [attestation](https://www.w3.org/TR/webauthn-2/#authenticatorattestationresponse) and [assertion](https://www.w3.org/TR/webauthn-2/#authenticatorassertionresponse) responses
- Supports `EC2` and `RSA` keys with `SHA256`
- Supports `packed` attestation format

## Usage

### Setup

First we create mock entities to work with for running tests.

```go
// The relying party settings should mirror those on the actual WebAuthn server
rp := virtualwebauthn.RelyingParty{Name: "Example Corp", ID: "example.com", Origin: "https://example.com"}

// A mock authenticator that represents a security key or biometrics module
authenticator := virtualwebauthn.NewAuthenticator()

// Create a new credential that we'll try to register with the relying party
credential := virtualwebauthn.NewCredential(virtualwebauthn.KeyTypeEC2)
```

### Register

Start a register flow with the relying party and get an `attestationOptions` JSON string that contains the serialized [credential creation options](https://www.w3.org/TR/webauthn-2/#sctn-credentialcreationoptions-extension):

```go
// Ask the server to start a register flow for a user. The server and user here
// are placeholders for whatever the system being tested uses.
attestationOptions := server.registerStart(user)
```

Use the `ParseAttestationOptions` and `CreateAttestationResponse` functions to parse the `attestationOptions` string, ensure that it's valid, and generate an appropriate `attestationResponse` that should appear to have come from a browser's `navigator.credentials.create` call:

```go
// Parses the attestation options we got from the relying party to ensure they're valid
parsedAttestationOptions, err := virtualwebauthn.ParseAttestationOptions(attestationOptions)
if err != nil {
    ...
}

// Creates an attestation response that we can send to the relying party as if it came from
// an actual browser and authenticator.
attestationResponse := virtualwebauthn.CreateAttestationResponse(rp, authenticator, credential, *parsedAttestationOptions)
```

We can now go back to the relying party with the `attestationResponse` and finish the register flow:

```go
// Finish the register flow by sending the attestation response. Again the server and
// user here are placeholders for whatever the system being tested uses.
err := server.registerFinish(user, attestationResponse)
if err != nil {
    ...
}

// Add the EC2 credential to the mock authenticator
authenticator.AddCredential(credential)
```
