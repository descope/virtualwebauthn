package virtualwebauthn

type AuthenticatorOptions struct {
	UserHandle      []byte
	UserNotPresent  bool
	UserNotVerified bool
	BackupEligible  bool
	BackupState     bool
}

type Authenticator struct {
	Options     AuthenticatorOptions `json:"options"`
	Aaguid      [16]byte             `json:"aaguid"`
	Credentials []Credential         `json:"credentials,omitempty"`
}

func NewAuthenticator() Authenticator {
	return NewAuthenticatorWithOptions(AuthenticatorOptions{})
}

func NewAuthenticatorWithOptions(options AuthenticatorOptions) Authenticator {
	auth := Authenticator{Options: options}
	copy(auth.Aaguid[:], randomBytes(len(auth.Aaguid)))
	return auth
}

func (a *Authenticator) AddCredential(cred Credential) {
	a.Credentials = append(a.Credentials, cred)
}

func (a *Authenticator) FindAllowedCredential(options AssertionOptions) *Credential {
	for i := range a.Credentials {
		if a.Credentials[i].IsAllowedForAssertion(options) {
			return &a.Credentials[i]
		}
	}
	return nil
}
