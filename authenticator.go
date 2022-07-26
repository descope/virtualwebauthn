package virtualwebauthn

type Authenticator struct {
	Aaguid      [16]byte     `json:"aaguid"`
	Credentials []Credential `json:"credentials,omitempty"`
}

func NewAuthenticator() Authenticator {
	auth := Authenticator{}
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
