package virtualwebauthn

type RelyingParty struct {
	Name   string `json:"name"`
	ID     string `json:"id"`
	Origin string `json:"origin"`
}
