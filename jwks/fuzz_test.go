package jwks_test

import (
	"encoding/json"
	"testing"

	"github.com/gtkit/gojwt/jwks"
)

func FuzzParse(f *testing.F) {
	for _, seed := range []string{`{"keys":[]}`, `{"keys":[null]}`, `{"keys":[],"keys":[]}`, `{"keys":[{"kty":"oct","k":"secret"}]}`, `{"keys":[{"kty":"EC","crv":"P-256","x":"AA","y":"AA"}]}`} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 8192 {
			t.Skip()
		}
		set, err := jwks.Parse(data)
		if err != nil {
			return
		}
		encoded, err := json.Marshal(set)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := jwks.Parse(encoded); err != nil {
			t.Fatalf("accepted set cannot round trip: %v", err)
		}
	})
}
