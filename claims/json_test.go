package claims

import (
	"encoding/json"
	"strings"
	"testing"

	jwtv5 "github.com/golang-jwt/jwt/v5"
)

func TestClaimsMarshalCustom(t *testing.T) {
	t.Parallel()
	for _, tt := range []struct {
		name    string
		claims  Claims
		wantErr bool
	}{
		{name: "empty"},
		{name: "custom integer", claims: Claims{RegisteredClaims: jwtv5.RegisteredClaims{Subject: "42"}, Custom: map[string]any{"large": json.Number("9007199254740993")}}},
		{name: "reserved", claims: Claims{Custom: map[string]any{"exp": 0}}, wantErr: true},
		{name: "reserved case", claims: Claims{Custom: map[string]any{"ToKeN_Id": "override"}}, wantErr: true},
		{name: "unicode case alias", claims: Claims{Custom: map[string]any{"iſſ": "override"}}, wantErr: true},
		{name: "custom unsupported", claims: Claims{Custom: map[string]any{"invalid": make(chan int)}}, wantErr: true},
		{name: "ext unsupported", claims: Claims{Ext: map[string]any{"invalid": make(chan int)}}, wantErr: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			data, err := json.Marshal(tt.claims)
			if (err != nil) != tt.wantErr {
				t.Fatalf("want error %v, got %v", tt.wantErr, err)
			}
			if err != nil {
				return
			}
			var fields map[string]json.RawMessage
			if err := json.Unmarshal(data, &fields); err != nil {
				t.Fatal(err)
			}
			if _, exists := fields["Custom"]; exists {
				t.Fatal("unexpected Custom envelope")
			}
			if tt.name == "custom integer" && (string(fields["large"]) != "9007199254740993" || string(fields["sub"]) != `"42"`) {
				t.Fatalf("claims changed: %s", data)
			}
		})
	}
}

func TestReservedClaimNames(t *testing.T) {
	t.Parallel()
	for _, name := range []string{"iss", "sub", "aud", "exp", "nbf", "iat", "jti", "uid", "prv", "roles", "token_id", "auth_time", "ext", "external", ""} {
		t.Run(name, func(t *testing.T) {
			want := name != "external" && name != ""
			if IsReservedName(name) != want || IsReservedName(strings.ToUpper(name)) != want {
				t.Fatalf("wrong reserved result for %q", name)
			}
		})
	}
}
