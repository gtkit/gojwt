package jwks_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"strings"
	"testing"

	"github.com/gtkit/gojwt"
	"github.com/gtkit/gojwt/jwks"
	"github.com/stretchr/testify/require"
)

type publicFixture struct {
	name string
	key  any
	alg  string
}

func publicFixtures(t *testing.T) []publicFixture {
	t.Helper()
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	edKey, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	fixtures := []publicFixture{{name: "RSA", key: &rsaKey.PublicKey, alg: "RS256"}, {name: "Ed25519", key: edKey, alg: "EdDSA"}}
	for _, tc := range []struct {
		curve elliptic.Curve
		alg   string
	}{{curve: elliptic.P256(), alg: "ES256"}, {curve: elliptic.P384(), alg: "ES384"}, {curve: elliptic.P521(), alg: "ES512"}} {
		key, err := ecdsa.GenerateKey(tc.curve, rand.Reader)
		require.NoError(t, err)
		fixtures = append(fixtures, publicFixture{name: tc.curve.Params().Name, key: &key.PublicKey, alg: tc.alg})
	}
	return fixtures
}

func edSet(t *testing.T, kid string) *jwks.Set {
	t.Helper()
	key, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	j, err := jwks.NewKey(kid, key, "EdDSA")
	require.NoError(t, err)
	set, err := jwks.NewSet(j)
	require.NoError(t, err)
	return set
}

func setJSON(t *testing.T, set *jwks.Set) []byte {
	t.Helper()
	data, err := set.MarshalJSON()
	require.NoError(t, err)
	return data
}

func keyJSON(t *testing.T, key jwks.JWK, name string, value any) []byte {
	t.Helper()
	data, err := json.Marshal(key)
	require.NoError(t, err)
	var fields map[string]any
	require.NoError(t, json.Unmarshal(data, &fields))
	fields[name] = value
	data, err = json.Marshal(map[string]any{"keys": []any{fields}})
	require.NoError(t, err)
	return data
}

func TestPublicKeyRoundTrip(t *testing.T) {
	for _, fixture := range publicFixtures(t) {
		for _, declared := range []string{"", fixture.alg} {
			t.Run(fixture.name+"/"+declared, func(t *testing.T) {
				j, err := jwks.NewKey("key", fixture.key, declared)
				require.NoError(t, err)
				set, err := jwks.NewSet(j)
				require.NoError(t, err)
				parsed, err := jwks.Parse(setJSON(t, set))
				require.NoError(t, err)
				resolved, err := parsed.ResolveKey(t.Context(), "key", fixture.alg)
				require.NoError(t, err)
				wantDER, err := x509.MarshalPKIXPublicKey(fixture.key)
				require.NoError(t, err)
				gotDER, err := x509.MarshalPKIXPublicKey(resolved)
				require.NoError(t, err)
				require.Equal(t, wantDER, gotDER)
				_, err = parsed.ResolveKey(t.Context(), "unknown", fixture.alg)
				require.ErrorIs(t, err, gojwt.ErrUnknownKeyID)
				_, err = parsed.ResolveKey(t.Context(), "key", "HS256")
				require.ErrorIs(t, err, jwks.ErrAlgorithmMismatch)
				ctx, cancel := context.WithCancel(t.Context())
				cancel()
				_, err = parsed.ResolveKey(ctx, "key", fixture.alg)
				require.ErrorIs(t, err, context.Canceled)
				var nilCtx context.Context // Exercise the documented nil-context policy.
				_, err = parsed.ResolveKey(nilCtx, "key", fixture.alg)
				require.NoError(t, err)
			})
		}
	}
}

func TestSetDoesNotExposeMutableKeys(t *testing.T) {
	for _, fixture := range publicFixtures(t) {
		t.Run(fixture.name, func(t *testing.T) {
			j, err := jwks.NewKey("key", fixture.key, fixture.alg)
			require.NoError(t, err)
			set, err := jwks.NewSet(j)
			require.NoError(t, err)
			original := setJSON(t, set)
			j.KeyOps[0] = "sign"
			keys := set.Keys()
			keys[0].KeyOps[0] = "sign"
			keys[0].KeyID = "changed"
			resolved, err := set.ResolveKey(t.Context(), "key", fixture.alg)
			require.NoError(t, err)
			switch key := resolved.(type) {
			case *rsa.PublicKey:
				key.N.SetInt64(1)
				key.E = 3
			case *ecdsa.PublicKey:
				key.X.SetInt64(1) //nolint:staticcheck // Deliberately corrupt the returned key to verify snapshot isolation.
				key.Y.SetInt64(1) //nolint:staticcheck // Deliberately corrupt the returned key to verify snapshot isolation.
			case ed25519.PublicKey:
				key[0] ^= 255
			}
			got, err := set.ResolveKey(t.Context(), "key", fixture.alg)
			require.NoError(t, err)
			wantDER, err := x509.MarshalPKIXPublicKey(fixture.key)
			require.NoError(t, err)
			gotDER, err := x509.MarshalPKIXPublicKey(got)
			require.NoError(t, err)
			require.Equal(t, wantDER, gotDER)
			require.Equal(t, original, setJSON(t, set))
		})
	}
}

func TestParseRejectsPrivateAndInvalidSets(t *testing.T) {
	key := edSet(t, "key").Keys()[0]
	for _, tc := range []struct {
		name string
		data []byte
	}{
		{name: "invalid JSON", data: []byte(`{`)},
		{name: "invalid UTF8", data: []byte("{\"keys\":[],\"extra\":\"\xff\"}")},
		{name: "non-object", data: []byte(`[]`)},
		{name: "null", data: []byte(`null`)},
		{name: "missing keys", data: []byte(`{}`)},
		{name: "null keys", data: []byte(`{"keys":null}`)},
		{name: "scalar keys", data: []byte(`{"keys":42}`)},
		{name: "null key", data: []byte(`{"keys":[null]}`)},
		{name: "non-object key", data: []byte(`{"keys":[42]}`)},
		{name: "duplicate member", data: []byte(`{"keys":[],"keys":[]}`)},
		{name: "trailing JSON", data: []byte(`{"keys":[]} {}`)},
		{name: "private scalar", data: keyJSON(t, key, "d", "secret")},
		{name: "private null", data: keyJSON(t, key, "d", nil)},
		{name: "uppercase private null", data: keyJSON(t, key, "D", nil)},
		{name: "uppercase private prime", data: keyJSON(t, key, "P", "secret")},
		{name: "uppercase type", data: keyJSON(t, key, "KTY", "OKP")},
		{name: "uppercase algorithm", data: keyJSON(t, key, "ALG", "EdDSA")},
		{name: "mixed case key operations", data: keyJSON(t, key, "Key_Ops", []string{"verify"})},
		{name: "Unicode case folded use", data: keyJSON(t, key, "uſe", "sig")},
		{name: "RSA prime", data: keyJSON(t, key, "p", "secret")},
		{name: "RSA other primes", data: keyJSON(t, key, "oth", []any{})},
		{name: "symmetric material", data: keyJSON(t, key, "k", "secret")},
		{name: "oct key", data: keyJSON(t, key, "kty", "oct")},
		{name: "null kid", data: keyJSON(t, key, "kid", nil)},
		{name: "numeric kid", data: keyJSON(t, key, "kid", 4)},
		{name: "null key operations", data: keyJSON(t, key, "key_ops", nil)},
		{name: "non-string key operations", data: keyJSON(t, key, "key_ops", []int{1})},
		{name: "no key operation", data: keyJSON(t, key, "key_ops", []string{})},
		{name: "sign operation", data: keyJSON(t, key, "key_ops", []string{"sign"})},
		{name: "mixed operations", data: keyJSON(t, key, "key_ops", []string{"verify", "sign"})},
		{name: "encryption use", data: keyJSON(t, key, "use", "enc")},
		{name: "wrong algorithm", data: keyJSON(t, key, "alg", "HS256")},
		{name: "wrong curve", data: keyJSON(t, key, "crv", "X25519")},
		{name: "mixed parameters", data: keyJSON(t, key, "n", "AQ")},
		{name: "empty coordinate", data: keyJSON(t, key, "x", "")},
		{name: "invalid base64", data: keyJSON(t, key, "x", "%%%")},
		{name: "padding", data: keyJSON(t, key, "x", key.X+"=")},
		{name: "newline base64", data: keyJSON(t, key, "x", key.X[:3]+"\n"+key.X[3:])},
		{name: "short coordinate", data: keyJSON(t, key, "x", "AQ")},
		{name: "size bomb", data: []byte(strings.Repeat(" ", jwks.MaxSetBytes+1))},
		{name: "nesting bomb", data: []byte(`{"keys":[],"extra":` + strings.Repeat("[", 40) + "0" + strings.Repeat("]", 40) + "}")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			set, err := jwks.Parse(tc.data)
			require.Nil(t, set)
			require.ErrorIs(t, err, jwks.ErrInvalidSet)
		})
	}
}

func TestKeyParameterValidation(t *testing.T) {
	fixtures := publicFixtures(t)
	rsaJWK, err := jwks.NewKey("rsa", fixtures[0].key, "")
	require.NoError(t, err)
	ecJWK, err := jwks.NewKey("ec", fixtures[2].key, "")
	require.NoError(t, err)
	for _, tc := range []struct {
		name string
		key  jwks.JWK
		edit func(*jwks.JWK)
	}{
		{name: "RSA zero exponent", key: rsaJWK, edit: func(j *jwks.JWK) { j.E = "AA" }},
		{name: "RSA exponent one", key: rsaJWK, edit: func(j *jwks.JWK) { j.E = "AQ" }},
		{name: "RSA even exponent", key: rsaJWK, edit: func(j *jwks.JWK) { j.E = "Ag" }},
		{name: "RSA oversized exponent", key: rsaJWK, edit: func(j *jwks.JWK) { j.E = "AQAAAAE" }},
		{name: "RSA invalid exponent", key: rsaJWK, edit: func(j *jwks.JWK) { j.E = "%" }},
		{name: "RSA zero modulus", key: rsaJWK, edit: func(j *jwks.JWK) { j.N = "AA" }},
		{name: "RSA short modulus", key: rsaJWK, edit: func(j *jwks.JWK) { j.N = "Aw" }},
		{name: "RSA leading zero", key: rsaJWK, edit: func(j *jwks.JWK) {
			data, _ := base64.RawURLEncoding.DecodeString(j.N)
			j.N = base64.RawURLEncoding.EncodeToString(append([]byte{0}, data...))
		}},
		{name: "RSA even modulus", key: rsaJWK, edit: func(j *jwks.JWK) {
			data, _ := base64.RawURLEncoding.DecodeString(j.N)
			data[len(data)-1] &^= 1
			j.N = base64.RawURLEncoding.EncodeToString(data)
		}},
		{name: "RSA mixed key", key: rsaJWK, edit: func(j *jwks.JWK) { j.X = "AQ" }},
		{name: "EC unsupported curve", key: ecJWK, edit: func(j *jwks.JWK) { j.Curve = "secp256k1" }},
		{name: "EC wrong algorithm", key: ecJWK, edit: func(j *jwks.JWK) { j.Algorithm = "ES512" }},
		{name: "EC wrong X length", key: ecJWK, edit: func(j *jwks.JWK) { j.X = "AQ" }},
		{name: "EC wrong Y length", key: ecJWK, edit: func(j *jwks.JWK) { j.Y = "AQ" }},
		{name: "EC point outside curve", key: ecJWK, edit: func(j *jwks.JWK) { j.X = base64.RawURLEncoding.EncodeToString(make([]byte, 32)); j.Y = j.X }},
		{name: "EC mixed key", key: ecJWK, edit: func(j *jwks.JWK) { j.E = "AQ" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tc.edit(&tc.key)
			set, err := jwks.NewSet(tc.key)
			require.Nil(t, set)
			require.ErrorIs(t, err, jwks.ErrInvalidSet)
		})
	}
}

func TestSetLimitsAndEmptyIdentifiers(t *testing.T) {
	for _, tc := range []struct {
		name string
		run  func(*testing.T)
	}{
		{name: "empty set", run: func(t *testing.T) {
			set, err := jwks.Parse([]byte(`{"keys":[]}`))
			require.NoError(t, err)
			require.JSONEq(t, `{"keys":[]}`, string(setJSON(t, set)))
			_, err = set.ResolveKey(t.Context(), "", "EdDSA")
			require.ErrorIs(t, err, gojwt.ErrUnknownKeyID)
		}},
		{name: "explicit empty ID", run: func(t *testing.T) {
			set := edSet(t, "")
			_, err := set.ResolveKey(t.Context(), "", "EdDSA")
			require.NoError(t, err)
			_, err = set.ResolveKey(t.Context(), "unknown", "EdDSA")
			require.ErrorIs(t, err, gojwt.ErrUnknownKeyID)
		}},
		{name: "duplicate ID", run: func(t *testing.T) {
			key := edSet(t, "").Keys()[0]
			_, err := jwks.NewSet(key, key)
			require.ErrorIs(t, err, jwks.ErrInvalidSet)
			data, err := json.Marshal(map[string]any{"keys": []jwks.JWK{key, key}})
			require.NoError(t, err)
			_, err = jwks.Parse(data)
			require.ErrorIs(t, err, jwks.ErrInvalidSet)
		}},
		{name: "too many keys", run: func(t *testing.T) {
			key := edSet(t, "").Keys()[0]
			keys := make([]jwks.JWK, jwks.MaxKeys+1)
			for i := range keys {
				keys[i] = key
				keys[i].KeyID = fmt.Sprint(i)
			}
			_, err := jwks.NewSet(keys...)
			require.ErrorIs(t, err, jwks.ErrInvalidSet)
			data, err := json.Marshal(map[string]any{"keys": keys})
			require.NoError(t, err)
			_, err = jwks.Parse(data)
			require.ErrorIs(t, err, jwks.ErrInvalidSet)
		}},
		{name: "oversized export", run: func(t *testing.T) {
			key := edSet(t, "key").Keys()[0]
			key.KeyID = strings.Repeat("x", jwks.MaxSetBytes)
			_, err := jwks.NewSet(key)
			require.ErrorIs(t, err, jwks.ErrInvalidSet)
		}},
		{name: "nil and zero set", run: func(t *testing.T) {
			var set *jwks.Set
			require.Nil(t, set.Keys())
			_, err := set.MarshalJSON()
			require.ErrorIs(t, err, jwks.ErrInvalidSet)
			_, err = set.ResolveKey(t.Context(), "key", "EdDSA")
			require.ErrorIs(t, err, jwks.ErrInvalidSet)
			var zero jwks.Set
			require.JSONEq(t, `{"keys":[]}`, string(setJSON(t, &zero)))
		}},
	} {
		t.Run(tc.name, tc.run)
	}
}

func TestExportRejectsPrivateAndInvalidKeys(t *testing.T) {
	for _, tc := range []struct {
		name string
		key  any
	}{
		{name: "private RSA", key: &rsa.PrivateKey{}},
		{name: "private EC", key: &ecdsa.PrivateKey{}},
		{name: "private Ed25519", key: ed25519.PrivateKey{}},
		{name: "nil", key: nil},
		{name: "nil RSA", key: (*rsa.PublicKey)(nil)},
		{name: "negative RSA", key: &rsa.PublicKey{N: big.NewInt(-3), E: 65537}},
		{name: "nil EC", key: (*ecdsa.PublicKey)(nil)},
		{name: "missing EC coordinates", key: &ecdsa.PublicKey{Curve: elliptic.P256()}},
		{name: "unsupported EC", key: &ecdsa.PublicKey{Curve: elliptic.P224(), X: big.NewInt(1), Y: big.NewInt(1)}}, //nolint:staticcheck // Construct invalid input deliberately.
		{name: "negative EC", key: &ecdsa.PublicKey{Curve: elliptic.P256(), X: big.NewInt(-1), Y: big.NewInt(1)}},   //nolint:staticcheck // Construct invalid input deliberately.
		{name: "short Ed25519", key: ed25519.PublicKey{1}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := jwks.NewKey("key", tc.key, "")
			require.ErrorIs(t, err, jwks.ErrInvalidSet)
		})
	}
}

func TestSetPermitsUnknownPublicMetadataWithLargeNumbers(t *testing.T) {
	for _, nested := range []bool{false, true} {
		t.Run(map[bool]string{false: "top-level", true: "key metadata"}[nested], func(t *testing.T) {
			set := edSet(t, "key")
			large := json.Number(strings.Repeat("9", 400))
			var data []byte
			var err error
			if nested {
				data = keyJSON(t, set.Keys()[0], "extension", large)
			} else {
				data, err = json.Marshal(map[string]any{"keys": set.Keys(), "extension": large})
				require.NoError(t, err)
			}
			parsed, err := jwks.Parse(data)
			require.NoError(t, err)
			_, err = parsed.ResolveKey(t.Context(), "key", "EdDSA")
			require.NoError(t, err)
		})
	}
}
