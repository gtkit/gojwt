package gojwt_test

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"math/big"
	"strings"
	"testing"

	jwtv5 "github.com/golang-jwt/jwt/v5"
	"github.com/gtkit/gojwt"
	"github.com/stretchr/testify/require"
)

func TestCryptoRSAParameterDomain(t *testing.T) {
	t.Parallel()
	key := capabilityRSAKey(t)
	tests := []struct {
		name    string
		n       *big.Int
		e       int
		wantErr error
	}{
		{name: "valid", n: key.N, e: key.E},
		{name: "nil modulus", e: key.E, wantErr: gojwt.ErrInvalidKey},
		{name: "zero modulus", n: new(big.Int), e: key.E, wantErr: gojwt.ErrInvalidKey},
		{name: "negative modulus", n: new(big.Int).Neg(key.N), e: key.E, wantErr: gojwt.ErrInvalidKey},
		{name: "even modulus", n: new(big.Int).Add(key.N, big.NewInt(1)), e: key.E, wantErr: gojwt.ErrInvalidKey},
		{name: "short modulus", n: new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 2047), big.NewInt(1)), e: key.E, wantErr: gojwt.ErrInvalidConfig},
		{name: "zero exponent", n: key.N, wantErr: gojwt.ErrInvalidKey},
		{name: "one exponent", n: key.N, e: 1, wantErr: gojwt.ErrInvalidKey},
		{name: "even exponent", n: key.N, e: 2, wantErr: gojwt.ErrInvalidKey},
		{name: "negative exponent", n: key.N, e: -3, wantErr: gojwt.ErrInvalidKey},
	}
	if maxInt := int(^uint(0) >> 1); maxInt > 1<<31-1 {
		tests = append(tests, struct {
			name    string
			n       *big.Int
			e       int
			wantErr error
		}{name: "too large exponent", n: key.N, e: maxInt, wantErr: gojwt.ErrInvalidKey})
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			j, err := gojwt.NewJwtRSAVerifier(&rsa.PublicKey{N: tc.n, E: tc.e})
			if tc.wantErr != nil {
				require.ErrorIs(t, err, tc.wantErr)
				require.Nil(t, j)
				return
			}
			require.NoError(t, err)
			require.NotNil(t, j)
		})
	}
}

func TestCryptoECDSAOptionRejectedByOtherAlgorithms(t *testing.T) {
	t.Parallel()
	publicKey, privateKey := capabilityEd25519Keys(t)
	rsaKey := capabilityRSAKey(t)
	tests := []struct {
		name string
		new  func(gojwt.Option) error
	}{
		{name: "HMAC", new: func(opt gojwt.Option) error { _, err := gojwt.NewJwtHmac(make([]byte, 32), opt); return err }},
		{name: "RSA", new: func(opt gojwt.Option) error { _, err := gojwt.NewJwtRSAVerifier(&rsaKey.PublicKey, opt); return err }},
		{name: "Ed25519", new: func(opt gojwt.Option) error {
			_, err := gojwt.NewJwtEd25519FromKeys(privateKey, publicKey, opt)
			return err
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			require.ErrorIs(t, tc.new(gojwt.WithECDSASigningMethod(jwtv5.SigningMethodES256)), gojwt.ErrInvalidConfig)
		})
	}
}

func TestCryptoRSAPrivateParameterDomain(t *testing.T) {
	t.Parallel()
	key := capabilityRSAKey(t)
	tests := []struct {
		name   string
		mutate func(*rsa.PrivateKey)
	}{
		{name: "nil D", mutate: func(k *rsa.PrivateKey) { k.D = nil }},
		{name: "zero D", mutate: func(k *rsa.PrivateKey) { k.D = new(big.Int) }},
		{name: "negative D", mutate: func(k *rsa.PrivateKey) { k.D = new(big.Int).Neg(k.D) }},
		{name: "incorrect D", mutate: func(k *rsa.PrivateKey) { k.D = big.NewInt(1) }},
		{name: "nil prime", mutate: func(k *rsa.PrivateKey) { k.Primes[0] = nil }},
		{name: "zero prime", mutate: func(k *rsa.PrivateKey) { k.Primes[0] = new(big.Int) }},
		{name: "negative prime", mutate: func(k *rsa.PrivateKey) { k.Primes[0] = new(big.Int).Neg(k.Primes[0]) }},
		{name: "incorrect prime", mutate: func(k *rsa.PrivateKey) { k.Primes[0] = big.NewInt(3) }},
		{name: "missing primes", mutate: func(k *rsa.PrivateKey) { k.Primes = nil }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			copyKey := *key
			copyKey.Primes = append([]*big.Int{}, key.Primes...)
			tc.mutate(&copyKey)
			j, err := gojwt.NewJwtRSAFromKeys(&copyKey, &key.PublicKey)
			require.ErrorIs(t, err, gojwt.ErrInvalidKey)
			require.Nil(t, j)
		})
	}
}

func TestCryptoPSSRequiresJOSESalt(t *testing.T) {
	t.Parallel()
	key := capabilityRSAKey(t)
	methods := []struct {
		name   string
		method *jwtv5.SigningMethodRSAPSS
	}{
		{name: "PS256", method: jwtv5.SigningMethodPS256},
		{name: "PS384", method: jwtv5.SigningMethodPS384},
		{name: "PS512", method: jwtv5.SigningMethodPS512},
	}
	for _, method := range methods {
		t.Run(method.name, func(t *testing.T) {
			t.Parallel()
			issuer, err := gojwt.NewJwtRSAFromKeys(key, &key.PublicKey, gojwt.WithRSASigningMethod(method.method))
			require.NoError(t, err)
			verifier, err := gojwt.NewJwtRSAVerifier(&key.PublicKey, gojwt.WithRSASigningMethod(method.method))
			require.NoError(t, err)
			token, err := issuer.GenerateToken(42)
			require.NoError(t, err)
			parts := strings.Split(token, ".")
			signingInput := parts[0] + "." + parts[1]
			hasher := method.method.Hash.New()
			_, err = hasher.Write([]byte(signingInput))
			require.NoError(t, err)
			salts := []struct {
				name string
				len  int
				pass bool
			}{
				{name: "hash sized", len: method.method.Hash.Size(), pass: true},
				{name: "one byte", len: 1},
				{name: "half sized", len: method.method.Hash.Size() / 2},
				{name: "one longer", len: method.method.Hash.Size() + 1},
				{name: "legacy maximum", len: rsa.PSSSaltLengthAuto},
			}
			for _, salt := range salts {
				t.Run(salt.name, func(t *testing.T) {
					signature, err := rsa.SignPSS(rand.Reader, key, method.method.Hash, hasher.Sum(nil), &rsa.PSSOptions{SaltLength: salt.len})
					require.NoError(t, err)
					modified := signingInput + "." + base64.RawURLEncoding.EncodeToString(signature)
					parsed, err := verifier.ParseTokenContext(t.Context(), modified)
					if !salt.pass {
						require.ErrorIs(t, err, gojwt.ErrTokenSignatureInvalid)
						require.Nil(t, parsed)
						return
					}
					require.NoError(t, err)
					require.Equal(t, int64(42), parsed.UserID)
				})
			}
			// 构造和验签没有污染上游全局对象的兼容设置。
			require.Equal(t, rsa.PSSSaltLengthAuto, method.method.VerifyOptions.SaltLength)
		})
	}
}

func TestCryptoRSASigningMethodValidationAndCopy(t *testing.T) {
	t.Parallel()
	key := capabilityRSAKey(t)
	tests := []struct {
		name    string
		method  jwtv5.SigningMethod
		mutate  func(jwtv5.SigningMethod)
		wantErr error
	}{
		{name: "RS method copy", method: &jwtv5.SigningMethodRSA{Name: "RS256", Hash: crypto.SHA256}, mutate: func(m jwtv5.SigningMethod) { m.(*jwtv5.SigningMethodRSA).Hash = crypto.SHA512 }},
		{name: "PS method deep copy", method: &jwtv5.SigningMethodRSAPSS{SigningMethodRSA: &jwtv5.SigningMethodRSA{Name: "PS256", Hash: crypto.SHA256}, Options: &rsa.PSSOptions{SaltLength: 1}, VerifyOptions: &rsa.PSSOptions{SaltLength: 1}}, mutate: func(m jwtv5.SigningMethod) {
			ps := m.(*jwtv5.SigningMethodRSAPSS)
			ps.Hash = crypto.SHA512
			ps.Options.SaltLength = 16
			ps.VerifyOptions.SaltLength = 16
		}},
		{name: "nil interface", wantErr: gojwt.ErrInvalidConfig},
		{name: "typed nil RS", method: (*jwtv5.SigningMethodRSA)(nil), wantErr: gojwt.ErrInvalidConfig},
		{name: "typed nil PS", method: (*jwtv5.SigningMethodRSAPSS)(nil), wantErr: gojwt.ErrInvalidConfig},
		{name: "PS nil base", method: &jwtv5.SigningMethodRSAPSS{}, wantErr: gojwt.ErrInvalidConfig},
		{name: "wrong hash", method: &jwtv5.SigningMethodRSA{Name: "RS256", Hash: crypto.SHA1}, wantErr: gojwt.ErrInvalidConfig},
		{name: "PS masquerading as RS", method: &jwtv5.SigningMethodRSAPSS{SigningMethodRSA: &jwtv5.SigningMethodRSA{Name: "RS256", Hash: crypto.SHA256}}, wantErr: gojwt.ErrInvalidConfig},
		{name: "non RSA", method: jwtv5.SigningMethodEdDSA, wantErr: gojwt.ErrInvalidConfig},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			issuer, err := gojwt.NewJwtRSAFromKeys(key, &key.PublicKey, gojwt.WithRSASigningMethod(tc.method))
			if tc.wantErr != nil {
				require.ErrorIs(t, err, tc.wantErr)
				require.Nil(t, issuer)
				return
			}
			require.NoError(t, err)
			verifier, err := gojwt.NewJwtRSAVerifier(&key.PublicKey, gojwt.WithRSASigningMethod(tc.method))
			require.NoError(t, err)
			tc.mutate(tc.method)
			token, err := issuer.GenerateToken(42)
			require.NoError(t, err)
			parsed, err := verifier.ParseTokenContext(t.Context(), token)
			require.NoError(t, err)
			require.Equal(t, int64(42), parsed.UserID)
		})
	}
}
