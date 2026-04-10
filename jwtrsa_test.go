package gojwt_test

import (
	"crypto/rand"
	"crypto/rsa"
	"path/filepath"
	"testing"
	"time"

	jwtv5 "github.com/golang-jwt/jwt/v5"
	"github.com/gtkit/gojwt"
	"github.com/gtkit/gojwt/claims"
	"github.com/stretchr/testify/require"
)

// ---------- helpers ----------

func generateRSAKeyFiles(t *testing.T, bits int) (priPath, pubPath string) {
	t.Helper()
	dir := t.TempDir()
	priPath = filepath.Join(dir, "rsa.pem")
	pubPath = filepath.Join(dir, "rsa.pub.pem")
	require.NoError(t, gojwt.GenerateRSAKeys(priPath, pubPath, bits))
	return priPath, pubPath
}

func newRSA(t *testing.T, opts ...gojwt.Option) *gojwt.JwtRSA {
	t.Helper()
	priPath, pubPath := generateRSAKeyFiles(t, 2048)
	j, err := gojwt.NewJwtRSA(priPath, pubPath, opts...)
	require.NoError(t, err)
	return j
}

// ---------- basic ----------

func TestJwtRSAGenerateAndParse(t *testing.T) {
	j := newRSA(t)

	token, err := j.GenerateToken(99, claims.WithPrv("api"), claims.WithRoles("admin"))
	require.NoError(t, err)

	c, err := j.ParseToken(token)
	require.NoError(t, err)
	require.Equal(t, int64(99), c.UserID)
	require.Equal(t, "api", c.Prv)
	require.Equal(t, []string{"admin"}, c.Roles)
	require.Equal(t, c.TokenID, c.ID)
}

func TestJwtRSAUsesRS256ByDefault(t *testing.T) {
	j := newRSA(t)

	token, err := j.GenerateToken(1)
	require.NoError(t, err)

	parsed, _, err := jwtv5.NewParser().ParseUnverified(token, &claims.Claims{})
	require.NoError(t, err)
	require.Equal(t, jwtv5.SigningMethodRS256.Alg(), parsed.Method.Alg())
}

// ---------- signing methods ----------

func TestJwtRSASigningMethods(t *testing.T) {
	tests := []struct {
		name   string
		method jwtv5.SigningMethod
		bits   int
	}{
		{"RS256", jwtv5.SigningMethodRS256, 2048},
		{"RS384", jwtv5.SigningMethodRS384, 3072},
		{"RS512", jwtv5.SigningMethodRS512, 4096},
		{"PS256", jwtv5.SigningMethodPS256, 2048},
		{"PS384", jwtv5.SigningMethodPS384, 3072},
		{"PS512", jwtv5.SigningMethodPS512, 4096},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			priPath, pubPath := generateRSAKeyFiles(t, tc.bits)
			j, err := gojwt.NewJwtRSA(priPath, pubPath, gojwt.WithRSASigningMethod(tc.method))
			require.NoError(t, err)

			token, err := j.GenerateToken(1)
			require.NoError(t, err)

			parsed, _, err := jwtv5.NewParser().ParseUnverified(token, &claims.Claims{})
			require.NoError(t, err)
			require.Equal(t, tc.method.Alg(), parsed.Method.Alg())

			c, err := j.ParseToken(token)
			require.NoError(t, err)
			require.Equal(t, int64(1), c.UserID)
		})
	}
}

// ---------- refresh ----------

func TestJwtRSARefreshTokenRotatesTokenID(t *testing.T) {
	j := newRSA(t,
		gojwt.WithTokenDuration(2*time.Second),
		gojwt.WithRefreshDuration(time.Minute),
	)

	token, err := j.GenerateToken(10)
	require.NoError(t, err)

	orig, err := j.ParseToken(token)
	require.NoError(t, err)

	time.Sleep(1100 * time.Millisecond)

	refreshed, err := j.RefreshToken(token)
	require.NoError(t, err)

	rc, err := j.ParseToken(refreshed)
	require.NoError(t, err)
	require.NotEqual(t, orig.TokenID, rc.TokenID)
	require.Equal(t, rc.TokenID, rc.ID)
	require.True(t, rc.IssuedAt.Time.After(orig.IssuedAt.Time))
	require.True(t, rc.NotBefore.Time.After(orig.NotBefore.Time))
}

func TestJwtRSARefreshTooEarly(t *testing.T) {
	j := newRSA(t,
		gojwt.WithTokenDuration(10*time.Minute),
		gojwt.WithRefreshDuration(time.Hour),
	)

	token, err := j.GenerateToken(10)
	require.NoError(t, err)

	_, err = j.RefreshToken(token)
	require.ErrorIs(t, err, gojwt.ErrRefreshTooEarly)
}

// ---------- cached parse ----------

func TestJwtRSACachedParseToken(t *testing.T) {
	j := newRSA(t)

	token, err := j.GenerateToken(42)
	require.NoError(t, err)

	c1, err := j.CachedParseToken(token)
	require.NoError(t, err)

	c2, err := j.CachedParseToken(token)
	require.NoError(t, err)
	require.Equal(t, c1.TokenID, c2.TokenID)
}

func TestJwtRSACachedParseTokenWithParserOption(t *testing.T) {
	j := newRSA(t)

	token, err := j.GenerateToken(1, claims.WithIssuer("a"))
	require.NoError(t, err)

	_, err = j.CachedParseToken(token)
	require.NoError(t, err)

	_, err = j.CachedParseToken(token, jwtv5.WithIssuer("b"))
	require.ErrorIs(t, err, gojwt.ErrTokenInvalidIssuer)
}

// ---------- parallel verify ----------

func TestJwtRSAParallelVerify(t *testing.T) {
	j := newRSA(t)

	tokens := make([]string, 5)
	for i := range tokens {
		var err error
		tokens[i], err = j.GenerateToken(int64(i + 1))
		require.NoError(t, err)
	}

	results, errs := j.ParallelVerify(tokens)
	for i, c := range results {
		require.NoError(t, errs[i])
		require.Equal(t, int64(i+1), c.UserID)
	}
}

// ---------- blacklist ----------

func TestJwtRSABlacklistBlocksParseToken(t *testing.T) {
	blacklist := gojwt.NewBlacklist()
	j := newRSA(t, gojwt.WithBlacklistFunc(blacklist.In))

	token, err := j.GenerateToken(10)
	require.NoError(t, err)

	c, err := j.ParseToken(token)
	require.NoError(t, err)

	blacklist.Add(c.TokenID)
	_, err = j.ParseToken(token)
	require.ErrorIs(t, err, gojwt.ErrTokenBlacklisted)
}

// ---------- from keys ----------

func TestNewJwtRSAFromKeys(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	j, err := gojwt.NewJwtRSAFromKeys(privateKey, &privateKey.PublicKey)
	require.NoError(t, err)

	token, err := j.GenerateToken(77)
	require.NoError(t, err)

	c, err := j.ParseToken(token)
	require.NoError(t, err)
	require.Equal(t, int64(77), c.UserID)
}

func TestNewJwtRSAFromKeysRejectsNil(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	_, err = gojwt.NewJwtRSAFromKeys(nil, &privateKey.PublicKey)
	require.ErrorIs(t, err, gojwt.ErrInvalidKey)

	_, err = gojwt.NewJwtRSAFromKeys(privateKey, nil)
	require.ErrorIs(t, err, gojwt.ErrInvalidKey)
}

// ---------- validation ----------

func TestNewJwtRSARejectsHMACSigningMethod(t *testing.T) {
	priPath, pubPath := generateRSAKeyFiles(t, 2048)
	_, err := gojwt.NewJwtRSA(priPath, pubPath, gojwt.WithHMACSigningMethod(jwtv5.SigningMethodHS256))
	require.ErrorIs(t, err, gojwt.ErrInvalidConfig)
}

func TestNewJwtRSARejectsUnsupportedSigningMethod(t *testing.T) {
	priPath, pubPath := generateRSAKeyFiles(t, 2048)

	_, err := gojwt.NewJwtRSA(priPath, pubPath, gojwt.WithRSASigningMethod(nil))
	require.ErrorIs(t, err, gojwt.ErrInvalidConfig)

	_, err = gojwt.NewJwtRSA(priPath, pubPath, gojwt.WithRSASigningMethod(jwtv5.SigningMethodEdDSA))
	require.ErrorIs(t, err, gojwt.ErrInvalidConfig)
}

func TestNewJwtRSARejectsKeyTooSmallForMethod(t *testing.T) {
	priPath, pubPath := generateRSAKeyFiles(t, 2048)

	_, err := gojwt.NewJwtRSA(priPath, pubPath, gojwt.WithRSASigningMethod(jwtv5.SigningMethodRS384))
	require.ErrorIs(t, err, gojwt.ErrInvalidConfig)

	_, err = gojwt.NewJwtRSA(priPath, pubPath, gojwt.WithRSASigningMethod(jwtv5.SigningMethodPS512))
	require.ErrorIs(t, err, gojwt.ErrInvalidConfig)
}

func TestGenerateRSAKeysRejectsTooSmall(t *testing.T) {
	dir := t.TempDir()
	err := gojwt.GenerateRSAKeys(
		filepath.Join(dir, "pri.pem"),
		filepath.Join(dir, "pub.pem"),
		1024,
	)
	require.ErrorIs(t, err, gojwt.ErrInvalidConfig)
}

func TestNewJwtRSARejectsNonPositiveDurations(t *testing.T) {
	priPath, pubPath := generateRSAKeyFiles(t, 2048)

	_, err := gojwt.NewJwtRSA(priPath, pubPath, gojwt.WithTokenDuration(0))
	require.ErrorIs(t, err, gojwt.ErrInvalidConfig)

	_, err = gojwt.NewJwtRSA(priPath, pubPath, gojwt.WithRefreshDuration(-time.Minute))
	require.ErrorIs(t, err, gojwt.ErrInvalidConfig)
}

// ---------- nil receiver ----------

func TestJwtRSANilReceiverSafety(t *testing.T) {
	var j *gojwt.JwtRSA

	_, err := j.GenerateToken(1)
	require.ErrorIs(t, err, gojwt.ErrJWTNotInit)

	_, err = j.ParseToken("token")
	require.ErrorIs(t, err, gojwt.ErrJWTNotInit)

	_, err = j.RefreshToken("token")
	require.ErrorIs(t, err, gojwt.ErrJWTNotInit)

	_, err = j.CachedParseToken("token")
	require.ErrorIs(t, err, gojwt.ErrJWTNotInit)
}

// ---------- Tokener interface ----------

func TestJwtRSAImplementsTokener(t *testing.T) {
	var _ gojwt.Tokener = (*gojwt.JwtRSA)(nil)
}

// ---------- cross-algorithm rejection ----------

func TestJwtRSARejectsTokenSignedWithDifferentAlgorithm(t *testing.T) {
	j := newRSA(t)

	// HMAC token should be rejected
	hmacKey := []byte("12345678901234567890123456789012")
	hmacJ, err := gojwt.NewJwtHmac(hmacKey)
	require.NoError(t, err)

	hmacToken, err := hmacJ.GenerateToken(1)
	require.NoError(t, err)

	_, err = j.ParseToken(hmacToken)
	require.Error(t, err)
}
