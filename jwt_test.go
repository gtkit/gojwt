package gojwt_test

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/gtkit/gojwt"
	"github.com/gtkit/gojwt/claims"
	"github.com/stretchr/testify/require"
)

func TestJwtGenerate(t *testing.T) {
	key := "t8yij6okp2ldadg7feqoibjladj92gjh"
	j, _ := gojwt.NewJwtHmac([]byte(key))
	token, err := j.GenerateToken(10,
		claims.WithExpiresAt(24*time.Hour),
		claims.WithRoles("admin", "Finance"),
		claims.WithPrv("prv1"),
	)
	if err != nil {
		t.Error("generate token error:", err)
		return
	}

	tokenClaims, err := j.ParseToken(token)
	if err != nil {
		t.Error("parse token error:", err)
		return
	}
	t.Logf("claim: %+v", tokenClaims)
}

func TestJwtOptionsApplyToTokenDuration(t *testing.T) {
	key := []byte("t8yij6okp2ldadg7feqoibjladj92gjh")
	j, err := gojwt.NewJwtHmac(key, gojwt.WithTokenDuration(time.Minute))
	require.NoError(t, err)

	token, err := j.GenerateToken(10)
	require.NoError(t, err)

	tokenClaims, err := j.ParseToken(token)
	require.NoError(t, err)
	require.Less(t, tokenClaims.TTL(), time.Minute+5*time.Second)
}

func TestCachedParseTokenIsScopedToInstanceSecret(t *testing.T) {
	first, err := gojwt.NewJwtHmac([]byte("12345678901234567890123456789012"))
	require.NoError(t, err)
	second, err := gojwt.NewJwtHmac([]byte("abcdefghijklmnopqrstuvwxyz123456"))
	require.NoError(t, err)

	token, err := first.GenerateToken(42)
	require.NoError(t, err)

	_, err = first.CachedParseToken(token)
	require.NoError(t, err)

	_, err = second.CachedParseToken(token)
	require.Error(t, err)
}

func TestRefreshTokenKeepsAccessTokenTTL(t *testing.T) {
	key := []byte("t8yij6okp2ldadg7feqoibjladj92gjh")
	j, err := gojwt.NewJwtHmac(
		key,
		gojwt.WithTokenDuration(time.Second),
		gojwt.WithRefreshDuration(time.Minute),
	)
	require.NoError(t, err)

	token, err := j.GenerateToken(10)
	require.NoError(t, err)

	refreshed, err := j.RefreshToken(token)
	require.NoError(t, err)

	tokenClaims, err := j.ParseToken(refreshed)
	require.NoError(t, err)
	require.Less(t, tokenClaims.TTL(), 5*time.Second)
}

func TestJwtEd25519GenerateAndParse(t *testing.T) {
	dir := t.TempDir()
	priPath := filepath.Join(dir, "jwt_ed25519.pem")
	pubPath := filepath.Join(dir, "jwt_ed25519.pub.pem")

	require.NoError(t, gojwt.GenerateEd25519Keys(priPath, pubPath))

	j, err := gojwt.NewJwtEd25519(priPath, pubPath)
	require.NoError(t, err)

	token, err := j.GenerateToken(99)
	require.NoError(t, err)

	tokenClaims, err := j.ParseToken(token)
	require.NoError(t, err)
	require.Equal(t, int64(99), tokenClaims.UserID)
}

func TestNewJwtHmacRejectsShortSecret(t *testing.T) {
	_, err := gojwt.NewJwtHmac([]byte("short-secret"))
	require.Error(t, err)
	require.Contains(t, err.Error(), "at least 32 bytes")
}

func TestRefreshTokenReturnsErrRefreshTooEarly(t *testing.T) {
	key := []byte("t8yij6okp2ldadg7feqoibjladj92gjh")
	j, err := gojwt.NewJwtHmac(
		key,
		gojwt.WithTokenDuration(10*time.Minute),
		gojwt.WithRefreshDuration(time.Hour),
	)
	require.NoError(t, err)

	token, err := j.GenerateToken(10)
	require.NoError(t, err)

	_, err = j.RefreshToken(token)
	require.ErrorIs(t, err, gojwt.ErrRefreshTooEarly)
}

func TestGenerateSecureKeyIsDeprecated(t *testing.T) {
	err := gojwt.GenerateSecureKey()
	require.EqualError(t, err, "GenerateSecureKey is deprecated; use GenerateSecureKeyString instead")
}

func TestBlacklistConcurrentAccess(t *testing.T) {
	blacklist := gojwt.NewBlacklist()

	var wg sync.WaitGroup
	for i := range 64 {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()

			tokenID := fmt.Sprintf("token-%d", i)
			blacklist.Add(tokenID)
			_ = blacklist.In(tokenID)
			blacklist.Remove(tokenID)
		}(i)
	}
	wg.Wait()
}

func TestOptionAliasesRemainUsable(t *testing.T) {
	var option gojwt.Options = gojwt.WithTokenDuration(time.Minute)
	require.NotNil(t, option)

	var claimOption claims.Options = claims.WithPrv("admin")
	require.NotNil(t, claimOption)
}

func TestClaimsErrorIsUnified(t *testing.T) {
	c := claims.Claims{}
	err := c.VerifyRole("admin")
	require.ErrorIs(t, err, gojwt.ErrTokenRole)

	err = c.VerifyPrv("service")
	require.ErrorIs(t, err, gojwt.ErrTokenPrv)
}

func TestClaimsOmitZeroFieldsInJSON(t *testing.T) {
	tokenClaims := claims.Claims{UserID: 1, TokenID: "token"}
	payload, err := json.Marshal(tokenClaims)
	require.NoError(t, err)
	require.NotContains(t, string(payload), `"prv"`)
	require.NotContains(t, string(payload), `"roles"`)
}

func TestTokenerImplementations(t *testing.T) {
	var _ gojwt.Tokener = (*gojwt.JwtHmac)(nil)
	var _ gojwt.Tokener = (*gojwt.JwtEd25519)(nil)
}
