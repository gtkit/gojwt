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

func TestGenerateSecureKeyDeprecated(t *testing.T) {
	key, err := gojwt.GenerateSecureKey()
	require.NoError(t, err)
	require.NotEmpty(t, key)
}

func TestBlacklistConcurrentAccess(t *testing.T) {
	blacklist := gojwt.NewBlacklist()

	var wg sync.WaitGroup
	for i := range 64 {
		wg.Go(func() {
			tokenID := fmt.Sprintf("token-%d", i)
			blacklist.Add(tokenID)
			_ = blacklist.In(tokenID)
			blacklist.Remove(tokenID)
		})
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

// ======================== 黑名单注入测试 ========================

func TestBlacklistFuncBlocksParseToken(t *testing.T) {
	blacklist := gojwt.NewBlacklist()
	key := []byte("t8yij6okp2ldadg7feqoibjladj92gjh")

	j, err := gojwt.NewJwtHmac(key, gojwt.WithBlacklistFunc(blacklist.In))
	require.NoError(t, err)

	token, err := j.GenerateToken(10)
	require.NoError(t, err)

	// 正常解析
	tokenClaims, err := j.ParseToken(token)
	require.NoError(t, err)
	require.Equal(t, int64(10), tokenClaims.UserID)

	// 加入黑名单后解析失败
	blacklist.Add(tokenClaims.TokenID)
	_, err = j.ParseToken(token)
	require.ErrorIs(t, err, gojwt.ErrTokenBlacklisted)

	// 从黑名单移除后恢复正常
	blacklist.Remove(tokenClaims.TokenID)
	_, err = j.ParseToken(token)
	require.NoError(t, err)
}

func TestBlacklistFuncBlocksCachedParseToken(t *testing.T) {
	blacklist := gojwt.NewBlacklist()
	key := []byte("t8yij6okp2ldadg7feqoibjladj92gjh")

	j, err := gojwt.NewJwtHmac(key, gojwt.WithBlacklistFunc(blacklist.In))
	require.NoError(t, err)

	token, err := j.GenerateToken(20)
	require.NoError(t, err)

	// 首次解析（写入缓存）
	tokenClaims, err := j.CachedParseToken(token)
	require.NoError(t, err)

	// 加入黑名单后，缓存命中但仍被拦截
	blacklist.Add(tokenClaims.TokenID)
	_, err = j.CachedParseToken(token)
	require.ErrorIs(t, err, gojwt.ErrTokenBlacklisted)
}

func TestBlacklistFuncWithCustomCallback(t *testing.T) {
	// 模拟 Redis EXISTS 风格的外部检查函数
	revokedTokens := map[string]struct{}{
		"revoked-token-001": {},
	}
	isRevoked := func(tokenID string) bool {
		_, ok := revokedTokens[tokenID]
		return ok
	}

	key := []byte("t8yij6okp2ldadg7feqoibjladj92gjh")
	j, err := gojwt.NewJwtHmac(key, gojwt.WithBlacklistFunc(isRevoked))
	require.NoError(t, err)

	token, err := j.GenerateToken(30)
	require.NoError(t, err)

	// 正常 token 不在黑名单中，解析成功
	_, err = j.ParseToken(token)
	require.NoError(t, err)
}

func TestNoBlacklistFuncSkipsCheck(t *testing.T) {
	key := []byte("t8yij6okp2ldadg7feqoibjladj92gjh")

	// 不注入 WithBlacklistFunc，黑名单检查被跳过
	j, err := gojwt.NewJwtHmac(key)
	require.NoError(t, err)

	token, err := j.GenerateToken(40)
	require.NoError(t, err)

	_, err = j.ParseToken(token)
	require.NoError(t, err)
}

func TestBlacklistFuncWithEd25519(t *testing.T) {
	blacklist := gojwt.NewBlacklist()
	dir := t.TempDir()
	priPath := filepath.Join(dir, "jwt_ed25519.pem")
	pubPath := filepath.Join(dir, "jwt_ed25519.pub.pem")

	require.NoError(t, gojwt.GenerateEd25519Keys(priPath, pubPath))

	j, err := gojwt.NewJwtEd25519(priPath, pubPath, gojwt.WithBlacklistFunc(blacklist.In))
	require.NoError(t, err)

	token, err := j.GenerateToken(50)
	require.NoError(t, err)

	tokenClaims, err := j.ParseToken(token)
	require.NoError(t, err)

	blacklist.Add(tokenClaims.TokenID)
	_, err = j.ParseToken(token)
	require.ErrorIs(t, err, gojwt.ErrTokenBlacklisted)
}

func TestBlacklistFuncWithEd25519CachedParse(t *testing.T) {
	blacklist := gojwt.NewBlacklist()
	dir := t.TempDir()
	priPath := filepath.Join(dir, "jwt_ed25519.pem")
	pubPath := filepath.Join(dir, "jwt_ed25519.pub.pem")

	require.NoError(t, gojwt.GenerateEd25519Keys(priPath, pubPath))

	j, err := gojwt.NewJwtEd25519(priPath, pubPath, gojwt.WithBlacklistFunc(blacklist.In))
	require.NoError(t, err)

	token, err := j.GenerateToken(60)
	require.NoError(t, err)

	// 首次缓存解析
	tokenClaims, err := j.CachedParseToken(token)
	require.NoError(t, err)

	// 加入黑名单后缓存命中仍被拦截
	blacklist.Add(tokenClaims.TokenID)
	_, err = j.CachedParseToken(token)
	require.ErrorIs(t, err, gojwt.ErrTokenBlacklisted)
}

func TestRefreshTokenAlsoChecksBlacklist(t *testing.T) {
	blacklist := gojwt.NewBlacklist()
	key := []byte("t8yij6okp2ldadg7feqoibjladj92gjh")

	j, err := gojwt.NewJwtHmac(
		key,
		gojwt.WithTokenDuration(time.Second),
		gojwt.WithRefreshDuration(time.Minute),
		gojwt.WithBlacklistFunc(blacklist.In),
	)
	require.NoError(t, err)

	token, err := j.GenerateToken(70)
	require.NoError(t, err)

	// 先正常解析拿到 tokenID
	tokenClaims, err := j.ParseToken(token)
	require.NoError(t, err)

	// 加入黑名单后刷新也应失败（因为 RefreshToken 内部调用了 ParseToken）
	blacklist.Add(tokenClaims.TokenID)
	_, err = j.RefreshToken(token)
	require.ErrorIs(t, err, gojwt.ErrTokenBlacklisted)
}
