package gojwt_test

import (
	"bytes"
	"crypto"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	jwtv5 "github.com/golang-jwt/jwt/v5"
	"github.com/gtkit/gojwt"
	"github.com/gtkit/gojwt/claims"
	"github.com/stretchr/testify/require"
)

func TestJwtGenerate(t *testing.T) {
	key := "t8yij6okp2ldadg7feqoibjladj92gjh"
	j, _ := gojwt.NewJwtHmac([]byte(key))
	token, err := j.GenerateToken(10,
		claims.WithExpiresIn(24*time.Hour),
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

func TestParseTokenAllowsSmallClockSkewByDefault(t *testing.T) {
	key := []byte("12345678901234567890123456789012")
	j, err := gojwt.NewJwtHmac(key)
	require.NoError(t, err)

	now := time.Now()
	token, err := jwtv5.NewWithClaims(jwtv5.SigningMethodHS256, claims.Claims{
		UserID:  10,
		TokenID: "clock-skew-token",
		RegisteredClaims: jwtv5.RegisteredClaims{
			ExpiresAt: jwtv5.NewNumericDate(now.Add(time.Hour)),
			IssuedAt:  jwtv5.NewNumericDate(now),
			NotBefore: jwtv5.NewNumericDate(now.Add(3 * time.Second)),
			ID:        "clock-skew-token",
		},
	}).SignedString(key)
	require.NoError(t, err)

	_, err = j.ParseToken(token)
	require.NoError(t, err)
}

func TestParseTokenWithZeroLeewayRejectsSmallClockSkew(t *testing.T) {
	key := []byte("12345678901234567890123456789012")
	j, err := gojwt.NewJwtHmac(key, gojwt.WithParseLeeway(0))
	require.NoError(t, err)

	now := time.Now()
	token, err := jwtv5.NewWithClaims(jwtv5.SigningMethodHS256, claims.Claims{
		UserID:  10,
		TokenID: "strict-clock-skew-token",
		RegisteredClaims: jwtv5.RegisteredClaims{
			ExpiresAt: jwtv5.NewNumericDate(now.Add(time.Hour)),
			IssuedAt:  jwtv5.NewNumericDate(now),
			NotBefore: jwtv5.NewNumericDate(now.Add(3 * time.Second)),
			ID:        "strict-clock-skew-token",
		},
	}).SignedString(key)
	require.NoError(t, err)

	_, err = j.ParseToken(token)
	require.ErrorIs(t, err, gojwt.ErrTokenNotValidYet)
}

func TestParseTokenAllowsRecentlyExpiredTokenWithinDefaultLeeway(t *testing.T) {
	key := []byte("12345678901234567890123456789012")
	j, err := gojwt.NewJwtHmac(key)
	require.NoError(t, err)

	now := time.Now()
	token, err := jwtv5.NewWithClaims(jwtv5.SigningMethodHS256, claims.Claims{
		UserID:  10,
		TokenID: "recently-expired-token",
		RegisteredClaims: jwtv5.RegisteredClaims{
			ExpiresAt: jwtv5.NewNumericDate(now.Add(-3 * time.Second)),
			IssuedAt:  jwtv5.NewNumericDate(now.Add(-time.Minute)),
			NotBefore: jwtv5.NewNumericDate(now.Add(-time.Minute)),
			ID:        "recently-expired-token",
		},
	}).SignedString(key)
	require.NoError(t, err)

	_, err = j.ParseToken(token)
	require.NoError(t, err)
}

func TestJwtHmacUsesHS256ByDefault(t *testing.T) {
	key := []byte("12345678901234567890123456789012")
	j, err := gojwt.NewJwtHmac(key)
	require.NoError(t, err)

	token, err := j.GenerateToken(10)
	require.NoError(t, err)

	parsed, _, err := jwtv5.NewParser().ParseUnverified(token, &claims.Claims{})
	require.NoError(t, err)
	require.Equal(t, jwtv5.SigningMethodHS256.Alg(), parsed.Method.Alg())
}

func TestJwtHmacCanUseConfiguredSigningMethod(t *testing.T) {
	testCases := []struct {
		name   string
		keyLen int
		method *jwtv5.SigningMethodHMAC
	}{
		{name: "hs384", keyLen: 48, method: jwtv5.SigningMethodHS384},
		{name: "hs512", keyLen: 64, method: jwtv5.SigningMethodHS512},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			key := bytes.Repeat([]byte("k"), tc.keyLen)
			j, err := gojwt.NewJwtHmac(key, gojwt.WithHMACSigningMethod(tc.method))
			require.NoError(t, err)

			token, err := j.GenerateToken(10)
			require.NoError(t, err)

			parsed, _, err := jwtv5.NewParser().ParseUnverified(token, &claims.Claims{})
			require.NoError(t, err)
			require.Equal(t, tc.method.Alg(), parsed.Method.Alg())

			tokenClaims, err := j.ParseToken(token)
			require.NoError(t, err)
			require.Equal(t, int64(10), tokenClaims.UserID)
		})
	}
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

func TestParallelVerifyUsesBoundedConcurrency(t *testing.T) {
	const workerLimit = 2

	previous := runtime.GOMAXPROCS(workerLimit)
	defer runtime.GOMAXPROCS(previous)

	var active atomic.Int64
	var maxActive atomic.Int64
	release := make(chan struct{})

	j, err := gojwt.NewJwtHmac(
		[]byte("12345678901234567890123456789012"),
		gojwt.WithBlacklistCheckFunc(func(tokenID string) (bool, error) {
			current := active.Add(1)
			for {
				max := maxActive.Load()
				if current <= max || maxActive.CompareAndSwap(max, current) {
					break
				}
			}
			<-release
			active.Add(-1)
			return false, nil
		}),
	)
	require.NoError(t, err)

	tokens := make([]string, 8)
	for i := range tokens {
		tokens[i], err = j.GenerateToken(int64(i + 1))
		require.NoError(t, err)
	}

	done := make(chan struct{})
	go func() {
		j.ParallelVerify(tokens)
		close(done)
	}()

	require.Eventually(t, func() bool {
		return maxActive.Load() >= workerLimit
	}, time.Second, 10*time.Millisecond)

	time.Sleep(100 * time.Millisecond)
	close(release)
	<-done

	require.LessOrEqual(t, maxActive.Load(), int64(workerLimit))
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

func TestRefreshTokenRotatesTokenIDAndJwtID(t *testing.T) {
	key := []byte("12345678901234567890123456789012")
	j, err := gojwt.NewJwtHmac(
		key,
		gojwt.WithTokenDuration(2*time.Second),
		gojwt.WithRefreshDuration(time.Minute),
	)
	require.NoError(t, err)

	token, err := j.GenerateToken(10)
	require.NoError(t, err)

	originalClaims, err := j.ParseToken(token)
	require.NoError(t, err)

	time.Sleep(1100 * time.Millisecond)

	refreshed, err := j.RefreshToken(token)
	require.NoError(t, err)

	refreshedClaims, err := j.ParseToken(refreshed)
	require.NoError(t, err)
	require.NotEqual(t, originalClaims.TokenID, refreshedClaims.TokenID)
	require.Equal(t, refreshedClaims.TokenID, refreshedClaims.ID)
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

func TestJwtEd25519RefreshTokenRotatesTokenID(t *testing.T) {
	dir := t.TempDir()
	priPath := filepath.Join(dir, "jwt_ed25519.pem")
	pubPath := filepath.Join(dir, "jwt_ed25519.pub.pem")
	require.NoError(t, gojwt.GenerateEd25519Keys(priPath, pubPath))

	j, err := gojwt.NewJwtEd25519(
		priPath,
		pubPath,
		gojwt.WithTokenDuration(2*time.Second),
		gojwt.WithRefreshDuration(time.Minute),
	)
	require.NoError(t, err)

	token, err := j.GenerateToken(99)
	require.NoError(t, err)

	originalClaims, err := j.ParseToken(token)
	require.NoError(t, err)

	time.Sleep(1100 * time.Millisecond)

	refreshed, err := j.RefreshToken(token)
	require.NoError(t, err)

	refreshedClaims, err := j.ParseToken(refreshed)
	require.NoError(t, err)
	require.NotEqual(t, originalClaims.TokenID, refreshedClaims.TokenID)
	require.Equal(t, refreshedClaims.TokenID, refreshedClaims.ID)
}

func TestNewJwtEd25519RejectsNonPositiveDurations(t *testing.T) {
	dir := t.TempDir()
	priPath := filepath.Join(dir, "jwt_ed25519.pem")
	pubPath := filepath.Join(dir, "jwt_ed25519.pub.pem")
	require.NoError(t, gojwt.GenerateEd25519Keys(priPath, pubPath))

	_, err := gojwt.NewJwtEd25519(priPath, pubPath, gojwt.WithTokenDuration(0))
	require.ErrorIs(t, err, gojwt.ErrInvalidConfig)

	_, err = gojwt.NewJwtEd25519(priPath, pubPath, gojwt.WithRefreshDuration(-time.Minute))
	require.ErrorIs(t, err, gojwt.ErrInvalidConfig)
}

func TestNewJwtEd25519RejectsNegativeParseLeeway(t *testing.T) {
	dir := t.TempDir()
	priPath := filepath.Join(dir, "jwt_ed25519.pem")
	pubPath := filepath.Join(dir, "jwt_ed25519.pub.pem")
	require.NoError(t, gojwt.GenerateEd25519Keys(priPath, pubPath))

	_, err := gojwt.NewJwtEd25519(priPath, pubPath, gojwt.WithParseLeeway(-time.Second))
	require.ErrorIs(t, err, gojwt.ErrInvalidConfig)
}

func TestNewJwtEd25519RejectsHMACSigningMethodOption(t *testing.T) {
	dir := t.TempDir()
	priPath := filepath.Join(dir, "jwt_ed25519.pem")
	pubPath := filepath.Join(dir, "jwt_ed25519.pub.pem")
	require.NoError(t, gojwt.GenerateEd25519Keys(priPath, pubPath))

	_, err := gojwt.NewJwtEd25519(priPath, pubPath, gojwt.WithHMACSigningMethod(jwtv5.SigningMethodHS512))
	require.ErrorIs(t, err, gojwt.ErrInvalidConfig)
}

func TestNewJwtHmacRejectsShortSecret(t *testing.T) {
	_, err := gojwt.NewJwtHmac([]byte("short-secret"))
	require.Error(t, err)
	require.Contains(t, err.Error(), "at least 32 bytes")
}

func TestNewJwtHmacRejectsUnsupportedHMACSigningMethod(t *testing.T) {
	key := bytes.Repeat([]byte("k"), 64)

	_, err := gojwt.NewJwtHmac(key, gojwt.WithHMACSigningMethod(nil))
	require.ErrorIs(t, err, gojwt.ErrInvalidConfig)

	_, err = gojwt.NewJwtHmac(key, gojwt.WithHMACSigningMethod(&jwtv5.SigningMethodHMAC{
		Name: "HS999",
		Hash: crypto.SHA256,
	}))
	require.ErrorIs(t, err, gojwt.ErrInvalidConfig)
}

func TestNewJwtHmacRejectsSecretTooShortForConfiguredHMACMethod(t *testing.T) {
	key := bytes.Repeat([]byte("k"), 32)

	_, err := gojwt.NewJwtHmac(key, gojwt.WithHMACSigningMethod(jwtv5.SigningMethodHS384))
	require.ErrorIs(t, err, gojwt.ErrInvalidConfig)

	_, err = gojwt.NewJwtHmac(key, gojwt.WithHMACSigningMethod(jwtv5.SigningMethodHS512))
	require.ErrorIs(t, err, gojwt.ErrInvalidConfig)
}

func TestNewJwtHmacRejectsNonPositiveDurations(t *testing.T) {
	key := []byte("12345678901234567890123456789012")

	_, err := gojwt.NewJwtHmac(key, gojwt.WithTokenDuration(0))
	require.ErrorIs(t, err, gojwt.ErrInvalidConfig)

	_, err = gojwt.NewJwtHmac(key, gojwt.WithRefreshDuration(-time.Minute))
	require.ErrorIs(t, err, gojwt.ErrInvalidConfig)
}

func TestNewJwtHmacRejectsNegativeParseLeeway(t *testing.T) {
	key := []byte("12345678901234567890123456789012")

	_, err := gojwt.NewJwtHmac(key, gojwt.WithParseLeeway(-time.Second))
	require.ErrorIs(t, err, gojwt.ErrInvalidConfig)
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

func TestBlacklistAddTokenExpiresWithClaims(t *testing.T) {
	blacklist := gojwt.NewBlacklist()

	err := blacklist.AddToken(&claims.Claims{
		TokenID: "exp-aware-token",
		RegisteredClaims: jwtv5.RegisteredClaims{
			ExpiresAt: jwtv5.NewNumericDate(time.Now().Add(1500 * time.Millisecond)),
		},
	})
	require.NoError(t, err)
	require.True(t, blacklist.In("exp-aware-token"))

	require.Eventually(t, func() bool {
		return !blacklist.In("exp-aware-token")
	}, 3*time.Second, 20*time.Millisecond)
}

func TestBlacklistAddWithExpirationExpires(t *testing.T) {
	blacklist := gojwt.NewBlacklist()

	blacklist.AddWithExpiration("expiring-token", time.Now().Add(50*time.Millisecond))
	require.True(t, blacklist.In("expiring-token"))

	require.Eventually(t, func() bool {
		return !blacklist.In("expiring-token")
	}, time.Second, 10*time.Millisecond)
}

func TestBlacklistAddRemainsPermanent(t *testing.T) {
	blacklist := gojwt.NewBlacklist()

	blacklist.Add("permanent-token")
	time.Sleep(100 * time.Millisecond)

	require.True(t, blacklist.In("permanent-token"))
}

func TestBlacklistAddTokenRejectsInvalidClaims(t *testing.T) {
	blacklist := gojwt.NewBlacklist()

	require.ErrorIs(t, blacklist.AddToken(nil), gojwt.ErrTokenInvalidClaims)
	require.ErrorIs(t, blacklist.AddToken(&claims.Claims{}), gojwt.ErrTokenInvalidClaims)
	require.ErrorIs(t, blacklist.AddToken(&claims.Claims{TokenID: "missing-exp"}), gojwt.ErrTokenInvalidClaims)
}

func TestOptionAliasesRemainUsable(t *testing.T) {
	var option gojwt.Options = gojwt.WithTokenDuration(time.Minute)
	require.NotNil(t, option)

	var claimOption claims.Options = claims.WithPrv("admin") //nolint:staticcheck // verify deprecated alias remains usable
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

func TestCachedParseTokenAppliesParserOptionsOnEveryCall(t *testing.T) {
	key := []byte("12345678901234567890123456789012")
	j, err := gojwt.NewJwtHmac(key)
	require.NoError(t, err)

	token, err := j.GenerateToken(10, claims.WithIssuer("issuer-a"))
	require.NoError(t, err)

	_, err = j.CachedParseToken(token)
	require.NoError(t, err)

	_, err = j.CachedParseToken(token, jwtv5.WithIssuer("issuer-b"))
	require.ErrorIs(t, err, gojwt.ErrTokenInvalidIssuer)
}

func TestCachedParseTokenDoesNotCacheClaimsValidationBypass(t *testing.T) {
	key := []byte("12345678901234567890123456789012")
	j, err := gojwt.NewJwtHmac(key)
	require.NoError(t, err)

	now := time.Now()
	token, err := jwtv5.NewWithClaims(jwtv5.SigningMethodHS256, claims.Claims{
		UserID:  10,
		TokenID: "nbf-token",
		RegisteredClaims: jwtv5.RegisteredClaims{
			ExpiresAt: jwtv5.NewNumericDate(now.Add(time.Hour)),
			IssuedAt:  jwtv5.NewNumericDate(now),
			NotBefore: jwtv5.NewNumericDate(now.Add(time.Hour)),
			ID:        "nbf-token",
		},
	}).SignedString(key)
	require.NoError(t, err)

	_, err = j.CachedParseToken(token, jwtv5.WithoutClaimsValidation())
	require.NoError(t, err)

	_, err = j.CachedParseToken(token)
	require.ErrorIs(t, err, gojwt.ErrTokenNotValidYet)
}

func TestParseTokenRejectsNonHS256HMACTokens(t *testing.T) {
	key := []byte("12345678901234567890123456789012")
	j, err := gojwt.NewJwtHmac(key)
	require.NoError(t, err)

	now := time.Now()
	token, err := jwtv5.NewWithClaims(jwtv5.SigningMethodHS512, claims.Claims{
		UserID:  10,
		TokenID: "hs512-token",
		RegisteredClaims: jwtv5.RegisteredClaims{
			ExpiresAt: jwtv5.NewNumericDate(now.Add(time.Hour)),
			IssuedAt:  jwtv5.NewNumericDate(now),
			NotBefore: jwtv5.NewNumericDate(now),
			ID:        "hs512-token",
		},
	}).SignedString(key)
	require.NoError(t, err)

	_, err = j.ParseToken(token)
	require.ErrorIs(t, err, gojwt.ErrTokenSignatureInvalid)
}

func TestParseTokenNormalizesInvalidIssuerError(t *testing.T) {
	key := []byte("12345678901234567890123456789012")
	j, err := gojwt.NewJwtHmac(key)
	require.NoError(t, err)

	token, err := j.GenerateToken(10, claims.WithIssuer("issuer-a"))
	require.NoError(t, err)

	_, err = j.ParseToken(token, jwtv5.WithIssuer("issuer-b"))
	require.ErrorIs(t, err, gojwt.ErrTokenInvalidIssuer)
}

func TestCachedParseTokenPropagatesBlacklistCheckErrorOnCacheHit(t *testing.T) {
	key := []byte("12345678901234567890123456789012")
	expected := errors.New("blacklist backend unavailable")
	calls := 0

	j, err := gojwt.NewJwtHmac(key, gojwt.WithBlacklistCheckFunc(func(tokenID string) (bool, error) {
		calls++
		if calls == 1 {
			return false, nil
		}
		return false, expected
	}))
	require.NoError(t, err)

	token, err := j.GenerateToken(10)
	require.NoError(t, err)

	_, err = j.CachedParseToken(token)
	require.NoError(t, err)

	_, err = j.CachedParseToken(token)
	require.ErrorIs(t, err, expected)
}

func TestGenerateTokenKeepsTokenIDAndJwtIDAligned(t *testing.T) {
	key := []byte("12345678901234567890123456789012")
	j, err := gojwt.NewJwtHmac(
		key,
		gojwt.WithTokenDuration(time.Second),
		gojwt.WithRefreshDuration(time.Minute),
	)
	require.NoError(t, err)

	token, err := j.GenerateToken(10, claims.WithJwtID("custom-jti"))
	require.NoError(t, err)

	tokenClaims, err := j.ParseToken(token)
	require.NoError(t, err)
	require.Equal(t, "custom-jti", tokenClaims.TokenID)
	require.Equal(t, tokenClaims.TokenID, tokenClaims.ID)

	refreshed, err := j.RefreshToken(token)
	require.NoError(t, err)

	refreshedClaims, err := j.ParseToken(refreshed)
	require.NoError(t, err)
	require.NotEqual(t, "custom-jti", refreshedClaims.TokenID)
	require.Equal(t, refreshedClaims.TokenID, refreshedClaims.ID)
}

func TestRefreshTokenUpdatesIatAndNbf(t *testing.T) {
	key := []byte("12345678901234567890123456789012")
	j, err := gojwt.NewJwtHmac(
		key,
		gojwt.WithTokenDuration(2*time.Second),
		gojwt.WithRefreshDuration(time.Minute),
	)
	require.NoError(t, err)

	token, err := j.GenerateToken(10)
	require.NoError(t, err)

	originalClaims, err := j.ParseToken(token)
	require.NoError(t, err)

	time.Sleep(1100 * time.Millisecond)

	refreshed, err := j.RefreshToken(token)
	require.NoError(t, err)

	refreshedClaims, err := j.ParseToken(refreshed)
	require.NoError(t, err)

	require.True(t, refreshedClaims.IssuedAt.Time.After(originalClaims.IssuedAt.Time),
		"iat should be updated after refresh")
	require.True(t, refreshedClaims.NotBefore.Time.After(originalClaims.NotBefore.Time),
		"nbf should be updated after refresh")
}

func TestJwtEd25519RefreshTokenUpdatesIatAndNbf(t *testing.T) {
	dir := t.TempDir()
	priPath := filepath.Join(dir, "jwt_ed25519.pem")
	pubPath := filepath.Join(dir, "jwt_ed25519.pub.pem")
	require.NoError(t, gojwt.GenerateEd25519Keys(priPath, pubPath))

	j, err := gojwt.NewJwtEd25519(
		priPath,
		pubPath,
		gojwt.WithTokenDuration(2*time.Second),
		gojwt.WithRefreshDuration(time.Minute),
	)
	require.NoError(t, err)

	token, err := j.GenerateToken(99)
	require.NoError(t, err)

	originalClaims, err := j.ParseToken(token)
	require.NoError(t, err)

	time.Sleep(1100 * time.Millisecond)

	refreshed, err := j.RefreshToken(token)
	require.NoError(t, err)

	refreshedClaims, err := j.ParseToken(refreshed)
	require.NoError(t, err)

	require.NotEqual(t, originalClaims.TokenID, refreshedClaims.TokenID)
	require.True(t, refreshedClaims.IssuedAt.Time.After(originalClaims.IssuedAt.Time))
	require.True(t, refreshedClaims.NotBefore.Time.After(originalClaims.NotBefore.Time))
}

func TestJwtEd25519ParallelVerify(t *testing.T) {
	dir := t.TempDir()
	priPath := filepath.Join(dir, "jwt_ed25519.pem")
	pubPath := filepath.Join(dir, "jwt_ed25519.pub.pem")
	require.NoError(t, gojwt.GenerateEd25519Keys(priPath, pubPath))

	j, err := gojwt.NewJwtEd25519(priPath, pubPath)
	require.NoError(t, err)

	tokens := make([]string, 5)
	for i := range tokens {
		tokens[i], err = j.GenerateToken(int64(i + 1))
		require.NoError(t, err)
	}

	results, errs := j.ParallelVerify(tokens)
	for i, c := range results {
		require.NoError(t, errs[i])
		require.Equal(t, int64(i+1), c.UserID)
	}
}

func TestJwtEd25519ParallelVerifyWithInvalidToken(t *testing.T) {
	dir := t.TempDir()
	priPath := filepath.Join(dir, "jwt_ed25519.pem")
	pubPath := filepath.Join(dir, "jwt_ed25519.pub.pem")
	require.NoError(t, gojwt.GenerateEd25519Keys(priPath, pubPath))

	j, err := gojwt.NewJwtEd25519(priPath, pubPath)
	require.NoError(t, err)

	validToken, err := j.GenerateToken(1)
	require.NoError(t, err)

	tokens := []string{validToken, "invalid-token", validToken}
	results, errs := j.ParallelVerify(tokens)

	require.NoError(t, errs[0])
	require.Equal(t, int64(1), results[0].UserID)

	require.Error(t, errs[1])
	require.Nil(t, results[1])

	require.NoError(t, errs[2])
	require.Equal(t, int64(1), results[2].UserID)
}

func TestParallelVerifyEmptyInput(t *testing.T) {
	key := []byte("12345678901234567890123456789012")
	j, err := gojwt.NewJwtHmac(key)
	require.NoError(t, err)

	results, errs := j.ParallelVerify(nil)
	require.Empty(t, results)
	require.Empty(t, errs)
}

func TestNormalizeParseErrorCoversAllJwtErrors(t *testing.T) {
	key := []byte("12345678901234567890123456789012")
	j, err := gojwt.NewJwtHmac(key)
	require.NoError(t, err)

	now := time.Now()

	// ErrTokenExpired
	expiredToken, err := jwtv5.NewWithClaims(jwtv5.SigningMethodHS256, claims.Claims{
		UserID: 1, TokenID: "t1",
		RegisteredClaims: jwtv5.RegisteredClaims{
			ExpiresAt: jwtv5.NewNumericDate(now.Add(-time.Hour)),
			IssuedAt:  jwtv5.NewNumericDate(now.Add(-2 * time.Hour)),
			NotBefore: jwtv5.NewNumericDate(now.Add(-2 * time.Hour)),
			ID:        "t1",
		},
	}).SignedString(key)
	require.NoError(t, err)
	_, err = j.ParseToken(expiredToken, jwtv5.WithLeeway(0))
	require.ErrorIs(t, err, gojwt.ErrTokenExpired)

	// ErrTokenNotValidYet
	nbfToken, err := jwtv5.NewWithClaims(jwtv5.SigningMethodHS256, claims.Claims{
		UserID: 1, TokenID: "t2",
		RegisteredClaims: jwtv5.RegisteredClaims{
			ExpiresAt: jwtv5.NewNumericDate(now.Add(time.Hour)),
			IssuedAt:  jwtv5.NewNumericDate(now),
			NotBefore: jwtv5.NewNumericDate(now.Add(time.Hour)),
			ID:        "t2",
		},
	}).SignedString(key)
	require.NoError(t, err)
	_, err = j.ParseToken(nbfToken, jwtv5.WithLeeway(0))
	require.ErrorIs(t, err, gojwt.ErrTokenNotValidYet)

	// ErrTokenMalformed
	_, err = j.ParseToken("not.a.jwt")
	require.ErrorIs(t, err, gojwt.ErrTokenMalformed)

	// ErrTokenSignatureInvalid
	otherKey := []byte("other-key-with-at-least-32-bytes!")
	forgedToken, err := jwtv5.NewWithClaims(jwtv5.SigningMethodHS256, claims.Claims{
		UserID: 1, TokenID: "t3",
		RegisteredClaims: jwtv5.RegisteredClaims{
			ExpiresAt: jwtv5.NewNumericDate(now.Add(time.Hour)),
			IssuedAt:  jwtv5.NewNumericDate(now),
			NotBefore: jwtv5.NewNumericDate(now),
			ID:        "t3",
		},
	}).SignedString(otherKey)
	require.NoError(t, err)
	_, err = j.ParseToken(forgedToken)
	require.ErrorIs(t, err, gojwt.ErrTokenSignatureInvalid)

	// ErrTokenInvalidIssuer (already tested but included for completeness)
	issToken, err := j.GenerateToken(1, claims.WithIssuer("a"))
	require.NoError(t, err)
	_, err = j.ParseToken(issToken, jwtv5.WithIssuer("b"))
	require.ErrorIs(t, err, gojwt.ErrTokenInvalidIssuer)

	// ErrTokenInvalidAudience
	audToken, err := j.GenerateToken(1, claims.WithAudience("a"))
	require.NoError(t, err)
	_, err = j.ParseToken(audToken, jwtv5.WithAudience("b"))
	require.ErrorIs(t, err, gojwt.ErrTokenInvalidAudience)

	// ErrTokenInvalidSubject
	subToken, err := j.GenerateToken(1, claims.WithSubject("user:1"))
	require.NoError(t, err)
	_, err = j.ParseToken(subToken, jwtv5.WithSubject("user:2"))
	require.ErrorIs(t, err, gojwt.ErrTokenInvalidSubject)

	// Empty token
	_, err = j.ParseToken("")
	require.ErrorIs(t, err, gojwt.ErrTokenMalformed)
}

func TestBlacklistManagerInterfaceCompliance(t *testing.T) {
	var _ gojwt.Blacklister = (*gojwt.Blacklist)(nil)
	var _ gojwt.BlacklistManager = (*gojwt.Blacklist)(nil)
}

func TestBlacklistNilReceiverSafety(t *testing.T) {
	var b *gojwt.Blacklist

	require.False(t, b.In("token"))
	b.Add("token")
	b.AddWithExpiration("token", time.Now().Add(time.Hour))
	b.Remove("token")
	require.Equal(t, 0, b.SweepExpired())
	b.Close()
}

func TestJwtHmacNilReceiverSafety(t *testing.T) {
	var j *gojwt.JwtHmac

	_, err := j.GenerateToken(1)
	require.ErrorIs(t, err, gojwt.ErrJWTNotInit)

	_, err = j.ParseToken("token")
	require.ErrorIs(t, err, gojwt.ErrJWTNotInit)

	_, err = j.RefreshToken("token")
	require.ErrorIs(t, err, gojwt.ErrJWTNotInit)

	_, err = j.CachedParseToken("token")
	require.ErrorIs(t, err, gojwt.ErrJWTNotInit)
}

func TestJwtEd25519NilReceiverSafety(t *testing.T) {
	var j *gojwt.JwtEd25519

	_, err := j.GenerateToken(1)
	require.ErrorIs(t, err, gojwt.ErrJWTNotInit)

	_, err = j.ParseToken("token")
	require.ErrorIs(t, err, gojwt.ErrJWTNotInit)

	_, err = j.RefreshToken("token")
	require.ErrorIs(t, err, gojwt.ErrJWTNotInit)

	_, err = j.CachedParseToken("token")
	require.ErrorIs(t, err, gojwt.ErrJWTNotInit)
}
