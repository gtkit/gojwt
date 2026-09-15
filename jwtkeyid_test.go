package gojwt_test

import (
	"path/filepath"
	"testing"
	"time"

	jwtv5 "github.com/golang-jwt/jwt/v5"
	"github.com/gtkit/gojwt"
	"github.com/gtkit/gojwt/claims"
	"github.com/stretchr/testify/require"
)

// ---------- helpers ----------

// tokenHeaderKid 读取 token header 里的 kid。
// 第二个返回值表示 header 中是否存在该字段——"不存在"与"存在且为空串"
// 是两种不同的结果，向后兼容性正是靠前者保证的。
func tokenHeaderKid(t *testing.T, token string) (string, bool) {
	t.Helper()

	parsed, _, err := jwtv5.NewParser().ParseUnverified(token, &claims.Claims{})
	require.NoError(t, err)

	raw, ok := parsed.Header["kid"]
	if !ok {
		return "", false
	}
	kid, ok := raw.(string)
	require.Truef(t, ok, "kid 应当是字符串，实际类型 %T", raw)
	return kid, true
}

// tokenerFactory 按算法构造 Tokener，让同一份用例覆盖三种签名实现。
type tokenerFactory struct {
	name string
	newf func(t *testing.T, opts ...gojwt.Option) gojwt.Tokener
}

func allTokenerFactories() []tokenerFactory {
	return []tokenerFactory{
		{
			name: "hmac",
			newf: func(t *testing.T, opts ...gojwt.Option) gojwt.Tokener {
				t.Helper()
				j, err := gojwt.NewJwtHmac([]byte("12345678901234567890123456789012"), opts...)
				require.NoError(t, err)
				return j
			},
		},
		{
			name: "ed25519",
			newf: func(t *testing.T, opts ...gojwt.Option) gojwt.Tokener {
				t.Helper()
				dir := t.TempDir()
				priPath := filepath.Join(dir, "ed25519.pem")
				pubPath := filepath.Join(dir, "ed25519.pub.pem")
				require.NoError(t, gojwt.GenerateEd25519Keys(priPath, pubPath))
				j, err := gojwt.NewJwtEd25519(priPath, pubPath, opts...)
				require.NoError(t, err)
				return j
			},
		},
		{
			name: "rsa",
			newf: func(t *testing.T, opts ...gojwt.Option) gojwt.Tokener {
				t.Helper()
				priPath, pubPath := generateRSAKeyFiles(t, 2048)
				j, err := gojwt.NewJwtRSA(priPath, pubPath, opts...)
				require.NoError(t, err)
				return j
			},
		},
	}
}

// ---------- 写入 ----------

func TestWithKeyIDWritesKidHeader(t *testing.T) {
	for _, f := range allTokenerFactories() {
		t.Run(f.name, func(t *testing.T) {
			j := f.newf(t, gojwt.WithKeyID("app-2026"))

			token, err := j.GenerateToken(10)
			require.NoError(t, err)

			kid, ok := tokenHeaderKid(t, token)
			require.True(t, ok, "header 中应当写入 kid")
			require.Equal(t, "app-2026", kid)
		})
	}
}

// TestKeyIDAbsentWithoutOption 锁住向后兼容: 不用这个选项时 header 里不该多出 kid。
// 空字符串与不设置等价——否则调用方从配置读到空值时会签出一个 kid 为空的 token。
func TestKeyIDAbsentWithoutOption(t *testing.T) {
	testCases := []struct {
		name string
		opts []gojwt.Option
	}{
		{name: "未设置", opts: nil},
		{name: "空字符串", opts: []gojwt.Option{gojwt.WithKeyID("")}},
	}

	for _, f := range allTokenerFactories() {
		for _, tc := range testCases {
			t.Run(f.name+"/"+tc.name, func(t *testing.T) {
				j := f.newf(t, tc.opts...)

				token, err := j.GenerateToken(10)
				require.NoError(t, err)

				_, ok := tokenHeaderKid(t, token)
				require.False(t, ok, "未设置 kid 时 header 中不应出现该字段")
			})
		}
	}
}

// TestWithKeyIDPreservesValue 覆盖需要 JSON 转义的取值:
// kid 由调用方给定，写进 header 后必须原样取回。
func TestWithKeyIDPreservesValue(t *testing.T) {
	testCases := []struct {
		name string
		kid  string
	}{
		{name: "普通", kid: "app-2026"},
		{name: "含双引号与反斜杠", kid: `a"b\c`},
		{name: "含换行", kid: "a\nb"},
		{name: "含空格", kid: "app 2026"},
		{name: "非 ASCII", kid: "密钥-2026"},
		{name: "单字符", kid: "k"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			j, err := gojwt.NewJwtHmac([]byte("12345678901234567890123456789012"),
				gojwt.WithKeyID(tc.kid))
			require.NoError(t, err)

			token, err := j.GenerateToken(10)
			require.NoError(t, err)

			kid, ok := tokenHeaderKid(t, token)
			require.True(t, ok)
			require.Equal(t, tc.kid, kid)
		})
	}
}

// TestWithKeyIDLastOneWins 确认多次传入时按 Option 的常规语义取最后一个。
func TestWithKeyIDLastOneWins(t *testing.T) {
	j, err := gojwt.NewJwtHmac([]byte("12345678901234567890123456789012"),
		gojwt.WithKeyID("first"), gojwt.WithKeyID("second"))
	require.NoError(t, err)

	token, err := j.GenerateToken(10)
	require.NoError(t, err)

	kid, ok := tokenHeaderKid(t, token)
	require.True(t, ok)
	require.Equal(t, "second", kid)
}

// ---------- 与既有行为的关系 ----------

// TestWithKeyIDDoesNotAffectParsing 确认写了 kid 之后签发方自己仍能解析。
func TestWithKeyIDDoesNotAffectParsing(t *testing.T) {
	for _, f := range allTokenerFactories() {
		t.Run(f.name, func(t *testing.T) {
			j := f.newf(t, gojwt.WithKeyID("app-2026"))

			token, err := j.GenerateToken(42, claims.WithSubject("u42"), claims.WithPrv("api"))
			require.NoError(t, err)

			tokenClaims, err := j.ParseToken(token)
			require.NoError(t, err)
			require.Equal(t, int64(42), tokenClaims.UserID)
			require.Equal(t, "u42", tokenClaims.Subject)
			require.Equal(t, "api", tokenClaims.Prv)
		})
	}
}

// TestWithKeyIDCoexistsWithSigningMethod 确认 kid 不影响算法选择——
// 两个选项写的是 header 里不同的字段，不该互相覆盖。
func TestWithKeyIDCoexistsWithSigningMethod(t *testing.T) {
	j, err := gojwt.NewJwtHmac([]byte("1234567890123456789012345678901234567890123456789012345678901234"),
		gojwt.WithHMACSigningMethod(jwtv5.SigningMethodHS512),
		gojwt.WithKeyID("app-2026"))
	require.NoError(t, err)

	token, err := j.GenerateToken(10)
	require.NoError(t, err)

	parsed, _, err := jwtv5.NewParser().ParseUnverified(token, &claims.Claims{})
	require.NoError(t, err)
	require.Equal(t, jwtv5.SigningMethodHS512.Alg(), parsed.Method.Alg())

	kid, ok := tokenHeaderKid(t, token)
	require.True(t, ok)
	require.Equal(t, "app-2026", kid)
}

// TestRefreshTokenKeepsKeyID 覆盖 RefreshToken 这条独立的签名路径:
// 刷新产出的是新签的 token，漏改这里会让 token 在一次刷新后丢掉 kid，
// 验证方随即找不到密钥。
func TestRefreshTokenKeepsKeyID(t *testing.T) {
	for _, f := range allTokenerFactories() {
		t.Run(f.name, func(t *testing.T) {
			j := f.newf(t,
				gojwt.WithKeyID("app-2026"),
				gojwt.WithTokenDuration(time.Second),
				gojwt.WithRefreshDuration(time.Minute),
			)

			token, err := j.GenerateToken(10)
			require.NoError(t, err)

			refreshed, err := j.RefreshToken(token)
			require.NoError(t, err)

			kid, ok := tokenHeaderKid(t, refreshed)
			require.True(t, ok, "刷新后的 token 应当保留 kid")
			require.Equal(t, "app-2026", kid)
		})
	}
}
