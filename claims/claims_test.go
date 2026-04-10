package claims

import (
	"testing"
	"time"

	jwtv5 "github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/require"
)

func TestWithExpiresInSetsRelativeDuration(t *testing.T) {
	c := &Claims{}
	WithExpiresIn(10 * time.Minute)(c)

	require.NotNil(t, c.ExpiresAt)
	ttl := time.Until(c.ExpiresAt.Time)
	require.InDelta(t, (10 * time.Minute).Seconds(), ttl.Seconds(), 2)
}

func TestWithExpiresAtTimeSetAbsoluteTime(t *testing.T) {
	target := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	c := &Claims{}
	WithExpiresAtTime(target)(c)

	require.NotNil(t, c.ExpiresAt)
	require.True(t, c.ExpiresAt.Time.Equal(target))
}

func TestDeprecatedWithExpiresAtDelegatesToWithExpiresIn(t *testing.T) {
	c := &Claims{}
	WithExpiresAt(5 * time.Minute)(c)

	require.NotNil(t, c.ExpiresAt)
	ttl := time.Until(c.ExpiresAt.Time)
	require.InDelta(t, (5 * time.Minute).Seconds(), ttl.Seconds(), 2)
}

func TestWithRole(t *testing.T) {
	c := &Claims{}
	WithRole("admin")(c)
	WithRole("editor")(c)

	require.Equal(t, []string{"admin", "editor"}, c.Roles)
}

func TestWithRoles(t *testing.T) {
	c := &Claims{}
	WithRoles("admin", "editor", "viewer")(c)

	require.Equal(t, []string{"admin", "editor", "viewer"}, c.Roles)
}

func TestWithPrv(t *testing.T) {
	c := &Claims{}
	WithPrv("app")(c)

	require.Equal(t, "app", c.Prv)
}

func TestWithIssuer(t *testing.T) {
	c := &Claims{}
	WithIssuer("my-service")(c)

	require.Equal(t, "my-service", c.Issuer)
}

func TestWithSubject(t *testing.T) {
	c := &Claims{}
	WithSubject("user:42")(c)

	require.Equal(t, "user:42", c.Subject)
}

func TestWithAudience(t *testing.T) {
	c := &Claims{}
	WithAudience("api", "web")(c)

	require.Equal(t, jwtv5.ClaimStrings{"api", "web"}, c.Audience)
}

func TestWithJwtID(t *testing.T) {
	c := &Claims{}
	WithJwtID("custom-jti")(c)

	require.Equal(t, "custom-jti", c.ID)
}

func TestUserId(t *testing.T) {
	c := Claims{UserID: 42}
	require.Equal(t, int64(42), c.UserId())
}

func TestVerifyRoleSuccess(t *testing.T) {
	c := Claims{Roles: []string{"admin", "editor"}}
	require.NoError(t, c.VerifyRole("admin"))
	require.NoError(t, c.VerifyRole("admin", "editor"))
}

func TestVerifyRoleMissing(t *testing.T) {
	c := Claims{Roles: []string{"viewer"}}
	require.ErrorIs(t, c.VerifyRole("admin"), ErrTokenRole)
}

func TestVerifyRolePartialMismatch(t *testing.T) {
	c := Claims{Roles: []string{"admin"}}
	require.ErrorIs(t, c.VerifyRole("admin", "editor"), ErrTokenRole)
}

func TestVerifyPrvMatch(t *testing.T) {
	c := Claims{Prv: "app"}
	require.NoError(t, c.VerifyPrv("app"))
}

func TestVerifyPrvMismatch(t *testing.T) {
	c := Claims{Prv: "app"}
	require.ErrorIs(t, c.VerifyPrv("admin"), ErrTokenPrv)
}

func TestTTLPositive(t *testing.T) {
	c := Claims{
		RegisteredClaims: jwtv5.RegisteredClaims{
			ExpiresAt: jwtv5.NewNumericDate(time.Now().Add(10 * time.Minute)),
		},
	}
	ttl := c.TTL()
	require.Greater(t, ttl, 9*time.Minute)
	require.LessOrEqual(t, ttl, 10*time.Minute)
}

func TestTTLExpiredReturnsZero(t *testing.T) {
	c := Claims{
		RegisteredClaims: jwtv5.RegisteredClaims{
			ExpiresAt: jwtv5.NewNumericDate(time.Now().Add(-time.Hour)),
		},
	}
	require.Equal(t, time.Duration(0), c.TTL())
}

func TestTTLNilExpiresAtReturnsZero(t *testing.T) {
	c := Claims{}
	require.Equal(t, time.Duration(0), c.TTL())
}
