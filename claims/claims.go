package claims

import (
	"slices"
	"time"

	jwtv5 "github.com/golang-jwt/jwt/v5"
)

type Claims struct {
	jwtv5.RegisteredClaims

	UserID  int64    `json:"uid"`
	Prv     string   `json:"prv,omitzero"`
	Roles   []string `json:"roles,omitzero"`
	TokenID string   `json:"token_id"`
}

type Option func(*Claims)
type Options = Option

func WithRole(role string) Option {
	return func(claims *Claims) {
		claims.Roles = append(claims.Roles, role)
	}
}

func WithRoles(roles ...string) Option {
	return func(claims *Claims) {
		claims.Roles = append(claims.Roles, roles...)
	}
}

func WithPrv(prv string) Option {
	return func(claims *Claims) {
		claims.Prv = prv
	}
}

func WithIssuer(issuer string) Option {
	return func(claims *Claims) {
		claims.Issuer = issuer
	}
}

func WithSubject(subject string) Option {
	return func(claims *Claims) {
		claims.Subject = subject
	}
}

func WithAudience(audience ...string) Option {
	return func(claims *Claims) {
		claims.Audience = append(claims.Audience, audience...)
	}
}

func WithExpiresAt(expiresAt time.Duration) Option {
	return func(claims *Claims) {
		claims.ExpiresAt = jwtv5.NewNumericDate(time.Now().Add(expiresAt))
	}
}

func WithJwtID(jwtID string) Option {
	return func(claims *Claims) {
		claims.ID = jwtID
	}
}

func (c Claims) UserId() int64 {
	return c.UserID
}

func (c Claims) VerifyRole(roles ...string) error {
	for _, role := range roles {
		if !slices.Contains(c.Roles, role) {
			return ErrTokenRole
		}
	}
	return nil
}

func (c Claims) VerifyPrv(prv string) error {
	if c.Prv == prv {
		return nil
	}
	return ErrTokenPrv
}

func (c Claims) TTL() time.Duration {
	if c.ExpiresAt == nil {
		return 0
	}
	return c.ExpiresAt.Sub(time.Now())
}
