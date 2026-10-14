package gojwt_test

import (
	"context"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/gtkit/gojwt"
	"github.com/gtkit/gojwt/claims"
	"github.com/stretchr/testify/require"
)

func TestRefreshTokenConcurrentContract(t *testing.T) {
	t.Parallel()
	algorithms := []struct {
		name string
		new  func(t *testing.T, options ...gojwt.Option) (gojwt.ContextTokener, error)
	}{
		{
			name: "HMAC",
			new: func(_ *testing.T, options ...gojwt.Option) (gojwt.ContextTokener, error) {
				return gojwt.NewJwtHmac([]byte(rand.Text()+rand.Text()), options...)
			},
		},
		{
			name: "Ed25519",
			new: func(t *testing.T, options ...gojwt.Option) (gojwt.ContextTokener, error) {
				publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
				require.NoError(t, err)
				return gojwt.NewJwtEd25519FromKeys(privateKey, publicKey, options...)
			},
		},
		{
			name: "RSA",
			new: func(t *testing.T, options ...gojwt.Option) (gojwt.ContextTokener, error) {
				key := capabilityRSAKey(t)
				return gojwt.NewJwtRSAFromKeys(key, &key.PublicKey, options...)
			},
		},
		{
			name: "ECDSA",
			new: func(t *testing.T, options ...gojwt.Option) (gojwt.ContextTokener, error) {
				key := capabilityECDSAKey(t, elliptic.P256())
				return gojwt.NewJwtECDSAFromKeys(key, &key.PublicKey, options...)
			},
		},
	}
	storeErr := errors.New("session store unavailable")
	tests := []struct {
		name          string
		input         string
		want          int
		wantErr       error
		window        time.Duration
		blacklisted   bool
		revoked       bool
		canceled      bool
		revocationErr error
	}{
		{name: "independent concurrent renewals", input: "valid", want: 16},
		{name: "empty token", wantErr: gojwt.ErrTokenMalformed},
		{name: "malformed token", input: "invalid", wantErr: gojwt.ErrTokenMalformed},
		{name: "already blacklisted", input: "valid", blacklisted: true, wantErr: gojwt.ErrTokenBlacklisted},
		{name: "revoked session", input: "valid", revoked: true, wantErr: gojwt.ErrTokenBlacklisted},
		{name: "store failure", input: "valid", revocationErr: storeErr, wantErr: storeErr},
		{name: "canceled context", input: "valid", canceled: true, wantErr: context.Canceled},
		{name: "outside refresh window", input: "valid", window: time.Minute, wantErr: gojwt.ErrRefreshTooEarly},
	}
	for _, algorithm := range algorithms {
		t.Run(algorithm.name, func(t *testing.T) {
			t.Parallel()
			for _, tc := range tests {
				t.Run(tc.name, func(t *testing.T) {
					t.Parallel()
					window := 30 * time.Minute
					if tc.window != 0 {
						window = tc.window
					}
					j, err := algorithm.new(t,
						gojwt.WithTokenDuration(30*time.Minute),
						gojwt.WithRefreshWindow(window),
						gojwt.WithBlacklistCheckContextFunc(func(context.Context, string) (bool, error) {
							return tc.blacklisted, nil
						}),
						gojwt.WithRevocationCheck(func(context.Context, *claims.Claims) (bool, error) {
							return tc.revoked, tc.revocationErr
						}),
					)
					require.NoError(t, err)
					input := tc.input
					if input == "valid" {
						input, err = j.GenerateToken(42,
							claims.WithRoles("reader"),
							claims.WithExt("session_version", int64(1)),
						)
						require.NoError(t, err)
					}
					ctx, cancel := context.WithCancel(t.Context())
					defer cancel()
					if tc.canceled {
						cancel()
					}
					var original *claims.Claims
					if tc.want > 0 {
						original, err = j.CachedParseTokenContext(ctx, input)
						require.NoError(t, err)
					}

					const requests = 16
					var tokens [requests]string
					var errs [requests]error
					start := make(chan struct{})
					var wg sync.WaitGroup
					for i := range requests {
						wg.Go(func() {
							<-start
							tokens[i], errs[i] = j.RefreshTokenContext(ctx, input)
						})
					}
					close(start)
					wg.Wait()

					ids := make(map[string]struct{}, requests)
					for i, token := range tokens {
						require.True(t, errors.Is(errs[i], tc.wantErr), "request %d: %v", i, errs[i])
						if tc.wantErr != nil {
							require.Empty(t, token)
							continue
						}
						c, err := j.ParseTokenContext(ctx, token)
						require.NoError(t, err)
						require.NotEqual(t, original.ID, c.ID)
						require.Equal(t, c.ID, c.TokenID)
						require.Equal(t, original.UserID, c.UserID)
						require.Equal(t, original.Roles, c.Roles)
						require.True(t, c.AuthTime.Equal(original.AuthTime.Time))
						require.False(t, c.ExpiresAt.After(original.AuthTime.Add(7*24*time.Hour)))
						version, ok := c.ExtInt64("session_version")
						require.True(t, ok)
						require.Equal(t, int64(1), version)
						ids[c.ID] = struct{}{}
					}
					require.Len(t, ids, tc.want)
					if tc.want > 0 {
						// 原 token 及其缓存未被续签修改，也没有被消费或自动吊销。
						after, err := j.CachedParseTokenContext(ctx, input)
						require.NoError(t, err)
						require.Equal(t, original.ID, after.ID)
						require.True(t, original.ExpiresAt.Equal(after.ExpiresAt.Time))
						repeated, err := j.RefreshTokenContext(ctx, input)
						require.NoError(t, err)
						c, err := j.ParseTokenContext(ctx, repeated)
						require.NoError(t, err)
						_, duplicate := ids[c.ID]
						require.False(t, duplicate)
					}
				})
			}
		})
	}
}
