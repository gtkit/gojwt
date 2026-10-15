package gojwt_test

import (
	"context"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	jwtv5 "github.com/golang-jwt/jwt/v5"
	"github.com/gtkit/gojwt"
	"github.com/gtkit/gojwt/claims"
	"github.com/stretchr/testify/require"
)

type lifecycleAlgorithm struct {
	name string
	new  func(*testing.T, ...gojwt.Option) (gojwt.ContextTokener, error)
}

func lifecycleAlgorithms() []lifecycleAlgorithm {
	return []lifecycleAlgorithm{
		{name: "HMAC", new: func(t *testing.T, options ...gojwt.Option) (gojwt.ContextTokener, error) {
			return gojwt.NewJwtHmac(reviewKey(t), options...)
		}},
		{name: "Ed25519", new: func(t *testing.T, options ...gojwt.Option) (gojwt.ContextTokener, error) {
			publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
			require.NoError(t, err)
			return gojwt.NewJwtEd25519FromKeys(privateKey, publicKey, options...)
		}},
		{name: "RSA", new: func(t *testing.T, options ...gojwt.Option) (gojwt.ContextTokener, error) {
			key := capabilityRSAKey(t)
			return gojwt.NewJwtRSAFromKeys(key, &key.PublicKey, options...)
		}},
		{name: "ECDSA", new: func(t *testing.T, options ...gojwt.Option) (gojwt.ContextTokener, error) {
			key := capabilityECDSAKey(t, elliptic.P256())
			return gojwt.NewJwtECDSAFromKeys(key, &key.PublicKey, options...)
		}},
	}
}

func TestTokenPrecisionBoundaries(t *testing.T) {
	for _, algorithm := range lifecycleAlgorithms() {
		t.Run(algorithm.name, func(t *testing.T) {
			for _, tc := range []struct {
				name     string
				input    time.Duration
				want     time.Duration
				override func(time.Time) claims.Option
			}{
				{name: "500ms", input: 500 * time.Millisecond, want: 500 * time.Millisecond},
				{name: "1500ms", input: 1500 * time.Millisecond, want: 1500 * time.Millisecond},
				{name: "two hours", input: 2 * time.Hour, want: 2 * time.Hour},
				{name: "relative override", input: time.Hour, want: 500 * time.Millisecond, override: func(time.Time) claims.Option {
					return claims.WithExpiresIn(500 * time.Millisecond)
				}},
				{name: "deprecated relative override", input: time.Hour, want: 500 * time.Millisecond, override: func(time.Time) claims.Option {
					return claims.WithExpiresAt(500 * time.Millisecond) //nolint:staticcheck // Verify the existing deprecated API remains compatible.
				}},
				{name: "absolute override", input: time.Hour, want: 500 * time.Millisecond, override: func(now time.Time) claims.Option {
					return claims.WithExpiresAtTime(now.Add(500 * time.Millisecond))
				}},
			} {
				t.Run(tc.name, func(t *testing.T) {
					synctest.Test(t, func(t *testing.T) {
						time.Sleep(250 * time.Millisecond)
						now := time.Now()
						precision := jwtv5.TimePrecision
						j, err := algorithm.new(t, gojwt.WithTokenDuration(tc.input), gojwt.WithParseLeeway(0),
							gojwt.WithClaimsValidator(func(_ context.Context, c *claims.Claims) error {
								if !c.ExpiresAt.Equal(now.Add(tc.want)) {
									return fmt.Errorf("callback date lost precision")
								}
								// 修改副本不能破坏返回值或缓存中的时间。
								c.ExpiresAt.Time = c.ExpiresAt.Add(time.Hour)
								return nil
							}))
						require.NoError(t, err)
						options := []claims.Option{claims.WithExt("integer", int64(1))}
						if tc.override != nil {
							options = append(options, tc.override(now))
						}
						raw, err := j.GenerateToken(42, options...)
						require.NoError(t, err)
						for range 2 {
							c, err := j.CachedParseTokenContext(t.Context(), raw)
							require.NoError(t, err)
							require.True(t, c.ExpiresAt.Equal(now.Add(tc.want)))
							require.True(t, c.IssuedAt.Equal(now))
							require.True(t, c.NotBefore.Equal(now))
							require.True(t, c.AuthTime.Equal(now))
							require.IsType(t, json.Number(""), c.Ext["integer"])
						}
						// 精确验证 exp 前一纳秒、exp 瞬间以及缓存入口。
						time.Sleep(tc.want - time.Nanosecond)
						_, err = j.CachedParseTokenContext(t.Context(), raw)
						require.NoError(t, err)
						time.Sleep(time.Nanosecond)
						_, err = j.ParseTokenContext(t.Context(), raw)
						require.ErrorIs(t, err, gojwt.ErrTokenExpired)
						_, err = j.CachedParseTokenContext(t.Context(), raw)
						require.ErrorIs(t, err, gojwt.ErrTokenExpired)
						_, err = j.RefreshTokenContext(t.Context(), raw)
						require.ErrorIs(t, err, gojwt.ErrTokenExpired)
						require.Equal(t, precision, jwtv5.TimePrecision)
					})
				})
			}
		})
	}
}

func TestRefreshPrecisionAndSessionCap(t *testing.T) {
	for _, algorithm := range lifecycleAlgorithms() {
		t.Run(algorithm.name, func(t *testing.T) {
			for _, tc := range []struct {
				name   string
				input  time.Duration
				legacy bool
				cap    bool
			}{
				{name: "no rounding drift", input: 10 * time.Second},
				{name: "fractional session deadline", input: 750 * time.Millisecond, cap: true},
				{name: "legacy integer origin", input: 10 * time.Second, legacy: true},
			} {
				t.Run(tc.name, func(t *testing.T) {
					synctest.Test(t, func(t *testing.T) {
						time.Sleep(250 * time.Millisecond)
						j, err := algorithm.new(t, gojwt.WithTokenDuration(500*time.Millisecond), gojwt.WithRefreshDuration(tc.input))
						require.NoError(t, err)
						var options []claims.Option
						if tc.legacy {
							options = append(options, func(c *claims.Claims) {
								c.AuthTime = nil
								c.IssuedAt = jwtv5.NewNumericDate(time.Now())
							})
						}
						raw, err := j.GenerateToken(42, options...)
						require.NoError(t, err)
						current, err := j.ParseToken(raw)
						require.NoError(t, err)
						origin := current.AuthTime
						if origin == nil {
							origin = current.IssuedAt
						}
						deadline := origin.Add(tc.input)
						for range 4 {
							// 旧整数 iat 的 token 可有较长 exp-iat，仍须等待进入配置的窗口。
							time.Sleep(max(100*time.Millisecond, time.Until(current.ExpiresAt.Time)-500*time.Millisecond))
							now := time.Now()
							wantExpiry := now.Add(current.ExpiresAt.Sub(current.IssuedAt.Time))
							if wantExpiry.After(deadline) {
								wantExpiry = deadline
							}
							raw, err = j.RefreshTokenContext(t.Context(), raw)
							require.NoError(t, err)
							current, err = j.CachedParseTokenContext(t.Context(), raw)
							require.NoError(t, err)
							require.True(t, current.AuthTime.Equal(origin.Time))
							require.True(t, current.IssuedAt.Equal(now))
							require.True(t, current.ExpiresAt.Equal(wantExpiry))
						}
						if tc.cap {
							require.True(t, current.ExpiresAt.Equal(deadline))
							time.Sleep(time.Until(deadline))
							_, err := j.RefreshToken(raw)
							require.ErrorIs(t, err, gojwt.ErrRefreshExpired)
						}
					})
				})
			}
		})
	}
}

func TestRevocationCoversLeeway(t *testing.T) {
	for _, tc := range []struct {
		name             string
		input            time.Duration
		defaultRetention bool
	}{
		{name: "default five seconds", input: 5 * time.Second, defaultRetention: true},
		{name: "custom thirty seconds", input: 30 * time.Second},
		{name: "zero leeway", input: 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				time.Sleep(250 * time.Millisecond)
				blacklist, err := gojwt.NewBlacklistWithCleanup(time.Second)
				require.NoError(t, err)
				defer blacklist.Close()
				j, err := gojwt.NewJwtHmac(reviewKey(t), gojwt.WithTokenDuration(500*time.Millisecond),
					gojwt.WithParseLeeway(tc.input), gojwt.WithBlacklistFunc(blacklist.In))
				require.NoError(t, err)
				raw, err := j.GenerateToken(42)
				require.NoError(t, err)
				c, err := j.CachedParseToken(raw)
				require.NoError(t, err)
				if tc.defaultRetention {
					err = blacklist.AddToken(c)
				} else {
					err = blacklist.AddTokenWithLeeway(c, tc.input)
				}
				require.NoError(t, err)
				checkRevoked := func() {
					t.Helper()
					require.True(t, blacklist.In(c.TokenID))
					_, err := j.ParseToken(raw)
					require.ErrorIs(t, err, gojwt.ErrTokenBlacklisted)
					_, err = j.CachedParseToken(raw)
					require.ErrorIs(t, err, gojwt.ErrTokenBlacklisted)
					_, err = j.RefreshToken(raw)
					require.ErrorIs(t, err, gojwt.ErrTokenBlacklisted)
				}
				checkRevoked()
				time.Sleep(time.Until(c.ExpiresAt.Time))
				if tc.input > 0 {
					checkRevoked()
					time.Sleep(tc.input - time.Nanosecond)
					checkRevoked()
					time.Sleep(time.Nanosecond)
				}
				require.False(t, blacklist.In(c.TokenID))
				_, err = j.ParseToken(raw)
				require.ErrorIs(t, err, gojwt.ErrTokenExpired)
				_, err = j.CachedParseToken(raw)
				require.ErrorIs(t, err, gojwt.ErrTokenExpired)
				_, err = j.RefreshToken(raw)
				require.ErrorIs(t, err, gojwt.ErrTokenExpired)
			})
		})
	}
}

func TestBlacklistExplicitLeewayInputs(t *testing.T) {
	valid := &claims.Claims{TokenID: "valid", RegisteredClaims: jwtv5.RegisteredClaims{ExpiresAt: &jwtv5.NumericDate{Time: time.Now().Add(time.Hour)}}}
	for _, tc := range []struct {
		name    string
		input   *claims.Claims
		leeway  time.Duration
		want    bool
		wantErr error
	}{
		{name: "positive", input: valid, leeway: time.Second, want: true},
		{name: "zero", input: valid, want: true},
		{name: "negative", input: valid, leeway: -time.Nanosecond, wantErr: gojwt.ErrInvalidConfig},
		{name: "nil claims", wantErr: gojwt.ErrTokenInvalidClaims},
		{name: "missing id", input: &claims.Claims{}, wantErr: gojwt.ErrTokenInvalidClaims},
		{name: "missing exp", input: &claims.Claims{TokenID: "valid"}, wantErr: gojwt.ErrTokenInvalidClaims},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b := gojwt.NewBlacklist()
			err := b.AddTokenWithLeeway(tc.input, tc.leeway)
			require.ErrorIs(t, err, tc.wantErr)
			require.Equal(t, tc.want, b.In("valid"))
		})
	}
}

func TestExternalNumericDatePrecision(t *testing.T) {
	key := reviewKey(t)
	j, err := gojwt.NewJwtHmac(key)
	require.NoError(t, err)
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256"}`))
	for _, tc := range []struct {
		name    string
		input   string
		want    time.Time
		wantErr error
	}{
		{name: "integer", input: "253402300799", want: time.Unix(253402300799, 0)},
		{name: "maximum nanosecond", input: "253402300799.999999999", want: time.Unix(253402300799, 999999999)},
		{name: "scientific", input: "2.53402300799999999999e11", want: time.Unix(253402300799, 999999999)},
		{name: "maximum excluded", input: "253402300800", wantErr: gojwt.ErrTokenMalformed},
		{name: "before minimum", input: "-62135596800.000000001", wantErr: gojwt.ErrTokenMalformed},
	} {
		t.Run(tc.name, func(t *testing.T) {
			payload := fmt.Sprintf(`{"exp":%s,"iat":-0.000000001,"nbf":-0.5,"auth_time":-11.75}`, tc.input)
			raw := reviewRawJWT(key, header, payload)
			for range 2 {
				c, err := j.CachedParseToken(raw)
				require.ErrorIs(t, err, tc.wantErr)
				if tc.wantErr != nil {
					require.Nil(t, c)
					continue
				}
				require.True(t, c.ExpiresAt.Equal(tc.want))
				require.True(t, c.IssuedAt.Equal(time.Unix(0, -1)))
				require.True(t, c.NotBefore.Equal(time.Unix(0, -500000000)))
				require.True(t, c.AuthTime.Equal(time.Unix(-11, -750000000)))
			}
		})
	}
}

// Existing interface implementations and constructor function values keep compiling.
type legacyBlacklistManager struct{}

func (*legacyBlacklistManager) In(string) bool                      { return false }
func (*legacyBlacklistManager) Add(string)                          {}
func (*legacyBlacklistManager) Remove(string)                       {}
func (*legacyBlacklistManager) AddWithExpiration(string, time.Time) {}
func (*legacyBlacklistManager) AddToken(*claims.Claims) error       { return nil }
func (*legacyBlacklistManager) SweepExpired() int                   { return 0 }
func (*legacyBlacklistManager) Close()                              {}

var (
	_ gojwt.BlacklistManager                        = (*legacyBlacklistManager)(nil)
	_ func() *gojwt.Blacklist                       = gojwt.NewBlacklist
	_ func(time.Duration) (*gojwt.Blacklist, error) = gojwt.NewBlacklistWithCleanup
)

func TestPasswordChangeConcurrentRefresh(t *testing.T) {
	for _, tc := range []struct {
		name   string
		legacy bool
	}{
		{name: "stable auth_time"},
		{name: "legacy iat origin", legacy: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				time.Sleep(250 * time.Millisecond)
				var cutoff atomic.Int64
				var block atomic.Bool
				entered, resume := make(chan struct{}), make(chan struct{})
				key := reviewKey(t)
				j, err := gojwt.NewJwtHmac(key, gojwt.WithTokenDuration(10*time.Second),
					gojwt.WithRefreshWindow(10*time.Second),
					gojwt.WithRevocationCheck(func(ctx context.Context, c *claims.Claims) (bool, error) {
						snapshot := cutoff.Load()
						if block.CompareAndSwap(true, false) {
							close(entered)
							select {
							case <-resume:
							case <-ctx.Done():
								return false, ctx.Err()
							}
						}
						return examplePasswordChangeRevoked(c, time.Unix(0, snapshot)), nil
					}))
				require.NoError(t, err)
				var options []claims.Option
				if tc.legacy {
					options = append(options, func(c *claims.Claims) { c.AuthTime = nil })
				}
				oldToken, err := j.GenerateToken(42, options...)
				require.NoError(t, err)
				original, err := j.CachedParseToken(oldToken)
				require.NoError(t, err)
				block.Store(true)
				type result struct {
					token string
					err   error
				}
				results := make(chan result, 1)
				go func() {
					token, err := j.RefreshTokenContext(t.Context(), oldToken)
					results <- result{token: token, err: err}
				}()
				<-entered
				time.Sleep(time.Second)
				cutoff.Store(time.Now().UnixNano())
				close(resume)
				refreshed := <-results
				require.NoError(t, refreshed.err)
				// Refresh can finish, but the original authentication origin makes its result unusable.
				_, err = j.CachedParseToken(oldToken)
				require.ErrorIs(t, err, gojwt.ErrTokenBlacklisted)
				_, err = j.ParseToken(refreshed.token)
				require.ErrorIs(t, err, gojwt.ErrTokenBlacklisted)
				_, err = j.RefreshToken(refreshed.token)
				require.ErrorIs(t, err, gojwt.ErrTokenBlacklisted)
				// Inspect the signed result through an independent verifier to prove iat was updated.
				verifier, err := gojwt.NewJwtHmac(key)
				require.NoError(t, err)
				verified, err := verifier.ParseToken(refreshed.token)
				require.NoError(t, err)
				require.False(t, verified.IssuedAt.Before(time.Unix(0, cutoff.Load())))
				require.True(t, original.IssuedAt.Before(time.Unix(0, cutoff.Load())))
			})
		})
	}
}

func TestPasswordChangeOriginInputs(t *testing.T) {
	now := time.Now()
	storeErr := errors.New("password cutoff store unavailable")
	for _, tc := range []struct {
		name     string
		input    *jwtv5.NumericDate
		iat      *jwtv5.NumericDate
		wantErr  error
		storeErr error
	}{
		{name: "old auth with recent iat", input: &jwtv5.NumericDate{Time: now.Add(-time.Hour)}, iat: &jwtv5.NumericDate{Time: now}, wantErr: gojwt.ErrTokenBlacklisted},
		{name: "new auth", input: &jwtv5.NumericDate{Time: now}, iat: &jwtv5.NumericDate{Time: now}},
		{name: "legacy old iat", iat: &jwtv5.NumericDate{Time: now.Add(-time.Hour)}, wantErr: gojwt.ErrTokenBlacklisted},
		{name: "legacy new iat", iat: &jwtv5.NumericDate{Time: now}},
		{name: "missing origins", wantErr: gojwt.ErrTokenBlacklisted},
		{name: "store failure", input: &jwtv5.NumericDate{Time: now}, iat: &jwtv5.NumericDate{Time: now}, storeErr: storeErr, wantErr: storeErr},
	} {
		t.Run(tc.name, func(t *testing.T) {
			j, err := gojwt.NewJwtHmac(reviewKey(t), gojwt.WithRevocationCheck(func(ctx context.Context, c *claims.Claims) (bool, error) {
				if err := ctx.Err(); err != nil {
					return false, err
				}
				if tc.storeErr != nil {
					return false, tc.storeErr
				}
				return examplePasswordChangeRevoked(c, now.Add(-time.Minute)), nil
			}))
			require.NoError(t, err)
			raw, err := j.GenerateToken(42, func(c *claims.Claims) { c.AuthTime, c.IssuedAt = tc.input, tc.iat })
			require.NoError(t, err)
			_, err = j.ParseTokenContext(t.Context(), raw)
			require.ErrorIs(t, err, tc.wantErr)
		})
	}
}

func TestBlacklistExplicitLeewayConcurrent(t *testing.T) {
	for _, tc := range []struct {
		name  string
		input time.Duration
	}{
		{name: "zero", input: 0},
		{name: "thirty seconds", input: 30 * time.Second},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b := gojwt.NewBlacklist()
			const requests = 16
			var errs [requests]error
			var active [requests]bool
			var wg sync.WaitGroup
			for i := range requests {
				wg.Go(func() {
					c := &claims.Claims{TokenID: fmt.Sprintf("token-%d", i), RegisteredClaims: jwtv5.RegisteredClaims{ExpiresAt: &jwtv5.NumericDate{Time: time.Now().Add(time.Hour)}}}
					errs[i] = b.AddTokenWithLeeway(c, tc.input)
					active[i] = b.In(c.TokenID)
					b.Remove(c.TokenID)
				})
			}
			wg.Wait()
			for i := range requests {
				require.NoError(t, errs[i])
				require.True(t, active[i])
			}
		})
	}
}
