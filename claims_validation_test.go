package gojwt_test

import (
	"context"
	"encoding/base64"
	"errors"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	jwtv5 "github.com/golang-jwt/jwt/v5"
	"github.com/gtkit/gojwt"
	"github.com/gtkit/gojwt/claims"
	"github.com/stretchr/testify/require"
)

func TestClaimsValidatorOptions(t *testing.T) {
	t.Parallel()
	policyErr := errors.New("subject does not identify the user")
	for _, factory := range allTokenerFactories() {
		t.Run(factory.name, func(t *testing.T) {
			for _, tt := range []struct {
				name     string
				mode     string
				subject  string
				wantErr  error
				wantCall int
			}{
				{name: "valid", mode: "enabled", subject: "42", wantCall: 1},
				{name: "mismatch", mode: "enabled", subject: "7", wantErr: policyErr, wantCall: 1},
				{name: "unset", mode: "unset", subject: "7"},
				{name: "nil", mode: "nil", subject: "7"},
				{name: "last value wins", mode: "replace", subject: "42", wantCall: 1},
				{name: "last nil disables", mode: "disable", subject: "7"},
			} {
				t.Run(tt.name, func(t *testing.T) {
					calls := 0
					validator := func(_ context.Context, c *claims.Claims) error {
						calls++
						if c.Subject != strconv.FormatInt(c.UserID, 10) {
							return policyErr
						}
						return nil
					}
					var options []gojwt.Option
					switch tt.mode {
					case "enabled":
						options = []gojwt.Option{gojwt.WithClaimsValidator(validator)}
					case "nil":
						options = []gojwt.Option{gojwt.WithClaimsValidator(nil)}
					case "replace":
						options = []gojwt.Option{
							gojwt.WithClaimsValidator(func(context.Context, *claims.Claims) error { return policyErr }),
							gojwt.WithClaimsValidator(validator),
						}
					case "disable":
						options = []gojwt.Option{gojwt.WithClaimsValidator(validator), gojwt.WithClaimsValidator(nil)}
					}
					j := factory.newf(t, options...)
					token, err := j.GenerateToken(42, claims.WithSubject(tt.subject))
					require.NoError(t, err)
					got, err := j.ParseToken(token)
					if tt.wantErr != nil {
						require.ErrorIs(t, err, tt.wantErr)
						require.ErrorIs(t, err, gojwt.ErrTokenInvalidClaims)
						require.Nil(t, got)
					} else {
						require.NoError(t, err)
						require.Equal(t, int64(42), got.UserID)
					}
					require.Equal(t, tt.wantCall, calls)
				})
			}
		})
	}
}

func TestClaimsValidatorOrder(t *testing.T) {
	t.Parallel()
	policyErr := errors.New("application rejected claims")
	for _, tt := range []struct {
		name      string
		issuer    string
		tamper    bool
		reject    bool
		wantErr   error
		wantOrder []string
	}{
		{name: "accepted", issuer: "auth", wantOrder: []string{"claims", "blacklist", "revocation"}},
		{name: "signature first", issuer: "auth", tamper: true, wantErr: gojwt.ErrTokenSignatureInvalid},
		{name: "standard claims first", issuer: "other", wantErr: gojwt.ErrTokenInvalidIssuer},
		{name: "application before revocation", issuer: "auth", reject: true, wantErr: policyErr, wantOrder: []string{"claims"}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var order []string
			secret, err := gojwt.GenerateHMACKeyString(jwtv5.SigningMethodHS256)
			require.NoError(t, err)
			j, err := gojwt.NewJwtHmac([]byte(secret),
				gojwt.WithParserOptions(jwtv5.WithIssuer("auth")),
				gojwt.WithClaimsValidator(func(context.Context, *claims.Claims) error {
					order = append(order, "claims")
					if tt.reject {
						return policyErr
					}
					return nil
				}),
				gojwt.WithBlacklistCheckContextFunc(func(context.Context, string) (bool, error) {
					order = append(order, "blacklist")
					return false, nil
				}),
				gojwt.WithRevocationCheck(func(context.Context, *claims.Claims) (bool, error) {
					order = append(order, "revocation")
					return false, nil
				}),
			)
			require.NoError(t, err)
			token, err := j.GenerateToken(42, claims.WithIssuer(tt.issuer))
			require.NoError(t, err)
			if tt.tamper {
				parts := strings.Split(token, ".")
				signature, decodeErr := base64.RawURLEncoding.DecodeString(parts[2])
				require.NoError(t, decodeErr)
				signature[0] ^= 1
				parts[2] = base64.RawURLEncoding.EncodeToString(signature)
				token = strings.Join(parts, ".")
			}
			got, err := j.ParseTokenContext(t.Context(), token)
			if tt.wantErr == nil {
				require.NoError(t, err)
				require.NotNil(t, got)
			} else {
				require.ErrorIs(t, err, tt.wantErr)
				require.Nil(t, got)
			}
			require.Equal(t, tt.wantOrder, order)
		})
	}
}

func TestClaimsValidatorIsolationAndCache(t *testing.T) {
	t.Parallel()
	for _, tt := range []struct {
		name   string
		cached bool
	}{
		{name: "uncached"},
		{name: "cache hit", cached: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			policyErr := errors.New("policy changed")
			var reject atomic.Bool
			var calls atomic.Int64
			secret, err := gojwt.GenerateHMACKeyString(jwtv5.SigningMethodHS256)
			require.NoError(t, err)
			j, err := gojwt.NewJwtHmac([]byte(secret), gojwt.WithClaimsValidator(func(_ context.Context, c *claims.Claims) error {
				calls.Add(1)
				if reject.Load() {
					return policyErr
				}
				c.UserID = 7
				c.Roles[0] = "admin"
				c.Audience[0] = "other"
				c.ExpiresAt.Time = time.Unix(0, 0)
				c.AuthTime.Time = time.Unix(0, 0)
				c.Ext["nested"].(map[string]any)["values"].([]any)[0] = "changed"
				return nil
			}))
			require.NoError(t, err)
			var originalExpiry, originalAuthTime time.Time
			token, err := j.GenerateToken(42, claims.WithRole("user"), claims.WithAudience("api"),
				claims.WithExt("nested", map[string]any{"values": []any{"original"}}),
				func(c *claims.Claims) {
					originalExpiry = c.ExpiresAt.Time
					originalAuthTime = c.AuthTime.Time
				})
			require.NoError(t, err)
			parse := j.ParseTokenContext
			if tt.cached {
				parse = j.CachedParseTokenContext
			}
			for range 2 {
				got, parseErr := parse(t.Context(), token)
				require.NoError(t, parseErr)
				require.Equal(t, int64(42), got.UserID)
				require.Equal(t, []string{"user"}, got.Roles)
				require.Equal(t, jwtv5.ClaimStrings{"api"}, got.Audience)
				require.True(t, got.ExpiresAt.Equal(originalExpiry))
				require.True(t, got.AuthTime.Equal(originalAuthTime))
				require.Equal(t, "original", got.Ext["nested"].(map[string]any)["values"].([]any)[0])
			}
			reject.Store(true)
			got, err := parse(t.Context(), token)
			require.Nil(t, got)
			require.ErrorIs(t, err, policyErr)
			require.ErrorIs(t, err, gojwt.ErrTokenInvalidClaims)
			require.Equal(t, int64(3), calls.Load())
		})
	}
}

func TestClaimsValidatorParallelAndContext(t *testing.T) {
	t.Parallel()
	policyErr := errors.New("user rejected")
	type contextKey struct{}
	for _, factory := range allTokenerFactories() {
		t.Run(factory.name, func(t *testing.T) {
			ctx := context.WithValue(t.Context(), contextKey{}, "request")
			var calls atomic.Int64
			j := factory.newf(t, gojwt.WithClaimsValidator(func(callbackCtx context.Context, c *claims.Claims) error {
				calls.Add(1)
				if callbackCtx.Value(contextKey{}) != "request" {
					return errors.New("request context missing")
				}
				if c.UserID%2 != 0 {
					return policyErr
				}
				return callbackCtx.Err()
			}))
			tokens := make([]string, 8)
			for i := range tokens {
				token, err := j.GenerateToken(int64(i + 1))
				require.NoError(t, err)
				tokens[i] = token
			}
			verifier := j.(gojwt.Verifier)
			results, errs := verifier.ParallelVerifyContext(ctx, tokens)
			for i := range tokens {
				if (i+1)%2 != 0 {
					require.ErrorIs(t, errs[i], policyErr)
					require.Nil(t, results[i])
				} else {
					require.NoError(t, errs[i])
					require.Equal(t, int64(i+1), results[i].UserID)
				}
			}
			require.Equal(t, int64(len(tokens)), calls.Load())
			canceled, cancel := context.WithCancel(ctx)
			cancel()
			for _, parse := range []func(context.Context, string, ...jwtv5.ParserOption) (*claims.Claims, error){
				verifier.ParseTokenContext, verifier.CachedParseTokenContext,
			} {
				got, err := parse(canceled, tokens[1])
				require.Nil(t, got)
				require.ErrorIs(t, err, context.Canceled)
			}
			results, errs = verifier.ParallelVerifyContext(canceled, tokens)
			for i := range tokens {
				require.Nil(t, results[i])
				require.ErrorIs(t, errs[i], context.Canceled)
			}
			require.Equal(t, int64(len(tokens)), calls.Load())
		})
	}
}

func TestClaimsValidatorApplicationProfile(t *testing.T) {
	t.Parallel()
	policyErr := errors.New("subject does not match uid")
	for _, tt := range []struct {
		name      string
		issuer    string
		audience  string
		subject   string
		parseOpts []jwtv5.ParserOption
		wantErr   error
	}{
		{name: "valid", issuer: "auth", audience: "api", subject: "42"},
		{name: "wrong issuer", issuer: "other", audience: "api", subject: "42", wantErr: gojwt.ErrTokenInvalidIssuer},
		{name: "missing issuer", audience: "api", subject: "42", wantErr: gojwt.ErrTokenRequiredClaimMissing},
		{name: "wrong audience", issuer: "auth", audience: "other", subject: "42", wantErr: gojwt.ErrTokenInvalidAudience},
		{name: "missing audience", issuer: "auth", subject: "42", wantErr: gojwt.ErrTokenRequiredClaimMissing},
		{name: "missing subject", issuer: "auth", audience: "api", wantErr: policyErr},
		{name: "wrong subject", issuer: "auth", audience: "api", subject: "7", wantErr: policyErr},
		{name: "parser option cannot skip callback", issuer: "auth", audience: "api", subject: "7", parseOpts: []jwtv5.ParserOption{jwtv5.WithoutClaimsValidation()}, wantErr: policyErr},
	} {
		t.Run(tt.name, func(t *testing.T) {
			secret, err := gojwt.GenerateHMACKeyString(jwtv5.SigningMethodHS256)
			require.NoError(t, err)
			j, err := gojwt.NewJwtHmac([]byte(secret),
				gojwt.WithParserOptions(nil, jwtv5.WithIssuer("auth"), jwtv5.WithAudience("api")),
				gojwt.WithClaimsValidator(func(_ context.Context, c *claims.Claims) error {
					if c.Subject != strconv.FormatInt(c.UserID, 10) {
						return policyErr
					}
					return nil
				}),
			)
			require.NoError(t, err)
			opts := []claims.Option{claims.WithIssuer(tt.issuer), claims.WithSubject(tt.subject)}
			if tt.audience != "" {
				opts = append(opts, claims.WithAudience(tt.audience))
			}
			token, err := j.GenerateToken(42, opts...)
			require.NoError(t, err)
			got, err := j.CachedParseTokenContext(t.Context(), token, tt.parseOpts...)
			if tt.wantErr == nil {
				require.NoError(t, err)
				require.Equal(t, int64(42), got.UserID)
			} else {
				require.Nil(t, got)
				require.ErrorIs(t, err, tt.wantErr)
			}
		})
	}
}
