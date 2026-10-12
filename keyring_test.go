package gojwt_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	jwtv5 "github.com/golang-jwt/jwt/v5"
	"github.com/gtkit/gojwt"
	"github.com/gtkit/gojwt/claims"
	"github.com/stretchr/testify/require"
)

func keyRingEd25519(t *testing.T, kid string) (*gojwt.JwtEd25519, *gojwt.JwtEd25519) {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	issuer, err := gojwt.NewJwtEd25519FromKeys(privateKey, publicKey, gojwt.WithKeyID(kid))
	require.NoError(t, err)
	verifier, err := gojwt.NewJwtEd25519Verifier(publicKey)
	require.NoError(t, err)
	return issuer, verifier
}

type keyRingParseMethod struct {
	name string
	call func(*gojwt.KeyRing, string, ...jwtv5.ParserOption) (*claims.Claims, error)
}

func keyRingParseMethods() []keyRingParseMethod {
	return []keyRingParseMethod{
		{name: "parse", call: (*gojwt.KeyRing).ParseToken},
		{name: "cached", call: (*gojwt.KeyRing).CachedParseToken},
	}
}

func TestKeyRingEd25519Rotation(t *testing.T) {
	for _, method := range keyRingParseMethods() {
		t.Run(method.name, func(t *testing.T) {
			oldIssuer, oldVerifier := keyRingEd25519(t, "old")
			newIssuer, newVerifier := keyRingEd25519(t, "new")
			ring := gojwt.NewKeyRing()
			require.NoError(t, ring.Register("old", oldVerifier))
			require.NoError(t, ring.Register("new", newVerifier))
			for _, tc := range []struct {
				name   string
				issuer *gojwt.JwtEd25519
				uid    int64
			}{
				{name: "old public key", issuer: oldIssuer, uid: 10},
				{name: "new public key", issuer: newIssuer, uid: 20},
			} {
				t.Run(tc.name, func(t *testing.T) {
					token, err := tc.issuer.GenerateToken(tc.uid, claims.WithIssuer("auth"), claims.WithAudience("api"))
					require.NoError(t, err)
					parsed, err := method.call(ring, token, jwtv5.WithIssuer("auth"), jwtv5.WithAudience("api"))
					require.NoError(t, err)
					require.Equal(t, tc.uid, parsed.UserID)
					_, err = method.call(ring, token, jwtv5.WithAudience("other-api"))
					require.ErrorIs(t, err, gojwt.ErrTokenInvalidAudience)
				})
			}
		})
	}
}

func TestKeyRingZeroValueAndRegistration(t *testing.T) {
	issuer, verifier := keyRingEd25519(t, "key")
	token, err := issuer.GenerateToken(42)
	require.NoError(t, err)
	for _, tc := range []struct {
		name string
		run  func(*testing.T)
	}{
		{name: "zero value registers", run: func(t *testing.T) {
			var ring gojwt.KeyRing
			ring.Unregister("absent")
			_, err := ring.ParseToken(token)
			require.ErrorIs(t, err, gojwt.ErrUnknownKeyID)
			require.NoError(t, ring.Register("key", verifier))
			parsed, err := ring.ParseToken(token)
			require.NoError(t, err)
			require.Equal(t, int64(42), parsed.UserID)
		}},
		{name: "nil verifier rejected", run: func(t *testing.T) {
			var ring gojwt.KeyRing
			require.ErrorIs(t, ring.Register("key", nil), gojwt.ErrInvalidConfig)
			_, err := ring.CachedParseToken(token)
			require.ErrorIs(t, err, gojwt.ErrUnknownKeyID)
		}},
		{name: "nil receiver", run: func(t *testing.T) {
			var ring *gojwt.KeyRing
			require.ErrorIs(t, ring.Register("key", verifier), gojwt.ErrJWTNotInit)
			ring.Unregister("key")
			for _, method := range keyRingParseMethods() {
				parsed, err := method.call(ring, token)
				require.Nil(t, parsed)
				require.ErrorIs(t, err, gojwt.ErrJWTNotInit)
			}
			parsed, err := ring.ParseTokenContext(t.Context(), token)
			require.Nil(t, parsed)
			require.ErrorIs(t, err, gojwt.ErrJWTNotInit)
			parsed, err = ring.CachedParseTokenContext(t.Context(), token)
			require.Nil(t, parsed)
			require.ErrorIs(t, err, gojwt.ErrJWTNotInit)
			for _, tokens := range [][]string{nil, {token, token}} {
				results, errs := ring.ParallelVerify(tokens)
				require.Len(t, results, len(tokens))
				require.Len(t, errs, len(tokens))
				for i := range tokens {
					require.Nil(t, results[i])
					require.ErrorIs(t, errs[i], gojwt.ErrJWTNotInit)
				}
				results, errs = ring.ParallelVerifyContext(t.Context(), tokens)
				require.Len(t, results, len(tokens))
				require.Len(t, errs, len(tokens))
				for i := range tokens {
					require.Nil(t, results[i])
					require.ErrorIs(t, errs[i], gojwt.ErrJWTNotInit)
				}
			}
		}},
	} {
		t.Run(tc.name, tc.run)
	}
}

func TestKeyRingRequiresExactKeyID(t *testing.T) {
	for _, method := range keyRingParseMethods() {
		for _, tc := range []struct {
			name string
			kid  string
		}{
			{name: "unknown kid does not fall back", kid: "unknown"},
			{name: "unkeyed token needs explicit registration", kid: ""},
		} {
			t.Run(method.name+"/"+tc.name, func(t *testing.T) {
				issuer, verifier := keyRingEd25519(t, tc.kid)
				token, err := issuer.GenerateToken(42)
				require.NoError(t, err)
				ring := gojwt.NewKeyRing()
				require.NoError(t, ring.Register("different", verifier))
				if tc.kid != "" {
					require.NoError(t, ring.Register("", verifier))
				}
				parsed, err := method.call(ring, token)
				require.Nil(t, parsed)
				require.ErrorIs(t, err, gojwt.ErrUnknownKeyID)
				require.NoError(t, ring.Register(tc.kid, verifier))
				parsed, err = method.call(ring, token)
				require.NoError(t, err)
				require.Equal(t, int64(42), parsed.UserID)
			})
		}
	}
}

func TestKeyRingOverwriteAndUnregisterInvalidateSelection(t *testing.T) {
	for _, method := range keyRingParseMethods() {
		t.Run(method.name, func(t *testing.T) {
			oldIssuer, oldVerifier := keyRingEd25519(t, "same-kid")
			newIssuer, newVerifier := keyRingEd25519(t, "same-kid")
			oldToken, err := oldIssuer.GenerateToken(10)
			require.NoError(t, err)
			newToken, err := newIssuer.GenerateToken(20)
			require.NoError(t, err)
			ring := gojwt.NewKeyRing()
			require.NoError(t, ring.Register("same-kid", oldVerifier))
			_, err = ring.CachedParseToken(oldToken)
			require.NoError(t, err)
			require.NoError(t, ring.Register("same-kid", newVerifier))
			parsed, err := method.call(ring, oldToken)
			require.Nil(t, parsed)
			require.ErrorIs(t, err, gojwt.ErrTokenSignatureInvalid)
			parsed, err = method.call(ring, newToken)
			require.NoError(t, err)
			require.Equal(t, int64(20), parsed.UserID)
			_, err = ring.CachedParseToken(newToken)
			require.NoError(t, err)
			ring.Unregister("same-kid")
			parsed, err = method.call(ring, newToken)
			require.Nil(t, parsed)
			require.ErrorIs(t, err, gojwt.ErrUnknownKeyID)
		})
	}
}

type keyRingContextMethod struct {
	name string
	call func(*gojwt.KeyRing, context.Context, string, ...jwtv5.ParserOption) (*claims.Claims, error)
}

func keyRingContextMethods() []keyRingContextMethod {
	return []keyRingContextMethod{
		{name: "parse", call: (*gojwt.KeyRing).ParseTokenContext},
		{name: "cached", call: (*gojwt.KeyRing).CachedParseTokenContext},
	}
}

type keyRingVerifierFunc struct {
	gojwt.Verifier
	parse func(context.Context, string, ...jwtv5.ParserOption) (*claims.Claims, error)
}

func (v *keyRingVerifierFunc) ParseTokenContext(ctx context.Context, token string, opts ...jwtv5.ParserOption) (*claims.Claims, error) {
	return v.parse(ctx, token, opts...)
}

func (v *keyRingVerifierFunc) CachedParseTokenContext(ctx context.Context, token string, opts ...jwtv5.ParserOption) (*claims.Claims, error) {
	return v.parse(ctx, token, opts...)
}

func TestKeyRingContextCancellationPriority(t *testing.T) {
	for _, method := range keyRingContextMethods() {
		for _, tc := range []struct {
			name string
			ctx  func(*testing.T) (context.Context, context.CancelFunc)
			want error
		}{
			{name: "canceled", ctx: func(t *testing.T) (context.Context, context.CancelFunc) {
				ctx, cancel := context.WithCancel(t.Context())
				cancel()
				return ctx, cancel
			}, want: context.Canceled},
			{name: "deadline", ctx: func(t *testing.T) (context.Context, context.CancelFunc) {
				return context.WithDeadline(t.Context(), time.Now().Add(-time.Second))
			}, want: context.DeadlineExceeded},
		} {
			t.Run(method.name+"/"+tc.name, func(t *testing.T) {
				ctx, cancel := tc.ctx(t)
				defer cancel()
				var calls atomic.Int32
				ring := gojwt.NewKeyRing()
				require.NoError(t, ring.Register("key", &keyRingVerifierFunc{parse: func(context.Context, string, ...jwtv5.ParserOption) (*claims.Claims, error) {
					calls.Add(1)
					return &claims.Claims{UserID: 42}, nil
				}}))
				for _, token := range []string{"", "invalid", keyIDHeaderToken(`{"kid":"unknown"}`), keyIDHeaderToken(`{"kid":"key"}`)} {
					parsed, err := method.call(ring, ctx, token)
					require.Nil(t, parsed)
					require.ErrorIs(t, err, tc.want)
				}
				require.Zero(t, calls.Load())
			})
		}
	}
}

func TestKeyRingNilContextIsNormalized(t *testing.T) {
	for _, method := range keyRingContextMethods() {
		t.Run(method.name, func(t *testing.T) {
			ring := gojwt.NewKeyRing()
			require.NoError(t, ring.Register("key", &keyRingVerifierFunc{parse: func(ctx context.Context, _ string, _ ...jwtv5.ParserOption) (*claims.Claims, error) {
				require.NotNil(t, ctx)
				require.NoError(t, ctx.Err())
				return &claims.Claims{UserID: 42}, nil
			}}))
			parsed, err := method.call(ring, nil, keyIDHeaderToken(`{"kid":"key"}`))
			require.NoError(t, err)
			require.Equal(t, int64(42), parsed.UserID)
		})
	}
}

func TestKeyRingParallelVerifyOrder(t *testing.T) {
	for _, tc := range []struct {
		name string
		call func(*gojwt.KeyRing, context.Context, []string) ([]*claims.Claims, []error)
	}{
		{name: "background", call: func(r *gojwt.KeyRing, _ context.Context, tokens []string) ([]*claims.Claims, []error) {
			return r.ParallelVerify(tokens)
		}},
		{name: "context", call: func(r *gojwt.KeyRing, ctx context.Context, tokens []string) ([]*claims.Claims, []error) {
			return r.ParallelVerifyContext(ctx, tokens)
		}},
		{name: "nil context", call: func(r *gojwt.KeyRing, _ context.Context, tokens []string) ([]*claims.Claims, []error) {
			return r.ParallelVerifyContext(nil, tokens) //nolint:staticcheck // SA1012: exercise the supported nil-context path.
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			oldIssuer, oldVerifier := keyRingEd25519(t, "old")
			newIssuer, newVerifier := keyRingEd25519(t, "new")
			oldToken, err := oldIssuer.GenerateToken(10)
			require.NoError(t, err)
			newToken, err := newIssuer.GenerateToken(20)
			require.NoError(t, err)
			ring := gojwt.NewKeyRing()
			require.NoError(t, ring.Register("old", oldVerifier))
			require.NoError(t, ring.Register("new", newVerifier))
			tokens := []string{newToken, "malformed", oldToken, keyIDHeaderToken(`{"kid":"unknown"}`), newToken}
			results, errs := tc.call(ring, t.Context(), tokens)
			require.Len(t, results, len(tokens))
			require.Len(t, errs, len(tokens))
			for i, want := range []int64{20, 0, 10, 0, 20} {
				if want == 0 {
					require.Nil(t, results[i])
					continue
				}
				require.NoError(t, errs[i])
				require.Equal(t, want, results[i].UserID)
			}
			require.ErrorIs(t, errs[1], gojwt.ErrTokenMalformed)
			require.ErrorIs(t, errs[3], gojwt.ErrUnknownKeyID)
			results, errs = tc.call(ring, t.Context(), nil)
			require.Empty(t, results)
			require.Empty(t, errs)
		})
	}
}

func TestKeyRingConcurrentRegistrationAndParsing(t *testing.T) {
	for _, method := range keyRingParseMethods() {
		t.Run(method.name, func(t *testing.T) {
			issuer, verifier := keyRingEd25519(t, "key")
			token, err := issuer.GenerateToken(42)
			require.NoError(t, err)
			var ring gojwt.KeyRing
			const workers = 8
			const iterations = 30
			failures := make(chan error, workers*iterations)
			start := make(chan struct{})
			var wg sync.WaitGroup
			for worker := range workers {
				wg.Go(func() {
					<-start
					for range iterations {
						if worker%2 == 0 {
							if err := ring.Register("key", verifier); err != nil {
								failures <- err
							}
							continue
						}
						if worker%3 == 0 {
							ring.Unregister("key")
							continue
						}
						parsed, err := method.call(&ring, token)
						if err != nil {
							if !errors.Is(err, gojwt.ErrUnknownKeyID) {
								failures <- err
							}
						} else if parsed == nil || parsed.UserID != 42 {
							failures <- fmt.Errorf("unexpected claims: %v", parsed)
						}
					}
				})
			}
			close(start)
			wg.Wait()
			close(failures)
			for err := range failures {
				t.Error(err)
			}
			require.NoError(t, ring.Register("key", verifier))
			parsed, err := method.call(&ring, token)
			require.NoError(t, err)
			require.Equal(t, int64(42), parsed.UserID)
		})
	}
}

func TestKeyRingRegistrationDoesNotLockVerifierCall(t *testing.T) {
	for _, method := range keyRingContextMethods() {
		t.Run(method.name, func(t *testing.T) {
			started := make(chan struct{})
			release := make(chan struct{})
			var releaseOnce sync.Once
			defer releaseOnce.Do(func() { close(release) })
			parsedDone := make(chan error, 1)
			ring := gojwt.NewKeyRing()
			require.NoError(t, ring.Register("key", &keyRingVerifierFunc{parse: func(context.Context, string, ...jwtv5.ParserOption) (*claims.Claims, error) {
				close(started)
				<-release
				return &claims.Claims{UserID: 42}, nil
			}}))
			go func() {
				_, err := method.call(ring, t.Context(), keyIDHeaderToken(`{"kid":"key"}`))
				parsedDone <- err
			}()
			<-started
			mutationDone := make(chan error, 1)
			go func() {
				ring.Unregister("key")
				mutationDone <- ring.Register("replacement", &keyRingVerifierFunc{})
			}()
			select {
			case err := <-mutationDone:
				require.NoError(t, err)
			case <-time.After(time.Second):
				t.Fatal("Register/Unregister waited for an in-flight verifier call")
			}
			releaseOnce.Do(func() { close(release) })
			require.NoError(t, <-parsedDone)
			_, err := method.call(ring, t.Context(), keyIDHeaderToken(`{"kid":"key"}`))
			require.ErrorIs(t, err, gojwt.ErrUnknownKeyID)
		})
	}
}

func TestKeyRingParallelVerifyCanceled(t *testing.T) {
	for _, tc := range []struct {
		name   string
		tokens []string
	}{
		{name: "empty"},
		{name: "one", tokens: []string{"invalid"}},
		{name: "mixed", tokens: []string{"", "invalid", keyIDHeaderToken(`{"kid":"key"}`)}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			cancel()
			ring := gojwt.NewKeyRing()
			var calls atomic.Int32
			require.NoError(t, ring.Register("key", &keyRingVerifierFunc{parse: func(context.Context, string, ...jwtv5.ParserOption) (*claims.Claims, error) {
				calls.Add(1)
				return &claims.Claims{UserID: 42}, nil
			}}))
			results, errs := ring.ParallelVerifyContext(ctx, tc.tokens)
			require.Len(t, results, len(tc.tokens))
			require.Len(t, errs, len(tc.tokens))
			for i := range tc.tokens {
				require.Nil(t, results[i])
				require.ErrorIs(t, errs[i], context.Canceled)
			}
			require.Zero(t, calls.Load())
		})
	}
}
