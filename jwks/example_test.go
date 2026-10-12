package jwks_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"net/http"
	"time"

	jwtv5 "github.com/golang-jwt/jwt/v5"
	"github.com/gtkit/gojwt"
	"github.com/gtkit/gojwt/claims"
	"github.com/gtkit/gojwt/jwks"
)

func exampleSignedToken() (*jwks.Set, string) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	public, err := jwks.NewKey("auth-2026", &key.PublicKey, "RS256")
	if err != nil {
		panic(err)
	}
	set, err := jwks.NewSet(public)
	if err != nil {
		panic(err)
	}
	issuer, err := gojwt.NewJwtRSAFromKeys(key, &key.PublicKey, gojwt.WithKeyID("auth-2026"))
	if err != nil {
		panic(err)
	}
	token, err := issuer.GenerateToken(42, claims.WithIssuer("https://auth.example"), claims.WithAudience("api"))
	if err != nil {
		panic(err)
	}
	return set, token
}

func ExampleNewSet() {
	set, token := exampleSignedToken()
	verifier, err := gojwt.NewVerifier(set, []string{"RS256"}, gojwt.WithParserOptions(
		jwtv5.WithIssuer("https://auth.example"), jwtv5.WithAudience("api"),
	))
	if err != nil {
		panic(err)
	}
	parsed, err := verifier.ParseToken(token)
	if err != nil {
		panic(err)
	}
	fmt.Println(parsed.UserID)
	// Output: 42
}

func ExampleNewRemote() {
	set, token := exampleSignedToken()
	data, err := set.MarshalJSON()
	if err != nil {
		panic(err)
	}
	// An injected transport keeps this runnable example independent of a server.
	// Production may omit WithClient to use the default HTTPS client.
	client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		return response(r, http.StatusOK, string(data)), nil
	})}
	remote, err := jwks.NewRemote("https://auth.example/.well-known/jwks.json",
		jwks.WithClient(client), jwks.WithTTL(5*time.Minute),
	)
	if err != nil {
		panic(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	// Refresh permits an explicit initial sync or an application-triggered rotation.
	// ResolveKey also refreshes on demand when its snapshot expires; no background loop.
	if err := remote.Refresh(ctx); err != nil {
		panic(err)
	}
	verifier, err := gojwt.NewVerifier(remote, []string{"RS256"}, gojwt.WithParserOptions(
		jwtv5.WithIssuer("https://auth.example"), jwtv5.WithAudience("api"),
	))
	if err != nil {
		panic(err)
	}
	parsed, err := verifier.ParseTokenContext(ctx, token)
	if err != nil {
		panic(err)
	}
	fmt.Println(parsed.UserID)
	// Output: 42
}
