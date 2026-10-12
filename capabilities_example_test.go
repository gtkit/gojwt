package gojwt_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"strconv"

	jwtv5 "github.com/golang-jwt/jwt/v5"
	"github.com/gtkit/gojwt"
	"github.com/gtkit/gojwt/claims"
)

func ExampleWithClaimsValidator() {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		fmt.Println(err)
		return
	}
	issuer, err := gojwt.NewJwtEd25519FromKeys(privateKey, publicKey, gojwt.WithKeyID("k2026"))
	if err != nil {
		fmt.Println(err)
		return
	}
	verifier, err := gojwt.NewJwtEd25519Verifier(publicKey,
		gojwt.WithParserOptions(jwtv5.WithIssuer("auth"), jwtv5.WithAudience("chat-api")),
		gojwt.WithClaimsValidator(func(_ context.Context, c *claims.Claims) error {
			if c.Subject != strconv.FormatInt(c.UserID, 10) {
				return gojwt.ErrTokenInvalidSubject
			}
			return nil
		}),
	)
	if err != nil {
		fmt.Println(err)
		return
	}
	token, err := issuer.GenerateToken(42, claims.WithIssuer("auth"),
		claims.WithAudience("chat-api"), claims.WithSubject("42"))
	if err != nil {
		fmt.Println(err)
		return
	}
	c, err := verifier.CachedParseToken(token)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println(c.UserID)
	_, err = verifier.GenerateToken(42)
	fmt.Println(errors.Is(err, gojwt.ErrNoSigningKey))
	// Output:
	// 42
	// true
}

func ExampleKeyRing() {
	ring := gojwt.NewKeyRing()
	tokens := make([]string, 0, 2)
	for _, kid := range []string{"old", "new"} {
		publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			fmt.Println(err)
			return
		}
		issuer, err := gojwt.NewJwtEd25519FromKeys(privateKey, publicKey, gojwt.WithKeyID(kid))
		if err != nil {
			fmt.Println(err)
			return
		}
		verifier, err := gojwt.NewJwtEd25519Verifier(publicKey)
		if err != nil {
			fmt.Println(err)
			return
		}
		if err := ring.Register(kid, verifier); err != nil {
			fmt.Println(err)
			return
		}
		token, err := issuer.GenerateToken(42)
		if err != nil {
			fmt.Println(err)
			return
		}
		tokens = append(tokens, token)
	}
	for _, token := range tokens {
		c, err := ring.ParseToken(token)
		if err != nil {
			fmt.Println(err)
			return
		}
		fmt.Println(c.UserID)
	}
	// 旧 token 全部过期后，从验签集合移除旧公钥。
	ring.Unregister("old")
	_, err := ring.ParseToken(tokens[0])
	fmt.Println(errors.Is(err, gojwt.ErrUnknownKeyID))
	// Output:
	// 42
	// 42
	// true
}
