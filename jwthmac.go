package gojwt

import (
	"fmt"
	"sync"
	"time"

	jwtv5 "github.com/golang-jwt/jwt/v5"
	"github.com/gtkit/gojwt/claims"
)

type JwtHmac struct {
	secretKey []byte
	duration
	cache claimsCache
}

const minHMACKeySize = 32

func NewJwtHmac(secretKey []byte, options ...Option) (*JwtHmac, error) {
	if len(secretKey) < minHMACKeySize {
		return nil, fmt.Errorf("secret key must be at least %d bytes, got %d", minHMACKeySize, len(secretKey))
	}

	j := &JwtHmac{
		secretKey: append([]byte(nil), secretKey...),
		duration: duration{
			tokenDuration:   2 * time.Hour,
			refreshDuration: 7 * 24 * time.Hour,
		},
	}
	for _, opt := range options {
		opt(&j.duration)
	}

	return j, nil
}

func (j *JwtHmac) GenerateToken(uid int64, options ...claims.Option) (string, error) {
	if j == nil {
		return "", ErrJWTNotInit
	}
	tokenID, err := generateTokenID()
	if err != nil {
		return "", err
	}

	now := time.Now()
	tokenClaims := &claims.Claims{
		UserID:  uid,
		TokenID: tokenID,
		RegisteredClaims: jwtv5.RegisteredClaims{
			ExpiresAt: jwtv5.NewNumericDate(now.Add(j.tokenDuration)),
			NotBefore: jwtv5.NewNumericDate(now),
			IssuedAt:  jwtv5.NewNumericDate(now),
			ID:        tokenID,
		},
	}

	for _, opt := range options {
		opt(tokenClaims)
	}

	token, err := createHmacToken(*tokenClaims, j.secretKey)
	if err != nil {
		return "", err
	}

	return token, nil
}

func (j *JwtHmac) RefreshToken(tokenString string, opt ...jwtv5.ParserOption) (string, error) {
	if j == nil {
		return "", ErrJWTNotInit
	}
	tokenClaims, err := j.ParseToken(tokenString, opt...)
	if err != nil {
		return "", err
	}

	if err := refreshTokenClaims(tokenClaims, j.tokenDuration, j.refreshDuration); err != nil {
		return "", err
	}

	tokenClaims.RegisteredClaims.ID = tokenClaims.TokenID
	return createHmacToken(*tokenClaims, j.secretKey)
}

func (j *JwtHmac) ParseToken(tokenString string, opt ...jwtv5.ParserOption) (*claims.Claims, error) {
	if j == nil {
		return nil, ErrJWTNotInit
	}
	if tokenString == "" {
		return nil, ErrTokenMalformed
	}
	token, err := jwtv5.ParseWithClaims(tokenString, &claims.Claims{}, func(token *jwtv5.Token) (any, error) {
		if _, ok := token.Method.(*jwtv5.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return j.secretKey, nil
	}, opt...)
	if err != nil {
		return nil, normalizeParseError(err)
	}

	if c, ok := token.Claims.(*claims.Claims); ok && token.Valid {
		return c, nil
	}
	return nil, ErrTokenInvalid
}

func (j *JwtHmac) CachedParseToken(tokenString string, opt ...jwtv5.ParserOption) (*claims.Claims, error) {
	if j == nil {
		return nil, ErrJWTNotInit
	}
	if tokenString == "" {
		return nil, ErrTokenMalformed
	}

	if c, ok := loadCachedClaims(&j.cache, tokenString); ok {
		return c, nil
	}

	tokenClaims, err := j.ParseToken(tokenString, opt...)
	if err != nil {
		return nil, err
	}

	storeCachedClaims(&j.cache, tokenString, tokenClaims)
	return tokenClaims, nil
}

func (j *JwtHmac) ParallelVerify(tokens []string, opt ...jwtv5.ParserOption) ([]*claims.Claims, []error) {
	var wg sync.WaitGroup
	results := make([]*claims.Claims, len(tokens))
	errs := make([]error, len(tokens))

	for i, token := range tokens {
		wg.Go(func() {
			tokenClaims, err := j.ParseToken(token, opt...)
			results[i] = tokenClaims
			errs[i] = err
		})
	}

	wg.Wait()
	return results, errs
}

func createHmacToken(claims claims.Claims, signKey any) (string, error) {
	return jwtv5.NewWithClaims(jwtv5.SigningMethodHS256, claims).SignedString(signKey)
}
