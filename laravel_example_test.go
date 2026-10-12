package gojwt_test

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"

	jwtv5 "github.com/golang-jwt/jwt/v5"
	"github.com/gtkit/gojwt"
)

func ExampleNewJwtHmac_laravelHS256() {
	// 生产中双方从安全配置读取同一份 JWT_SECRET；示例每次生成临时随机密钥。
	secret, err := gojwt.GenerateHMACKeyString(jwtv5.SigningMethodHS256)
	if err != nil {
		panic(err)
	}
	now := time.Now().Unix()
	payload, err := json.Marshal(map[string]any{
		"iss": "https://laravel.example.test/login", "sub": 42,
		"iat": now, "nbf": now, "exp": now + 300, "jti": "example-token-id",
	})
	if err != nil {
		panic(err)
	}
	// 独立构造 tymon 风格 payload 的 compact JWT，签名为 RFC 7518 HMAC-SHA256。
	input := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`)) + "." + base64.RawURLEncoding.EncodeToString(payload)
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write([]byte(input))
	raw := input + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	verifier, err := gojwt.NewJwtHmac([]byte(secret),
		gojwt.WithNumericSubject(true),
		gojwt.WithParserOptions(jwtv5.WithIssuer("https://laravel.example.test/login")),
	)
	if err != nil {
		panic(err)
	}
	c, err := verifier.ParseTokenContext(context.Background(), raw)
	if err != nil {
		panic(err)
	}
	fmt.Println(c.Subject, c.TokenID)
	// Output: 42 example-token-id
}
