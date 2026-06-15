package gojwt_test

import (
	"fmt"
	"log"
	"os"

	"github.com/gtkit/gojwt"
	"github.com/gtkit/gojwt/claims"
)

func ExampleNewJwtHmac() {
	key := []byte("your-32-byte-hmac-secret-key-here!")
	j, err := gojwt.NewJwtHmac(key)
	if err != nil {
		log.Fatal(err)
	}

	token, err := j.GenerateToken(42,
		claims.WithRole("admin"),
		claims.WithPrv("web"),
	)
	if err != nil {
		log.Fatal(err)
	}

	c, err := j.ParseToken(token)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(c.UserID)
	fmt.Println(c.Prv)
	fmt.Println(c.Roles)
	// Output:
	// 42
	// web
	// [admin]
}

func ExampleJwtHmac_CachedParseToken() {
	key := []byte("your-32-byte-hmac-secret-key-here!")
	j, err := gojwt.NewJwtHmac(key)
	if err != nil {
		log.Fatal(err)
	}

	token, err := j.GenerateToken(1)
	if err != nil {
		log.Fatal(err)
	}

	// 首次解析（写入缓存）
	c1, err := j.CachedParseToken(token)
	if err != nil {
		log.Fatal(err)
	}

	// 第二次解析（缓存命中，避免重复签名验证）
	c2, err := j.CachedParseToken(token)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(c1.UserID == c2.UserID)
	// Output:
	// true
}

func ExampleNewJwtEd25519() {
	dir, err := os.MkdirTemp("", "gojwt-example")
	if err != nil {
		log.Fatal(err)
	}
	defer func() { _ = os.RemoveAll(dir) }()

	priPath := dir + "/ed25519.pem"
	pubPath := dir + "/ed25519.pub.pem"

	if err := gojwt.GenerateEd25519Keys(priPath, pubPath); err != nil {
		log.Fatal(err)
	}

	j, err := gojwt.NewJwtEd25519(priPath, pubPath)
	if err != nil {
		log.Fatal(err)
	}

	token, err := j.GenerateToken(100, claims.WithRoles("editor"))
	if err != nil {
		log.Fatal(err)
	}

	c, err := j.ParseToken(token)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(c.UserID)
	// Output:
	// 100
}

func ExampleNewBlacklist() {
	blacklist := gojwt.NewBlacklist()
	blacklist.Add("revoked-token-id")

	fmt.Println(blacklist.In("revoked-token-id"))
	fmt.Println(blacklist.In("unknown-token-id"))
	// Output:
	// true
	// false
}

func ExampleWithBlacklistFunc() {
	blacklist := gojwt.NewBlacklist()
	key := []byte("your-32-byte-hmac-secret-key-here!")

	j, err := gojwt.NewJwtHmac(key, gojwt.WithBlacklistFunc(blacklist.In))
	if err != nil {
		log.Fatal(err)
	}

	token, err := j.GenerateToken(10)
	if err != nil {
		log.Fatal(err)
	}

	// 解析后拿到 TokenID，加入黑名单
	c, err := j.ParseToken(token)
	if err != nil {
		log.Fatal(err)
	}
	blacklist.Add(c.TokenID)

	// 再次解析应被黑名单拦截
	_, err = j.ParseToken(token)
	fmt.Println(err)
	// Output:
	// Token 已被注销
}
