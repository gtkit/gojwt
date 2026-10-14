package gojwt_test

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"sync"
	"sync/atomic"
	"time"

	jwtv5 "github.com/golang-jwt/jwt/v5"
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

func ExampleJwtHmac_RefreshTokenContext_concurrent() {
	secret, err := gojwt.GenerateHMACKeyString(jwtv5.SigningMethodHS256)
	if err != nil {
		fmt.Println(err)
		return
	}
	// 示例让整个有效期都能刷新，避免等待默认的临期窗口。
	j, err := gojwt.NewJwtHmac([]byte(secret),
		gojwt.WithTokenDuration(30*time.Minute),
		gojwt.WithRefreshWindow(30*time.Minute),
	)
	if err != nil {
		fmt.Println(err)
		return
	}
	oldToken, err := j.GenerateToken(42)
	if err != nil {
		fmt.Println(err)
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// 每个 goroutine 只写自己的结果位置，Wait 后再读取。
	var tokens [2]string
	var errs [2]error
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := range len(tokens) {
		wg.Go(func() {
			<-start
			tokens[i], errs[i] = j.RefreshTokenContext(ctx, oldToken)
		})
	}
	close(start)
	wg.Wait()

	var ids [2]string
	for i, token := range tokens {
		if errs[i] != nil {
			fmt.Println(errs[i])
			return
		}
		c, err := j.ParseTokenContext(ctx, token)
		if err != nil {
			fmt.Println(err)
			return
		}
		ids[i] = c.ID
	}
	_, err = j.ParseTokenContext(ctx, oldToken)
	fmt.Println("different jti:", ids[0] != ids[1])
	fmt.Println("old token valid:", err == nil)
	// Output:
	// different jti: true
	// old token valid: true
}

func ExampleWithRevocationCheck_sessionVersion() {
	secret, err := gojwt.GenerateHMACKeyString(jwtv5.SigningMethodHS256)
	if err != nil {
		fmt.Println(err)
		return
	}
	// 只演示一个会话；生产应用按已验证的会话 ID、用户和租户查询共享存储。
	const sessionID = "example-session"
	var sessionVersion atomic.Int64
	sessionVersion.Store(1)
	j, err := gojwt.NewJwtHmac([]byte(secret),
		gojwt.WithTokenDuration(30*time.Minute),
		gojwt.WithRefreshWindow(30*time.Minute), // 示例立即续签，无需等待临期窗口。
		gojwt.WithRevocationCheck(func(ctx context.Context, c *claims.Claims) (bool, error) {
			if err := ctx.Err(); err != nil {
				return false, err
			}
			id, hasID := c.ExtString("session_id")
			version, hasVersion := c.ExtInt64("session_version")
			// 回调只检查状态，不消费凭证或修改版本。
			return c.UserID != 42 || !hasID || id != sessionID ||
				!hasVersion || version != sessionVersion.Load(), nil
		}),
	)
	if err != nil {
		fmt.Println(err)
		return
	}
	oldToken, err := j.GenerateToken(42,
		claims.WithExt("session_id", sessionID),
		claims.WithExt("session_version", sessionVersion.Load()),
	)
	if err != nil {
		fmt.Println(err)
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	newToken, err := j.RefreshTokenContext(ctx, oldToken)
	if err != nil {
		fmt.Println(err)
		return
	}
	// 先填充解析缓存，后续命中缓存仍会重新检查会话状态。
	for _, token := range []string{oldToken, newToken} {
		if _, err := j.CachedParseTokenContext(ctx, token); err != nil {
			fmt.Println(err)
			return
		}
	}

	// 退出或踢下线由业务方更新版本，旧 token 和所有续签分支一起失效。
	sessionVersion.Add(1)
	_, oldErr := j.CachedParseTokenContext(ctx, oldToken)
	_, newErr := j.CachedParseTokenContext(ctx, newToken)
	_, refreshErr := j.RefreshTokenContext(ctx, newToken)
	fmt.Println("old token revoked:", errors.Is(oldErr, gojwt.ErrTokenBlacklisted))
	fmt.Println("new token revoked:", errors.Is(newErr, gojwt.ErrTokenBlacklisted))
	fmt.Println("refresh rejected:", errors.Is(refreshErr, gojwt.ErrTokenBlacklisted))
	// Output:
	// old token revoked: true
	// new token revoked: true
	// refresh rejected: true
}
