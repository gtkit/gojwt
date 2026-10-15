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

func ExampleBlacklist_AddTokenWithLeeway() {
	secret, err := gojwt.GenerateHMACKeyString(jwtv5.SigningMethodHS256)
	if err != nil {
		fmt.Println(err)
		return
	}
	blacklist := gojwt.NewBlacklist()
	const maximumLeeway = 30 * time.Second // 应用配置：覆盖所有验证方允许的最大容忍时间。
	j, err := gojwt.NewJwtHmac([]byte(secret), gojwt.WithParseLeeway(maximumLeeway), gojwt.WithBlacklistFunc(blacklist.In))
	if err != nil {
		fmt.Println(err)
		return
	}
	token, err := j.GenerateToken(42)
	if err != nil {
		fmt.Println(err)
		return
	}
	c, err := j.CachedParseToken(token)
	if err != nil {
		fmt.Println(err)
		return
	}
	// 默认 AddToken 使用 5 秒；应用使用 30 秒 leeway 时显式同步吊销保留时间。
	if err := blacklist.AddTokenWithLeeway(c, maximumLeeway); err != nil {
		fmt.Println(err)
		return
	}
	_, parseErr := j.CachedParseToken(token)
	_, refreshErr := j.RefreshToken(token)
	fmt.Println("cached token revoked:", errors.Is(parseErr, gojwt.ErrTokenBlacklisted))
	fmt.Println("refresh rejected:", errors.Is(refreshErr, gojwt.ErrTokenBlacklisted))
	// Output:
	// cached token revoked: true
	// refresh rejected: true
}

func ExampleJwtHmac_GenerateToken_expiration() {
	secret, err := gojwt.GenerateHMACKeyString(jwtv5.SigningMethodHS256)
	if err != nil {
		fmt.Println(err)
		return
	}
	j, err := gojwt.NewJwtHmac([]byte(secret), gojwt.WithTokenDuration(500*time.Millisecond), gojwt.WithParseLeeway(0))
	if err != nil {
		fmt.Println(err)
		return
	}
	var issuedAt time.Time
	token, err := j.GenerateToken(42, func(c *claims.Claims) { issuedAt = c.IssuedAt.Time })
	if err != nil {
		fmt.Println(err)
		return
	}
	// 固定校验时钟只用于这个边界演示；生产鉴权使用可信的真实服务端时钟。
	c, err := j.ParseToken(token, jwtv5.WithTimeFunc(func() time.Time { return issuedAt }))
	if err != nil {
		fmt.Println(err)
		return
	}
	_, beforeErr := j.ParseToken(token, jwtv5.WithTimeFunc(func() time.Time { return c.ExpiresAt.Add(-time.Nanosecond) }))
	_, atErr := j.ParseToken(token, jwtv5.WithTimeFunc(func() time.Time { return c.ExpiresAt.Time }))
	fmt.Println("lifetime:", c.ExpiresAt.Sub(c.IssuedAt.Time))
	fmt.Println("valid before exp:", beforeErr == nil)
	fmt.Println("expired at exp:", errors.Is(atErr, gojwt.ErrTokenExpired))
	// Output:
	// lifetime: 500ms
	// valid before exp: true
	// expired at exp: true
}

// 示例应用的策略；实际截止时间从应用存储读取，按用户和租户隔离。
func examplePasswordChangeRevoked(c *claims.Claims, cutoff time.Time) bool {
	origin := c.AuthTime
	if origin == nil {
		origin = c.IssuedAt // 兼容尚未携带 auth_time 的旧 token。
	}
	return origin == nil || origin.Before(cutoff)
}

func ExampleWithRevocationCheck_passwordChange() {
	secret, err := gojwt.GenerateHMACKeyString(jwtv5.SigningMethodHS256)
	if err != nil {
		fmt.Println(err)
		return
	}
	var cutoff atomic.Int64
	entered, resume := make(chan struct{}), make(chan struct{})
	var pause atomic.Bool
	j, err := gojwt.NewJwtHmac([]byte(secret), gojwt.WithTokenDuration(30*time.Minute),
		gojwt.WithRefreshWindow(30*time.Minute),
		gojwt.WithRevocationCheck(func(ctx context.Context, c *claims.Claims) (bool, error) {
			// 模拟外部查询读到了改密前的截止时间。
			snapshot := cutoff.Load()
			if pause.CompareAndSwap(true, false) {
				close(entered)
				select {
				case <-resume:
				case <-ctx.Done():
					return false, ctx.Err()
				}
			}
			return examplePasswordChangeRevoked(c, time.Unix(0, snapshot)), nil
		}))
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
	pause.Store(true)
	var newToken string
	var refreshErr error
	var wg sync.WaitGroup
	wg.Go(func() { newToken, refreshErr = j.RefreshTokenContext(ctx, oldToken) })
	select {
	case <-entered:
	case <-ctx.Done():
		wg.Wait()
		fmt.Println(ctx.Err())
		return
	}
	// 改密在查询与签发之间发生；会话版本/时间戳更新应与密码更新在应用事务中提交。
	cutoff.Store(time.Now().UnixNano())
	close(resume)
	wg.Wait()
	if refreshErr != nil {
		fmt.Println(refreshErr)
		return
	}
	// 新 iat 不会改变旧 auth_time，两个 token 的后续鉴权都被拒绝。
	_, oldErr := j.ParseTokenContext(ctx, oldToken)
	_, newErr := j.ParseTokenContext(ctx, newToken)
	fmt.Println("old session revoked:", errors.Is(oldErr, gojwt.ErrTokenBlacklisted))
	fmt.Println("concurrent renewal revoked:", errors.Is(newErr, gojwt.ErrTokenBlacklisted))
	// Output:
	// old session revoked: true
	// concurrent renewal revoked: true
}
