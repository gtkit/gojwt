package gojwt

import (
	"context"
	"fmt"
	"sync"

	jwtv5 "github.com/golang-jwt/jwt/v5"
	"github.com/gtkit/gojwt/claims"
)

// KeyRing 按 kid 汇集多个验签方：解析时用 ParseKeyID 取出 token 的 kid，再委托给对应的 Verifier 验签。
// 空 kid 对应"未携带 kid 的 token"。KeyRing 的零值可直接使用，
// 实现 Verifier，可被多个 goroutine 并发使用；使用后不得复制。
//
// Register / Unregister 可在运行期调用，密钥轮换的典型流程是：
// 先注册新 kid 的实例并让签发方切到新密钥，等旧 kid 签出的 token 全部过期后再注销旧 kid。
// 已选中验签方的解析可以继续完成，后续解析使用新的注册状态。
//
//	ring := gojwt.NewKeyRing()
//	_ = ring.Register("app-2025", oldJwt)
//	_ = ring.Register("app-2026", newJwt)
//	cc, err := ring.ParseToken(tokenString) // 按 kid 选键并验签
type KeyRing struct {
	mu        sync.RWMutex
	verifiers map[string]Verifier
}

// NewKeyRing 创建一个空的 KeyRing。
func NewKeyRing() *KeyRing {
	return &KeyRing{verifiers: make(map[string]Verifier)}
}

// Register 注册 kid 对应的验签方，kid 已存在时覆盖。
// kid 为空字符串表示用于未携带 kid 的 token。v 为 nil 返回 ErrInvalidConfig。
func (r *KeyRing) Register(kid string, v Verifier) error {
	if r == nil {
		return ErrJWTNotInit
	}
	if isNilValue(v) {
		return fmt.Errorf("%w: verifier for kid %q must not be nil", ErrInvalidConfig, kid)
	}
	r.mu.Lock()
	if r.verifiers == nil {
		r.verifiers = make(map[string]Verifier)
	}
	r.verifiers[kid] = v
	r.mu.Unlock()
	return nil
}

// Unregister 注销 kid 对应的验签方，之后携带该 kid 的 token 解析返回 ErrUnknownKeyID。
func (r *KeyRing) Unregister(kid string) {
	if r == nil {
		return
	}
	r.mu.Lock()
	delete(r.verifiers, kid)
	r.mu.Unlock()
}

// verifierFor 读出 token 的 kid 并定位验签方；kid 未注册返回 ErrUnknownKeyID。
func (r *KeyRing) verifierFor(tokenString string) (Verifier, error) {
	kid, err := ParseKeyID(tokenString)
	if err != nil {
		return nil, err
	}
	r.mu.RLock()
	v, ok := r.verifiers[kid]
	r.mu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("%w: %q", ErrUnknownKeyID, kid)
	}
	return v, nil
}

// ParseToken 按 kid 选键后解析并验证 JWT token。
func (r *KeyRing) ParseToken(tokenString string, opt ...jwtv5.ParserOption) (*claims.Claims, error) {
	return r.ParseTokenContext(context.Background(), tokenString, opt...)
}

// ParseTokenContext 按 kid 选键后解析并验证 JWT token，并尊重 ctx 取消和 deadline。
func (r *KeyRing) ParseTokenContext(ctx context.Context, tokenString string, opt ...jwtv5.ParserOption) (*claims.Claims, error) {
	if r == nil {
		return nil, ErrJWTNotInit
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	v, err := r.verifierFor(tokenString)
	if err != nil {
		return nil, err
	}
	return v.ParseTokenContext(ctx, tokenString, opt...)
}

// CachedParseToken 按 kid 选键后走对应实例的缓存解析。
func (r *KeyRing) CachedParseToken(tokenString string, opt ...jwtv5.ParserOption) (*claims.Claims, error) {
	return r.CachedParseTokenContext(context.Background(), tokenString, opt...)
}

// CachedParseTokenContext 按 kid 选键后走对应实例的缓存解析，并尊重 ctx 取消和 deadline。
func (r *KeyRing) CachedParseTokenContext(ctx context.Context, tokenString string, opt ...jwtv5.ParserOption) (*claims.Claims, error) {
	if r == nil {
		return nil, ErrJWTNotInit
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	v, err := r.verifierFor(tokenString)
	if err != nil {
		return nil, err
	}
	return v.CachedParseTokenContext(ctx, tokenString, opt...)
}

// ParallelVerify 并发验证多个 token，逐个按 kid 选键。
// results[i] 与 errs[i] 对应同一个输入 tokens[i]。
func (r *KeyRing) ParallelVerify(tokens []string, opt ...jwtv5.ParserOption) ([]*claims.Claims, []error) {
	return r.ParallelVerifyContext(context.Background(), tokens, opt...)
}

// ParallelVerifyContext 并发验证多个 token，逐个按 kid 选键，并在 ctx 取消后停止分发未开始的任务。
// results[i] 与 errs[i] 对应同一个输入 tokens[i]。
func (r *KeyRing) ParallelVerifyContext(ctx context.Context, tokens []string, opt ...jwtv5.ParserOption) ([]*claims.Claims, []error) {
	if r == nil {
		return notInitResults(len(tokens))
	}
	return parallelVerifyImplContext(ctx, tokens, opt, r.ParseTokenContext)
}
