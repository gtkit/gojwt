package gojwt

import (
	"fmt"
	"sync"
	"time"

	"github.com/gtkit/gojwt/claims"
)

// Blacklister 定义黑名单检查接口。
// 调用方可基于此接口实现 Redis、DB 或其他存储后端的黑名单。
type Blacklister interface {
	// In 判断 tokenID 是否在黑名单中。
	In(tokenID string) bool
	// Add 将 tokenID 加入黑名单。
	Add(tokenID string)
	// Remove 将 tokenID 从黑名单中移除。
	Remove(tokenID string)
}

// BlacklistManager 扩展 Blacklister，提供带过期时间的加入、从 Claims 加入、
// 过期清扫和关闭等增强能力。面向接口编程时可按需断言。
type BlacklistManager interface {
	Blacklister
	// AddWithExpiration 将 tokenID 加入黑名单，expiresAt 后自动失效。
	AddWithExpiration(tokenID string, expiresAt time.Time)
	// AddToken 从 claims 中读取 token_id 和 exp，并加入黑名单。
	AddToken(tokenClaims *claims.Claims) error
	// SweepExpired 主动清理已过期的黑名单条目，返回删除数量。
	SweepExpired() int
	// Close 停止后台清扫协程。
	Close()
}

// 编译期确保 *Blacklist 同时满足 Blacklister 和 BlacklistManager。
var (
	_ Blacklister      = (*Blacklist)(nil)
	_ BlacklistManager = (*Blacklist)(nil)
)

// Blacklist 是基于内存 map 的并发安全黑名单实现。
// 适用于单实例部署；多实例场景请使用 Redis 等外部存储。
type Blacklist struct {
	mu        sync.RWMutex
	m         map[string]time.Time
	stopCh    chan struct{}
	closeOnce sync.Once
}

// NewBlacklist 创建一个空的内存黑名单实例。
func NewBlacklist() *Blacklist {
	return &Blacklist{m: make(map[string]time.Time)}
}

// NewBlacklistWithCleanup 创建一个带后台过期清扫协程的内存黑名单。
func NewBlacklistWithCleanup(interval time.Duration) (*Blacklist, error) {
	if interval <= 0 {
		return nil, fmt.Errorf("%w: cleanup interval must be greater than zero", ErrInvalidConfig)
	}

	blacklist := NewBlacklist()
	blacklist.stopCh = make(chan struct{})
	go blacklist.runCleanup(interval)

	return blacklist, nil
}

// In 判断 tokenID 是否在黑名单中。并发安全。
func (b *Blacklist) In(tokenID string) bool {
	if b == nil {
		return false
	}

	b.mu.RLock()
	expiresAt, ok := b.m[tokenID]
	b.mu.RUnlock()
	if !ok {
		return false
	}
	if expiresAt.IsZero() {
		return true
	}
	if time.Now().Before(expiresAt) {
		return true
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	expiresAt, ok = b.m[tokenID]
	if !ok {
		return false
	}
	if expiresAt.IsZero() || time.Now().Before(expiresAt) {
		return true
	}

	delete(b.m, tokenID)
	return false
}

// Add 将 tokenID 加入黑名单。并发安全。
// 该方法会将 token 永久加入黑名单，直到显式 Remove。
func (b *Blacklist) Add(tokenID string) {
	b.AddWithExpiration(tokenID, time.Time{})
}

// AddWithExpiration 将 tokenID 加入黑名单，并在 expiresAt 后自动失效。
// expiresAt 为零值时表示永久拉黑。
func (b *Blacklist) AddWithExpiration(tokenID string, expiresAt time.Time) {
	if b == nil {
		return
	}
	if tokenID == "" {
		return
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	b.m[tokenID] = expiresAt
}

// AddToken 从 claims 中读取 token_id 和 exp，并加入黑名单。
func (b *Blacklist) AddToken(tokenClaims *claims.Claims) error {
	if tokenClaims == nil {
		return fmt.Errorf("%w: claims is required", ErrTokenInvalidClaims)
	}
	if tokenClaims.TokenID == "" {
		return fmt.Errorf("%w: token_id is required", ErrTokenInvalidClaims)
	}
	if tokenClaims.ExpiresAt == nil {
		return fmt.Errorf("%w: expires_at is required", ErrTokenInvalidClaims)
	}

	b.AddWithExpiration(tokenClaims.TokenID, tokenClaims.ExpiresAt.Time)
	return nil
}

// SweepExpired 主动清理已过期的黑名单条目，返回删除数量。
func (b *Blacklist) SweepExpired() int {
	if b == nil {
		return 0
	}

	now := time.Now()

	b.mu.Lock()
	defer b.mu.Unlock()

	removed := 0
	for tokenID, expiresAt := range b.m {
		if expiresAt.IsZero() || now.Before(expiresAt) {
			continue
		}
		delete(b.m, tokenID)
		removed++
	}

	return removed
}

// Remove 将 tokenID 从黑名单中移除。并发安全。
func (b *Blacklist) Remove(tokenID string) {
	if b == nil {
		return
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	delete(b.m, tokenID)
}

// Close 停止后台过期清扫协程。可重复调用。
func (b *Blacklist) Close() {
	if b == nil || b.stopCh == nil {
		return
	}

	b.closeOnce.Do(func() {
		close(b.stopCh)
	})
}

func (b *Blacklist) runCleanup(interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			b.SweepExpired()
		case <-b.stopCh:
			return
		}
	}
}
