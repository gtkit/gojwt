package gojwt

import "sync"

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

// Blacklist 是基于内存 map 的并发安全黑名单实现。
// 适用于单实例部署；多实例场景请使用 Redis 等外部存储。
type Blacklist struct {
	mu sync.RWMutex
	m  map[string]struct{}
}

// NewBlacklist 创建一个空的内存黑名单实例。
func NewBlacklist() *Blacklist {
	return &Blacklist{m: make(map[string]struct{})}
}

// In 判断 tokenID 是否在黑名单中。并发安全。
func (b *Blacklist) In(tokenID string) bool {
	if b == nil {
		return false
	}

	b.mu.RLock()
	defer b.mu.RUnlock()

	_, ok := b.m[tokenID]
	return ok
}

// Add 将 tokenID 加入黑名单。并发安全。
func (b *Blacklist) Add(tokenID string) {
	if b == nil {
		return
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	b.m[tokenID] = struct{}{}
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
