package gojwt

import "sync"

type Blacklister interface {
	In(tokenID string) bool
	Add(tokenID string)
	Remove(tokenID string)
}

type Blacklist struct {
	mu sync.RWMutex
	m  map[string]struct{}
}

func NewBlacklist() *Blacklist {
	return &Blacklist{m: make(map[string]struct{})}
}

func (b *Blacklist) In(tokenID string) bool {
	if b == nil {
		return false
	}

	b.mu.RLock()
	defer b.mu.RUnlock()

	_, ok := b.m[tokenID]
	return ok
}

func (b *Blacklist) Add(tokenID string) {
	if b == nil {
		return
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	b.m[tokenID] = struct{}{}
}

func (b *Blacklist) Remove(tokenID string) {
	if b == nil {
		return
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	delete(b.m, tokenID)
}
