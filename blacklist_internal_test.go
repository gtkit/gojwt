package gojwt

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestBlacklistInRemovesExpiredEntryLazily(t *testing.T) {
	blacklist := NewBlacklist()
	blacklist.AddWithExpiration("expired-token", time.Now().Add(-time.Millisecond))

	require.False(t, blacklist.In("expired-token"))

	blacklist.mu.RLock()
	_, ok := blacklist.m["expired-token"]
	blacklist.mu.RUnlock()
	require.False(t, ok)
}

func TestNewBlacklistWithCleanupRejectsNonPositiveInterval(t *testing.T) {
	_, err := NewBlacklistWithCleanup(0)
	require.ErrorIs(t, err, ErrInvalidConfig)
}

func TestBlacklistSweepExpiredRemovesExpiredEntries(t *testing.T) {
	blacklist := NewBlacklist()
	blacklist.AddWithExpiration("expired-token", time.Now().Add(-time.Millisecond))
	blacklist.AddWithExpiration("fresh-token", time.Now().Add(time.Minute))

	removed := blacklist.SweepExpired()
	require.Equal(t, 1, removed)
	require.False(t, blacklist.In("expired-token"))
	require.True(t, blacklist.In("fresh-token"))
}

func TestBlacklistBackgroundCleanupRemovesExpiredEntryWithoutLookup(t *testing.T) {
	blacklist, err := NewBlacklistWithCleanup(10 * time.Millisecond)
	require.NoError(t, err)
	t.Cleanup(blacklist.Close)

	blacklist.AddWithExpiration("expiring-token", time.Now().Add(20*time.Millisecond))

	require.Eventually(t, func() bool {
		blacklist.mu.RLock()
		_, ok := blacklist.m["expiring-token"]
		blacklist.mu.RUnlock()
		return !ok
	}, time.Second, 10*time.Millisecond)
}

func TestBlacklistCloseIsIdempotent(t *testing.T) {
	blacklist, err := NewBlacklistWithCleanup(10 * time.Millisecond)
	require.NoError(t, err)

	blacklist.Close()
	blacklist.Close()
}
