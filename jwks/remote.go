package jwks

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/gtkit/gojwt"
)

type remoteConfig struct {
	client      *http.Client
	now         func() time.Time
	ttl         time.Duration
	timeout     time.Duration
	minInterval time.Duration
}

// RemoteOption configures a remote resolver before first use.
type RemoteOption func(*remoteConfig)

// WithClient injects an HTTP client, usually to share a transport or for tests.
// The client is copied; redirects are always disabled and WithTimeout governs
// request deadlines. Cookies are disabled. Its transport must honor request cancellation.
func WithClient(client *http.Client) RemoteOption {
	return func(c *remoteConfig) { c.client = client }
}

// WithClock injects the cache clock. Default is time.Now. The function must be
// safe for concurrent calls; requests still use real context deadlines.
func WithClock(now func() time.Time) RemoteOption {
	return func(c *remoteConfig) { c.now = now }
}

// WithTTL sets how long a successful complete snapshot is trusted, default
// 5 minutes. It must be positive. HTTP failures never extend this deadline.
func WithTTL(ttl time.Duration) RemoteOption {
	return func(c *remoteConfig) { c.ttl = ttl }
}

// WithTimeout sets the request timeout, default 5 seconds. It must be positive;
// a shorter caller deadline also applies.
func WithTimeout(timeout time.Duration) RemoteOption {
	return func(c *remoteConfig) { c.timeout = timeout }
}

// WithMinRefreshInterval throttles unknown-kid and failed automatic attempts, default 30
// seconds. It must be positive. Explicit Refresh bypasses this interval while
// still joining an in-flight request. Failure and unknown-kid requests also
// consume an attempt, bounding attacker-triggered fetches. Successful TTL expiry
// refreshes do not wait for this interval if a shorter TTL was configured.
func WithMinRefreshInterval(interval time.Duration) RemoteOption {
	return func(c *remoteConfig) { c.minInterval = interval }
}

type remoteSnapshot struct {
	set       *Set
	expiresAt time.Time
}

type refreshCall struct {
	done chan struct{}
	err  error
}

// Remote resolves keys from one trusted HTTPS JWKS URL. It is safe for concurrent
// use. Fetches are bounded, coalesced and performed by calling goroutines; there
// is no implicit background goroutine. Waiters can cancel independently; the
// caller starting a fetch supplies its I/O context, and cancellation fails that
// shared attempt without publishing a snapshot.
type Remote struct {
	endpoint    string
	config      remoteConfig
	mu          sync.Mutex
	snapshot    remoteSnapshot
	call        *refreshCall
	attempted   bool
	lastAttempt time.Time
	lastError   error
}

var _ gojwt.KeyResolver = (*Remote)(nil)

// NewRemote validates a configured HTTPS URL and options. It does not perform
// I/O; ResolveKey fetches on first use, TTL expiry or an unknown kid. URL userinfo,
// fragments, opaque URLs and all redirects are forbidden. Token headers never
// influence this endpoint. NewRemote does not inspect private application URLs.
func NewRemote(endpoint string, options ...RemoteOption) (*Remote, error) {
	u, err := url.Parse(endpoint)
	if err != nil || u == nil || !strings.EqualFold(u.Scheme, "https") || u.Host == "" || u.Hostname() == "" || u.User != nil || strings.Contains(endpoint, "#") || u.Opaque != "" {
		return nil, fmt.Errorf("%w: an absolute HTTPS URL without userinfo or fragment is required", ErrInvalidConfig)
	}
	u.Scheme = "https"
	cfg := remoteConfig{client: &http.Client{}, now: time.Now, ttl: 5 * time.Minute, timeout: 5 * time.Second, minInterval: 30 * time.Second}
	for _, option := range options {
		if option != nil {
			option(&cfg)
		}
	}
	if cfg.client == nil || cfg.now == nil || cfg.ttl <= 0 || cfg.timeout <= 0 || cfg.minInterval <= 0 {
		return nil, fmt.Errorf("%w: client, clock and positive durations are required", ErrInvalidConfig)
	}
	client := *cfg.client
	client.Jar = nil
	client.Timeout = cfg.timeout
	client.CheckRedirect = func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }
	cfg.client = &client
	return &Remote{endpoint: u.String(), config: cfg}, nil
}

// ResolveKey returns a public key from a fresh snapshot. Unknown keys trigger at
// most one throttled refresh before exact lookup is retried. An expired snapshot
// is never used if refresh fails or is throttled; errors preserve fetch causes.
func (r *Remote) ResolveKey(ctx context.Context, kid, algorithm string) (any, error) {
	ctx = nonNilContext(ctx)
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if r == nil || r.config.client == nil {
		return nil, ErrInvalidConfig
	}
	snapshot := r.current()
	if r.fresh(snapshot) {
		key, err := snapshot.set.ResolveKey(ctx, kid, algorithm)
		if !errors.Is(err, gojwt.ErrUnknownKeyID) {
			return key, err
		}
	}
	refreshErr := r.refresh(ctx, false)
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	snapshot = r.current()
	if !r.fresh(snapshot) {
		if refreshErr != nil {
			return nil, refreshErr
		}
		return nil, fmt.Errorf("%w: no fresh snapshot while automatic refresh is throttled", ErrFetch)
	}
	key, err := snapshot.set.ResolveKey(ctx, kid, algorithm)
	if err != nil && refreshErr != nil {
		return nil, fmt.Errorf("%w: %w", err, refreshErr)
	}
	return key, err
}

// Refresh explicitly fetches and atomically replaces the complete snapshot.
// It bypasses automatic throttling, coalesces in-flight requests, and preserves
// both the previous keys and their original expiry on failure.
func (r *Remote) Refresh(ctx context.Context) error {
	ctx = nonNilContext(ctx)
	if err := ctx.Err(); err != nil {
		return err
	}
	if r == nil || r.config.client == nil {
		return ErrInvalidConfig
	}
	return r.refresh(ctx, true)
}

func (r *Remote) current() remoteSnapshot {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.snapshot
}

func (r *Remote) fresh(snapshot remoteSnapshot) bool {
	return snapshot.set != nil && r.config.now().Before(snapshot.expiresAt)
}

func (r *Remote) refresh(ctx context.Context, force bool) error {
	r.mu.Lock()
	if call := r.call; call != nil {
		r.mu.Unlock()
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-call.done:
			if err := ctx.Err(); err != nil {
				return err
			}
			return call.err
		}
	}
	now := r.config.now()
	if !force && r.attempted && now.Sub(r.lastAttempt) < r.config.minInterval &&
		(r.lastError != nil || (r.snapshot.set != nil && now.Before(r.snapshot.expiresAt))) {
		err := r.lastError
		r.mu.Unlock()
		return err
	}
	call := &refreshCall{done: make(chan struct{})}
	r.call = call
	r.attempted, r.lastAttempt = true, now
	r.mu.Unlock()

	set, err := r.fetch(ctx)
	r.mu.Lock()
	if err == nil {
		r.snapshot = remoteSnapshot{set: set, expiresAt: r.config.now().Add(r.config.ttl)}
	}
	r.lastError = err
	call.err = err
	r.call = nil
	close(call.done)
	r.mu.Unlock()
	return err
}

func (r *Remote) fetch(ctx context.Context) (*Set, error) {
	requestCtx, cancel := context.WithTimeout(ctx, r.config.timeout)
	defer cancel()
	request, err := http.NewRequestWithContext(requestCtx, http.MethodGet, r.endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: create request: %w", ErrFetch, err)
	}
	request.Header.Set("Accept", "application/jwk-set+json, application/json")
	response, err := r.config.client.Do(request)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrFetch, err)
	}
	defer func() {
		// The response has been consumed or rejected; closing cannot change its
		// already determined verification result, but must release resources.
		_ = response.Body.Close()
	}()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%w: HTTP status %d", ErrFetch, response.StatusCode)
	}
	if response.ContentLength > MaxSetBytes {
		return nil, fmt.Errorf("%w: response exceeds size limit", ErrFetch)
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, MaxSetBytes+1))
	if err != nil {
		return nil, fmt.Errorf("%w: read response: %w", ErrFetch, err)
	}
	if len(data) > MaxSetBytes {
		return nil, fmt.Errorf("%w: response exceeds size limit", ErrFetch)
	}
	set, err := Parse(data)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrFetch, err)
	}
	if err := requestCtx.Err(); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrFetch, err)
	}
	return set, nil
}

func nonNilContext(ctx context.Context) context.Context {
	if ctx == nil {
		return context.Background()
	}
	return ctx
}
