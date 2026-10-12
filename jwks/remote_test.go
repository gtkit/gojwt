package jwks_test

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gtkit/gojwt"
	"github.com/gtkit/gojwt/jwks"
	"github.com/stretchr/testify/require"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

type observedContext struct {
	context.Context
	observed chan struct{}
	once     sync.Once
}

func (c *observedContext) Done() <-chan struct{} {
	c.once.Do(func() { close(c.observed) })
	return c.Context.Done()
}

func response(r *http.Request, status int, body string) *http.Response {
	return &http.Response{StatusCode: status, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body)), ContentLength: -1, Request: r}
}

type remoteState struct {
	mu    sync.Mutex
	body  string
	err   error
	calls atomic.Int32
}

func (s *remoteState) transport(r *http.Request) (*http.Response, error) {
	s.calls.Add(1)
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.err != nil {
		return nil, s.err
	}
	return response(r, http.StatusOK, s.body), nil
}

func (s *remoteState) update(body string, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.body, s.err = body, err
}

type testClock struct{ value atomic.Int64 }

func newClock() *testClock {
	c := new(testClock)
	c.value.Store(time.Date(2026, 10, 12, 0, 0, 0, 0, time.UTC).UnixNano())
	return c
}
func (c *testClock) now() time.Time          { return time.Unix(0, c.value.Load()) }
func (c *testClock) advance(d time.Duration) { c.value.Add(int64(d)) }

func newRemote(t *testing.T, state *remoteState, clock *testClock, options ...jwks.RemoteOption) *jwks.Remote {
	t.Helper()
	opts := []jwks.RemoteOption{jwks.WithClient(&http.Client{Transport: roundTripFunc(state.transport)}), jwks.WithClock(clock.now)}
	opts = append(opts, options...)
	remote, err := jwks.NewRemote("https://issuer.example/keys", opts...)
	require.NoError(t, err)
	return remote
}

func TestRemoteConfiguration(t *testing.T) {
	for _, tc := range []struct {
		name     string
		endpoint string
		options  []jwks.RemoteOption
		wantErr  error
	}{
		{name: "HTTPS", endpoint: "https://issuer.example/jwks"},
		{name: "HTTPS case insensitive", endpoint: "HTTPS://issuer.example/jwks"},
		{name: "nil option", endpoint: "https://issuer.example/jwks", options: []jwks.RemoteOption{nil}},
		{name: "HTTP rejected", endpoint: "http://issuer.example/jwks", wantErr: jwks.ErrInvalidConfig},
		{name: "relative rejected", endpoint: "/jwks", wantErr: jwks.ErrInvalidConfig},
		{name: "userinfo rejected", endpoint: "https://user:password@issuer.example/jwks", wantErr: jwks.ErrInvalidConfig},
		{name: "fragment rejected", endpoint: "https://issuer.example/jwks#key", wantErr: jwks.ErrInvalidConfig},
		{name: "empty fragment rejected", endpoint: "https://issuer.example/jwks#", wantErr: jwks.ErrInvalidConfig},
		{name: "missing host", endpoint: "https:///jwks", wantErr: jwks.ErrInvalidConfig},
		{name: "opaque URL", endpoint: "https:issuer.example/jwks", wantErr: jwks.ErrInvalidConfig},
		{name: "invalid URL", endpoint: "https://[", wantErr: jwks.ErrInvalidConfig},
		{name: "nil client", endpoint: "https://issuer.example/jwks", options: []jwks.RemoteOption{jwks.WithClient(nil)}, wantErr: jwks.ErrInvalidConfig},
		{name: "nil clock", endpoint: "https://issuer.example/jwks", options: []jwks.RemoteOption{jwks.WithClock(nil)}, wantErr: jwks.ErrInvalidConfig},
		{name: "zero TTL", endpoint: "https://issuer.example/jwks", options: []jwks.RemoteOption{jwks.WithTTL(0)}, wantErr: jwks.ErrInvalidConfig},
		{name: "negative timeout", endpoint: "https://issuer.example/jwks", options: []jwks.RemoteOption{jwks.WithTimeout(-time.Second)}, wantErr: jwks.ErrInvalidConfig},
		{name: "zero interval", endpoint: "https://issuer.example/jwks", options: []jwks.RemoteOption{jwks.WithMinRefreshInterval(0)}, wantErr: jwks.ErrInvalidConfig},
	} {
		t.Run(tc.name, func(t *testing.T) {
			remote, err := jwks.NewRemote(tc.endpoint, tc.options...)
			if tc.wantErr == nil {
				require.NoError(t, err)
				require.NotNil(t, remote)
			} else {
				require.ErrorIs(t, err, tc.wantErr)
				require.Nil(t, remote)
			}
		})
	}
}

func TestRemoteRotationAndRemoval(t *testing.T) {
	for _, tc := range []struct {
		name     string
		ttl      time.Duration
		advance  time.Duration
		explicit bool
	}{
		{name: "explicit refresh", ttl: time.Minute, explicit: true},
		{name: "default TTL automatic refresh", ttl: 5 * time.Minute, advance: 5 * time.Minute},
		{name: "short TTL automatic refresh", ttl: 10 * time.Second, advance: 10 * time.Second},
		{name: "unknown kid automatic refresh", ttl: time.Minute, advance: 31 * time.Second},
	} {
		t.Run(tc.name, func(t *testing.T) {
			oldSet, newSet := edSet(t, "old"), edSet(t, "new")
			state := &remoteState{body: string(setJSON(t, oldSet))}
			clock := newClock()
			remote := newRemote(t, state, clock, jwks.WithTTL(tc.ttl))
			require.Zero(t, state.calls.Load(), "constructor must not fetch")
			_, err := remote.ResolveKey(t.Context(), "old", "EdDSA")
			require.NoError(t, err)
			_, err = remote.ResolveKey(t.Context(), "old", "EdDSA")
			require.NoError(t, err)
			require.Equal(t, int32(1), state.calls.Load())
			state.update(string(setJSON(t, newSet)), nil)
			clock.advance(tc.advance)
			if tc.explicit {
				require.NoError(t, remote.Refresh(t.Context()))
			}
			_, err = remote.ResolveKey(t.Context(), "new", "EdDSA")
			require.NoError(t, err)
			require.Equal(t, int32(2), state.calls.Load())
			_, err = remote.ResolveKey(t.Context(), "old", "EdDSA")
			require.ErrorIs(t, err, gojwt.ErrUnknownKeyID)
			_, err = remote.ResolveKey(t.Context(), "new", "HS256")
			require.ErrorIs(t, err, jwks.ErrAlgorithmMismatch)
			require.Equal(t, int32(2), state.calls.Load())
		})
	}
}

func TestRemoteFailureNeverExtendsOrPartiallyReplacesSnapshot(t *testing.T) {
	for _, tc := range []struct {
		name  string
		next  func(*testing.T) string
		cause error
	}{
		{name: "network error", cause: errors.New("offline")},
		{name: "invalid complete snapshot", next: func(t *testing.T) string {
			return `{"keys":[` + strings.TrimSuffix(strings.TrimPrefix(string(setJSON(t, edSet(t, "new"))), `{"keys":[`), `]}`) + `,{"kty":"RSA"}]}`
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			state := &remoteState{body: string(setJSON(t, edSet(t, "old")))}
			clock := newClock()
			remote := newRemote(t, state, clock, jwks.WithTTL(time.Minute))
			require.NoError(t, remote.Refresh(t.Context()))
			clock.advance(20 * time.Second)
			var body string
			if tc.next != nil {
				body = tc.next(t)
			}
			state.update(body, tc.cause)
			err := remote.Refresh(t.Context())
			require.ErrorIs(t, err, jwks.ErrFetch)
			if tc.cause != nil {
				require.ErrorIs(t, err, tc.cause)
			}
			_, err = remote.ResolveKey(t.Context(), "old", "EdDSA")
			require.NoError(t, err, "fresh old snapshot remains usable")
			_, err = remote.ResolveKey(t.Context(), "new", "EdDSA")
			require.ErrorIs(t, err, gojwt.ErrUnknownKeyID)
			clock.advance(40 * time.Second)
			_, err = remote.ResolveKey(t.Context(), "old", "EdDSA")
			require.ErrorIs(t, err, jwks.ErrFetch, "old original expiry must not move")
			calls := state.calls.Load()
			for range 20 {
				_, err = remote.ResolveKey(t.Context(), "old", "EdDSA")
				require.ErrorIs(t, err, jwks.ErrFetch)
			}
			require.Equal(t, calls, state.calls.Load(), "failed automatic attempts must be throttled")
		})
	}
}

func TestRemoteRejectsHTTPFailuresAndParsingBombs(t *testing.T) {
	for _, tc := range []struct {
		name     string
		status   int
		body     string
		declared int64
		failure  error
	}{
		{name: "HTTP error", status: http.StatusServiceUnavailable},
		{name: "redirect", status: http.StatusFound},
		{name: "oversized content length", status: http.StatusOK, declared: jwks.MaxSetBytes + 1},
		{name: "oversized stream", status: http.StatusOK, body: strings.Repeat("x", jwks.MaxSetBytes+1)},
		{name: "invalid JSON", status: http.StatusOK, body: "invalid"},
		{name: "private key", status: http.StatusOK, body: `{"keys":[{"kty":"oct","k":"secret"}]}`},
		{name: "read error", status: http.StatusOK, failure: io.ErrUnexpectedEOF},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var calls atomic.Int32
			var closed atomic.Bool
			transport := roundTripFunc(func(r *http.Request) (*http.Response, error) {
				calls.Add(1)
				resp := response(r, tc.status, tc.body)
				resp.Header.Set("Location", "https://untrusted.example/keys")
				resp.ContentLength = tc.declared
				resp.Body = &trackingBody{Reader: strings.NewReader(tc.body), failure: tc.failure, closed: &closed}
				return resp, nil
			})
			remote, err := jwks.NewRemote("https://issuer.example/keys", jwks.WithClient(&http.Client{Transport: transport}))
			require.NoError(t, err)
			err = remote.Refresh(t.Context())
			require.ErrorIs(t, err, jwks.ErrFetch)
			if tc.failure != nil {
				require.ErrorIs(t, err, tc.failure)
			}
			require.Equal(t, int32(1), calls.Load(), "redirect must never be followed")
			require.True(t, closed.Load(), "response body must be closed")
		})
	}
}

type trackingBody struct {
	io.Reader
	failure error
	closed  *atomic.Bool
}

func (b *trackingBody) Read(p []byte) (int, error) {
	if b.failure != nil {
		return 0, b.failure
	}
	return b.Reader.Read(p)
}
func (b *trackingBody) Close() error { b.closed.Store(true); return nil }

func TestRemoteUnknownKeyFloodIsThrottled(t *testing.T) {
	for _, interval := range []time.Duration{time.Second, 30 * time.Second} {
		t.Run(interval.String(), func(t *testing.T) {
			state := &remoteState{body: string(setJSON(t, edSet(t, "known")))}
			clock := newClock()
			remote := newRemote(t, state, clock, jwks.WithMinRefreshInterval(interval))
			require.NoError(t, remote.Refresh(t.Context()))
			for range 10 {
				_, err := remote.ResolveKey(t.Context(), "unknown", "EdDSA")
				require.ErrorIs(t, err, gojwt.ErrUnknownKeyID)
			}
			require.Equal(t, int32(1), state.calls.Load())
			clock.advance(interval)
			failures := make(chan error, 40)
			var wg sync.WaitGroup
			for range 40 {
				wg.Go(func() {
					_, err := remote.ResolveKey(t.Context(), "unknown", "EdDSA")
					if !errors.Is(err, gojwt.ErrUnknownKeyID) {
						failures <- err
					}
				})
			}
			wg.Wait()
			close(failures)
			for err := range failures {
				t.Errorf("unexpected lookup result: %v", err)
			}
			require.Equal(t, int32(2), state.calls.Load())
		})
	}
}

func TestRemoteCoalescingAndWaiterCancellation(t *testing.T) {
	for _, waiterCancels := range []bool{false, true} {
		t.Run(map[bool]string{false: "waiter receives snapshot", true: "waiter cancellation"}[waiterCancels], func(t *testing.T) {
			body := string(setJSON(t, edSet(t, "key")))
			started, release := make(chan struct{}), make(chan struct{})
			var calls atomic.Int32
			client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
				calls.Add(1)
				close(started)
				select {
				case <-r.Context().Done():
					return nil, r.Context().Err()
				case <-release:
					return response(r, http.StatusOK, body), nil
				}
			})}
			remote, err := jwks.NewRemote("https://issuer.example/keys", jwks.WithClient(client))
			require.NoError(t, err)
			leaderDone := make(chan error, 1)
			go func() { leaderDone <- remote.Refresh(t.Context()) }()
			<-started
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			waiterCtx := &observedContext{Context: ctx, observed: make(chan struct{})}
			waiterDone := make(chan error, 1)
			go func() { _, err := remote.ResolveKey(waiterCtx, "key", "EdDSA"); waiterDone <- err }()
			<-waiterCtx.observed // The waiter joined the fetch before cancellation or release.
			if waiterCancels {
				cancel()
				require.ErrorIs(t, <-waiterDone, context.Canceled)
			}
			close(release)
			require.NoError(t, <-leaderDone)
			if !waiterCancels {
				require.NoError(t, <-waiterDone)
			}
			require.Equal(t, int32(1), calls.Load())
		})
	}
}

func TestRemoteCancellationAndTimeout(t *testing.T) {
	for _, tc := range []struct {
		name     string
		canceled bool
		timeout  time.Duration
		want     error
	}{
		{name: "already canceled", canceled: true, timeout: time.Second, want: context.Canceled},
		{name: "request timeout", timeout: time.Millisecond, want: context.DeadlineExceeded},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var calls atomic.Int32
			client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
				calls.Add(1)
				<-r.Context().Done()
				return nil, r.Context().Err()
			})}
			remote, err := jwks.NewRemote("https://issuer.example/keys", jwks.WithClient(client), jwks.WithTimeout(tc.timeout))
			require.NoError(t, err)
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			if tc.canceled {
				cancel()
			}
			_, err = remote.ResolveKey(ctx, "key", "EdDSA")
			require.ErrorIs(t, err, tc.want)
			if tc.canceled {
				require.Zero(t, calls.Load())
				require.ErrorIs(t, remote.Refresh(ctx), context.Canceled)
			} else {
				require.Equal(t, int32(1), calls.Load())
			}
		})
	}
}

func TestRemoteNilAndEmptyReceivers(t *testing.T) {
	for _, remote := range []*jwks.Remote{nil, new(jwks.Remote)} {
		t.Run(map[bool]string{true: "nil", false: "zero"}[remote == nil], func(t *testing.T) {
			var nilCtx context.Context // This API explicitly accepts nil context.
			require.ErrorIs(t, remote.Refresh(nilCtx), jwks.ErrInvalidConfig)
			_, err := remote.ResolveKey(nilCtx, "key", "EdDSA")
			require.ErrorIs(t, err, jwks.ErrInvalidConfig)
		})
	}
}

func TestRemoteCopiesClientAndSupportsNilContext(t *testing.T) {
	for _, method := range []string{"resolve", "refresh"} {
		t.Run(method, func(t *testing.T) {
			body := string(setJSON(t, edSet(t, "key")))
			client := &http.Client{Timeout: time.Minute, Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) { return response(r, http.StatusOK, body), nil })}
			remote, err := jwks.NewRemote("https://issuer.example/keys", jwks.WithClient(client))
			require.NoError(t, err)
			require.Equal(t, time.Minute, client.Timeout)
			require.Nil(t, client.CheckRedirect)
			var nilCtx context.Context // Exercise the documented background fallback.
			if method == "resolve" {
				_, err = remote.ResolveKey(nilCtx, "key", "EdDSA")
			} else {
				err = remote.Refresh(nilCtx)
			}
			require.NoError(t, err)
		})
	}
}

func TestRemoteLeaderCancellationReleasesWaiters(t *testing.T) {
	for _, method := range []string{"resolve", "refresh"} {
		t.Run(method, func(t *testing.T) {
			var calls atomic.Int32
			started := make(chan struct{})
			client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
				calls.Add(1)
				close(started)
				<-r.Context().Done()
				return nil, r.Context().Err()
			})}
			remote, err := jwks.NewRemote("https://issuer.example/keys", jwks.WithClient(client))
			require.NoError(t, err)
			leaderCtx, cancel := context.WithCancel(t.Context())
			defer cancel()
			leaderDone := make(chan error, 1)
			go func() { leaderDone <- remote.Refresh(leaderCtx) }()
			<-started
			waiterCtx := &observedContext{Context: t.Context(), observed: make(chan struct{})}
			waiterDone := make(chan error, 1)
			go func() {
				if method == "refresh" {
					waiterDone <- remote.Refresh(waiterCtx)
					return
				}
				_, err := remote.ResolveKey(waiterCtx, "key", "EdDSA")
				waiterDone <- err
			}()
			<-waiterCtx.observed
			cancel()
			require.ErrorIs(t, <-leaderDone, context.Canceled)
			require.ErrorIs(t, <-waiterDone, context.Canceled)
			require.Equal(t, int32(1), calls.Load())
		})
	}
}

func TestUnknownKidDoesNotRepeatTTLFetch(t *testing.T) {
	for _, elapsed := range []time.Duration{0, 5 * time.Minute} {
		t.Run(elapsed.String(), func(t *testing.T) {
			state := &remoteState{body: string(setJSON(t, edSet(t, "known")))}
			clock := newClock()
			remote := newRemote(t, state, clock)
			if elapsed > 0 {
				require.NoError(t, remote.Refresh(t.Context()))
			}
			clock.advance(elapsed)
			before := state.calls.Load()
			_, err := remote.ResolveKey(t.Context(), "unknown", "EdDSA")
			require.ErrorIs(t, err, gojwt.ErrUnknownKeyID)
			require.Equal(t, before+1, state.calls.Load(), "one ResolveKey must make at most one request")
		})
	}
}

func TestRemoteDoesNotSendInjectedClientCookies(t *testing.T) {
	for _, endpoint := range []string{"https://issuer.example/keys", "https://issuer.example/other-keys"} {
		t.Run(endpoint, func(t *testing.T) {
			jar, err := cookiejar.New(nil)
			require.NoError(t, err)
			u, err := url.Parse(endpoint)
			require.NoError(t, err)
			jar.SetCookies(u, []*http.Cookie{{Name: "session", Value: "test-cookie"}})
			body := string(setJSON(t, edSet(t, "key")))
			requests := make(chan *http.Request, 1)
			client := &http.Client{Jar: jar, Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
				requests <- r
				return response(r, http.StatusOK, body), nil
			})}
			remote, err := jwks.NewRemote(endpoint, jwks.WithClient(client))
			require.NoError(t, err)
			require.NoError(t, remote.Refresh(t.Context()))
			r := <-requests
			require.Empty(t, r.Header.Get("Cookie"))
			require.Empty(t, r.Header.Get("Authorization"))
			require.Equal(t, "application/jwk-set+json, application/json", r.Header.Get("Accept"))
			require.Same(t, jar, client.Jar)
			require.Len(t, client.Jar.Cookies(u), 1)
		})
	}
}

type pausedDoneContext struct {
	context.Context
	entered chan struct{}
	resume  chan struct{}
	once    sync.Once
}

func (c *pausedDoneContext) Done() <-chan struct{} {
	c.once.Do(func() { close(c.entered); <-c.resume })
	return c.Context.Done()
}

func TestRemoteWaiterCancellationRacesCompletedFetch(t *testing.T) {
	for _, count := range []int{1, 32} {
		t.Run(map[int]string{1: "one completion", 32: "repeated completions"}[count], func(t *testing.T) {
			body := string(setJSON(t, edSet(t, "key")))
			for range count {
				started, release := make(chan struct{}), make(chan struct{})
				client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
					close(started)
					select {
					case <-r.Context().Done():
						return nil, r.Context().Err()
					case <-release:
						return response(r, http.StatusOK, body), nil
					}
				})}
				remote, err := jwks.NewRemote("https://issuer.example/keys", jwks.WithClient(client))
				require.NoError(t, err)
				leaderDone := make(chan error, 1)
				go func() { leaderDone <- remote.Refresh(t.Context()) }()
				<-started
				ctx, cancel := context.WithCancel(t.Context())
				waiterCtx := &pausedDoneContext{Context: ctx, entered: make(chan struct{}), resume: make(chan struct{})}
				waiterDone := make(chan error, 1)
				go func() { waiterDone <- remote.Refresh(waiterCtx) }()
				<-waiterCtx.entered
				cancel()
				close(release)
				require.NoError(t, <-leaderDone)
				// Both the cancellation and completed-fetch channels are ready
				// before allowing the waiter to evaluate its select.
				close(waiterCtx.resume)
				require.ErrorIs(t, <-waiterDone, context.Canceled)
			}
		})
	}
}
