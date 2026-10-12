package jwks

import (
	"net/http"
	"strconv"
	"sync/atomic"
)

type publishedSet struct{ data []byte }

// Publisher serves replaceable public JWKS snapshots. It is safe for concurrent
// Replace and ServeHTTP calls and owns no routes, keys or background goroutines.
type Publisher struct{ snapshot atomic.Pointer[publishedSet] }

// NewPublisher creates an HTTP handler with an initial validated public set.
func NewPublisher(set *Set) (*Publisher, error) {
	p := new(Publisher)
	if err := p.Replace(set); err != nil {
		return nil, err
	}
	return p, nil
}

// Replace atomically publishes a complete public snapshot. Errors preserve the
// previous response; the supplied set remains immutable.
func (p *Publisher) Replace(set *Set) error {
	if p == nil {
		return invalid("nil publisher")
	}
	data, err := set.MarshalJSON()
	if err != nil {
		return err
	}
	p.snapshot.Store(&publishedSet{data: data})
	return nil
}

// ServeHTTP serves GET and HEAD requests with application/jwk-set+json.
// Applications choose the route, transport security and response cache policy.
func (p *Publisher) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if p == nil || p.snapshot.Load() == nil {
		http.Error(w, "public key set unavailable", http.StatusServiceUnavailable)
		return
	}
	snapshot := p.snapshot.Load()
	w.Header().Set("Content-Type", "application/jwk-set+json")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Length", strconv.Itoa(len(snapshot.data)))
	if r.Method == http.MethodGet {
		_, _ = w.Write(snapshot.data)
	}
}
