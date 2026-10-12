package jwks_test

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/gtkit/gojwt/jwks"
	"github.com/stretchr/testify/require"
)

func TestPublisherHTTPAndReplacement(t *testing.T) {
	for _, tc := range []struct {
		name   string
		method string
		status int
		body   bool
	}{
		{name: "GET", method: http.MethodGet, status: http.StatusOK, body: true},
		{name: "HEAD", method: http.MethodHead, status: http.StatusOK},
		{name: "POST", method: http.MethodPost, status: http.StatusMethodNotAllowed},
	} {
		t.Run(tc.name, func(t *testing.T) {
			oldSet, newSet := edSet(t, "old"), edSet(t, "new")
			publisher, err := jwks.NewPublisher(oldSet)
			require.NoError(t, err)
			for _, set := range []*jwks.Set{oldSet, newSet} {
				require.NoError(t, publisher.Replace(set))
				recorder := httptest.NewRecorder()
				publisher.ServeHTTP(recorder, httptest.NewRequest(tc.method, "/trusted-route", nil))
				require.Equal(t, tc.status, recorder.Code)
				if tc.status == http.StatusOK {
					require.Equal(t, "application/jwk-set+json", recorder.Header().Get("Content-Type"))
					require.Equal(t, "nosniff", recorder.Header().Get("X-Content-Type-Options"))
				}
				if tc.body {
					require.JSONEq(t, string(setJSON(t, set)), recorder.Body.String())
				}
				if tc.method == http.MethodHead {
					require.Empty(t, recorder.Body.String())
				}
				if tc.status == http.StatusMethodNotAllowed {
					require.Equal(t, "GET, HEAD", recorder.Header().Get("Allow"))
				}
			}
			require.ErrorIs(t, publisher.Replace(nil), jwks.ErrInvalidSet)
			recorder := httptest.NewRecorder()
			publisher.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/keys", nil))
			require.JSONEq(t, string(setJSON(t, newSet)), recorder.Body.String())
		})
	}
}

func TestPublisherUnavailable(t *testing.T) {
	for _, publisher := range []*jwks.Publisher{nil, new(jwks.Publisher)} {
		t.Run(map[bool]string{true: "nil", false: "zero"}[publisher == nil], func(t *testing.T) {
			recorder := httptest.NewRecorder()
			publisher.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/keys", nil))
			require.Equal(t, http.StatusServiceUnavailable, recorder.Code)
			if publisher == nil {
				require.ErrorIs(t, publisher.Replace(edSet(t, "key")), jwks.ErrInvalidSet)
			}
			_, err := jwks.NewPublisher(nil)
			require.ErrorIs(t, err, jwks.ErrInvalidSet)
		})
	}
}

func TestPublisherConcurrentReplacement(t *testing.T) {
	for _, count := range []int{1, 8} {
		t.Run(map[int]string{1: "one reader", 8: "many readers"}[count], func(t *testing.T) {
			sets := []*jwks.Set{edSet(t, "old"), edSet(t, "new")}
			publisher, err := jwks.NewPublisher(sets[0])
			require.NoError(t, err)
			failures := make(chan error, (count+1)*30)
			var wg sync.WaitGroup
			wg.Go(func() {
				for i := range 30 {
					if err := publisher.Replace(sets[i%2]); err != nil {
						failures <- err
					}
				}
			})
			for range count {
				wg.Go(func() {
					for range 30 {
						recorder := httptest.NewRecorder()
						publisher.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/keys", nil))
						set, err := jwks.Parse(recorder.Body.Bytes())
						if err != nil {
							failures <- err
							continue
						}
						keys := set.Keys()
						if len(keys) != 1 || (keys[0].KeyID != "old" && keys[0].KeyID != "new") {
							failures <- errors.New("partial public snapshot")
						}
					}
				})
			}
			wg.Wait()
			close(failures)
			for err := range failures {
				t.Error(err)
			}
		})
	}
}
