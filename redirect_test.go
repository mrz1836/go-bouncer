package bouncer_test

import (
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/mrz1836/go-bouncer"
	"github.com/mrz1836/go-bouncer/internal/testutil"
)

// redirectStatuses are the redirects the standard library follows; 307 and
// 308 also resend the body.
func redirectStatuses() []int {
	return []int{
		http.StatusMovedPermanently, http.StatusFound, http.StatusSeeOther,
		http.StatusTemporaryRedirect, http.StatusPermanentRedirect,
	}
}

// followAll is a CheckRedirect that follows every redirect, as a careless
// injected client might.
func followAll(*http.Request, []*http.Request) error { return nil }

// redirectingTo returns a handler that answers every request with status and
// a Location pointing at target.
func redirectingTo(status int, target string) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Location", target)
		w.WriteHeader(status)
	}
}

// TestRedirectsAreNeverFollowed answers every operation with each redirect,
// to the same origin and to another one, through an injected client whose
// CheckRedirect would follow it. The SDK makes exactly one attempt, the target
// sees nothing (neither a request nor the key), and the call fails with
// ErrUnexpectedResponse carrying the 3xx status.
func TestRedirectsAreNeverFollowed(t *testing.T) {
	t.Parallel()
	for _, status := range redirectStatuses() {
		for _, sameOrigin := range []bool{true, false} {
			for _, oc := range opCases() {
				name := fmt.Sprintf("%d/same-origin=%t/%s", status, sameOrigin, oc.name)
				t.Run(name, func(t *testing.T) {
					t.Parallel()
					target := testutil.NewServer(t, testutil.Serve(oc.ok))
					origin := testutil.NewServer(t, func(w http.ResponseWriter, r *http.Request) {
						if sameOrigin && r.URL.Path == "/elsewhere" {
							testutil.Serve(oc.ok)(w, r)
							return
						}
						dest := target.URL() + oc.path
						if sameOrigin {
							dest = "/elsewhere"
						}
						redirectingTo(status, dest)(w, r)
					})
					hc := &http.Client{Transport: origin.Client().Transport, CheckRedirect: followAll}
					c := newClientAt(t, origin.URL(), hc)

					err := oc.call(t.Context(), c)
					requireCallError(t, err, oc.wantFor(wantCall{Kind: bouncer.FailureUnexpectedResponse, StatusCode: status}))
					assert.Equal(t, 1, origin.Hits(), "exactly one attempt")
					assert.Zero(t, target.Hits(), "the redirect target is never contacted")
					assert.NoError(t, hc.CheckRedirect(nil, nil), "the injected client is not modified")
				})
			}
		}
	}
}

// TestRedirectControlLeaksTheKey is the control: the same injected client,
// used directly, follows a cross-origin redirect and sends the custom API key
// header to the target, which the standard library does not treat as
// sensitive.
func TestRedirectControlLeaksTheKey(t *testing.T) {
	t.Parallel()
	target := testutil.NewServer(t, testutil.Serve(jsonStep(creditsOK)))
	origin := testutil.NewServer(t, redirectingTo(http.StatusTemporaryRedirect, target.URL()+pathCredits))
	hc := &http.Client{Transport: origin.Client().Transport, CheckRedirect: followAll}
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, origin.URL()+pathCredits, nil)
	require.NoError(t, err)
	req.Header.Set("X-Api-Key", testKey)
	resp, err := hc.Do(req)
	require.NoError(t, err)
	_, _ = io.Copy(io.Discard, resp.Body)
	require.NoError(t, resp.Body.Close())
	got := testutil.OnlyRequest(t, target)
	assert.Equal(t, testKey, got.Header.Get("X-Api-Key"), "without the SDK's guard the key follows the redirect")
}

// TestRedirectLocationIsNeverRead answers with redirects whose Location the
// standard library cannot parse, and which hold markers: the SDK strips the
// header before the client reads it, so the call fails as an unexpected
// response rather than with an error that quotes the Location.
func TestRedirectLocationIsNeverRead(t *testing.T) {
	t.Parallel()
	locations := []string{
		"https://[::1" + testEmail,
		"https://example.org/%zz?key=" + testKey,
		"http://user:" + testKey + "@example.org/",
	}
	for _, loc := range locations {
		for _, status := range redirectStatuses() {
			t.Run(fmt.Sprintf("%d/%s", status, strings.SplitN(loc, ":", 2)[0]), func(t *testing.T) {
				t.Parallel()
				srv := testutil.NewServer(t, redirectingTo(status, loc))
				hc := &http.Client{Transport: srv.Client().Transport, CheckRedirect: followAll}
				c := newClientAt(t, srv.URL(), hc)
				_, err := c.Credits(t.Context())
				requireCallError(t, err, wantCall{Kind: bouncer.FailureUnexpectedResponse, Op: bouncer.OpCredits, StatusCode: status})
				testutil.AssertNeverPrints(t, err, markers()...)
				assert.Equal(t, 1, srv.Hits())
			})
		}
	}
}
