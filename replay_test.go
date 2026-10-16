package bouncer_test

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/mrz1836/go-bouncer"
	"github.com/mrz1836/go-bouncer/internal/testutil"
)

// The harness's own tests (internal/testutil/replay_test.go) prove that both
// servers see a resend when Go's HTTP client makes one, so the counts below
// mean what they say.

// dropSecond drops the second request a DropServer reads: the first warms
// up a keep-alive connection, which the second then reuses.
func dropSecond(n int) bool { return n == 2 }

// warmUp makes a successful Credits call, which leaves an idle keep-alive
// connection in the client's pool.
func warmUp(t *testing.T, c *bouncer.Client) {
	t.Helper()
	_, err := c.Credits(t.Context())
	require.NoError(t, err, "warm-up call")
}

// TestHTTP1DroppedCallIsNotResent drops every operation's request on a reused
// HTTP/1.1 keep-alive connection after the server has read it: the call fails
// with ErrTransport, and the server sees it exactly once.
func TestHTTP1DroppedCallIsNotResent(t *testing.T) {
	t.Parallel()
	for _, oc := range opCases() {
		t.Run(oc.name, func(t *testing.T) {
			t.Parallel()
			srv := testutil.NewDropServer(t, jsonStep(creditsOK), dropSecond)
			c := newClientAt(t, srv.URL(), srv.Client())
			defer c.CloseIdleConnections()
			warmUp(t, c)

			err := oc.call(t.Context(), c)
			requireCallError(t, err, oc.wantFor(wantCall{Kind: bouncer.FailureTransport}))
			assert.Equal(t, 2, srv.Hits(), "warm-up and the dropped call, never a resend")
			assert.Equal(t, 1, srv.Conns(), "the dropped call reused the warm-up connection")
		})
	}
}

// TestHTTP2FaultIsNotResent sends every operation through an injected HTTP/2
// transport whose server faults the request in each way the HTTP/2 client may
// count as safe to retry: the call fails with ErrTransport, and the server
// reads one HEADERS frame.
//
// Finish is the documented exception. It is sent with http.NoBody, as a POST
// without a body must be to carry "Content-Length: 0", and the HTTP/2 client
// may resend it, depending on the fault and the Go version: Go 1.27 and later
// no longer retry after PROTOCOL_ERROR. Its outcome need only be consistent.
// Finish is free; the README says so.
func TestHTTP2FaultIsNotResent(t *testing.T) {
	t.Parallel()
	for _, fault := range testutil.H2Faults() {
		for _, oc := range opCases() {
			t.Run(string(fault)+"/"+oc.name, func(t *testing.T) {
				t.Parallel()
				srv := testutil.NewH2Server(t, fault)
				c := newClientAt(t, srv.URL(), &http.Client{Transport: srv.Transport()})
				defer c.CloseIdleConnections()

				err := oc.call(t.Context(), c)
				notResent := oc.wantFor(wantCall{Kind: bouncer.FailureTransport})
				if oc.op == bouncer.OpBatchFinish {
					requireResendConsistent(t, err, srv.Headers(), notResent)
					return
				}
				requireCallError(t, err, notResent)
				assert.Equal(t, 1, srv.Headers(), "one HEADERS frame: never resent")
			})
		}
	}
}

// requireResendConsistent fails tb unless a call that the HTTP/2 client may
// resend shows one of the two consistent outcomes: resent once and answered
// (no error, two HEADERS frames), or not resent and failed as notResent
// describes (one HEADERS frame). The server answers the resend with 200 and
// an empty body.
func requireResendConsistent(tb testing.TB, err error, headers int, notResent wantCall) {
	tb.Helper()
	if err == nil {
		assert.Equal(tb, 2, headers, "answered after the fault, so resent once")
		return
	}
	requireCallError(tb, err, notResent)
	assert.Equal(tb, 1, headers, "failed, so never resent")
}
