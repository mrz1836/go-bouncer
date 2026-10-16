package testutil_test

import (
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/mrz1836/go-bouncer/internal/testutil"
)

// dropSecond drops the second request a DropServer reads: the first warms up
// a keep-alive connection, which the second then reuses.
func dropSecond(n int) bool { return n == 2 }

// neverDrop answers every request.
func neverDrop(int) bool { return false }

// reply is a response as a client saw it, its body read and closed.
type reply struct {
	Status int
	Proto  string
	Header http.Header
	Body   string
}

// send makes one request through hc and returns its reply or the error. A
// GET with a nil body is one the standard library counts as safe to resend.
func send(t *testing.T, hc *http.Client, method, url string, body io.Reader) (reply, error) {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), method, url, body)
	require.NoError(t, err)
	resp, err := hc.Do(req)
	if err != nil {
		return reply{}, err
	}
	return reply{Status: resp.StatusCode, Proto: resp.Proto, Header: resp.Header, Body: readAll(t, resp)}, nil
}

func TestDropServerAnswersWithTheStep(t *testing.T) {
	t.Parallel()
	step := testutil.Step{Status: http.StatusTeapot, Header: http.Header{"X-Test": {"v"}}, Body: "tea"}
	srv := testutil.NewDropServer(t, step, neverDrop)
	hc := srv.Client()
	defer hc.CloseIdleConnections()

	r, err := send(t, hc, http.MethodGet, srv.URL()+"/p", nil)
	require.NoError(t, err)
	assert.Equal(t, http.StatusTeapot, r.Status)
	assert.Equal(t, "v", r.Header.Get("X-Test"))
	assert.Equal(t, "tea", r.Body)
	assert.Equal(t, "HTTP/1.1", r.Proto)
	assert.Equal(t, 1, srv.Hits())
	assert.Equal(t, 1, srv.Conns())
}

func TestDropServerAsksDropInOrder(t *testing.T) {
	t.Parallel()
	var (
		mu   sync.Mutex
		seen []int
	)
	srv := testutil.NewDropServer(t, testutil.Step{}, func(n int) bool {
		mu.Lock()
		defer mu.Unlock()
		seen = append(seen, n)
		return false
	})
	hc := srv.Client()
	defer hc.CloseIdleConnections()

	for range 3 {
		_, err := send(t, hc, http.MethodGet, srv.URL(), nil)
		require.NoError(t, err)
	}
	mu.Lock()
	defer mu.Unlock()
	assert.Equal(t, []int{1, 2, 3}, seen, "1-based, one call per request")
}

// TestDropServerDetectsResends is the HTTP/1 control: a GET with a nil body,
// which the standard library counts as safe to resend, is resent on a new
// connection when the reused one fails before the first response byte, so the
// server sees it twice. A client that trusts only RootCAs reaches the server.
func TestDropServerDetectsResends(t *testing.T) {
	t.Parallel()
	srv := testutil.NewDropServer(t, testutil.Step{Body: "{}"}, dropSecond)
	hc := &http.Client{Transport: &http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: srv.RootCAs(), MinVersion: tls.VersionTLS12},
	}}
	defer hc.CloseIdleConnections()

	for range 2 {
		r, err := send(t, hc, http.MethodGet, srv.URL(), nil)
		require.NoError(t, err, "the dropped request is resent and then answered")
		assert.Equal(t, reply{Status: http.StatusOK, Proto: "HTTP/1.1", Header: r.Header, Body: "{}"}, r)
	}
	assert.Equal(t, 3, srv.Hits(), "warm-up, dropped request, resend")
	assert.Equal(t, 2, srv.Conns(), "the resend dialed a new connection")
}

// TestDropServerDropIsSeenByTheClient drops a POST whose body cannot be
// rewound (io.NopCloser hides the reader's type from http.NewRequest), which
// the standard library never resends: the client sees the dropped connection,
// and the server reads the request once.
func TestDropServerDropIsSeenByTheClient(t *testing.T) {
	t.Parallel()
	srv := testutil.NewDropServer(t, testutil.Step{}, dropSecond)
	hc := srv.Client()
	defer hc.CloseIdleConnections()

	_, err := send(t, hc, http.MethodGet, srv.URL(), nil)
	require.NoError(t, err, "warm-up")
	_, err = send(t, hc, http.MethodPost, srv.URL(), io.NopCloser(strings.NewReader("payload")))
	require.Error(t, err)
	assert.Equal(t, 2, srv.Hits(), "warm-up and the dropped POST, never a resend")
	assert.Equal(t, 1, srv.Conns())
}

// TestDropServerClosesWhenTheTestEnds is not parallel: its subtest must end,
// and its cleanup close the server, before the test goes on.
func TestDropServerClosesWhenTheTestEnds(t *testing.T) {
	var (
		url string
		hc  *http.Client
	)
	t.Run("server", func(t *testing.T) {
		srv := testutil.NewDropServer(t, testutil.Step{}, neverDrop)
		url, hc = srv.URL(), srv.Client()
		_, err := send(t, hc, http.MethodGet, url, nil)
		require.NoError(t, err)
	})
	_, err := send(t, hc, http.MethodGet, url, nil)
	require.Error(t, err, "the subtest's cleanup closed the server")
}

// TestH2ServerDetectsResends is the HTTP/2 control. After a refused stream
// or a GOAWAY, every Go version resends a GET with a nil body, so the server
// reads two HEADERS frames for one request. After a protocol error, Go 1.26
// resends it and Go 1.27 and later do not, so either outcome passes as long
// as the count matches it. Only the first request is faulted: the next one is
// answered 200 with an empty body.
func TestH2ServerDetectsResends(t *testing.T) {
	t.Parallel()
	for _, fault := range testutil.H2Faults() {
		t.Run(string(fault), func(t *testing.T) {
			t.Parallel()
			srv := testutil.NewH2Server(t, fault)
			hc := &http.Client{Transport: srv.Transport()}
			defer hc.CloseIdleConnections()

			r, err := send(t, hc, http.MethodGet, srv.URL()+"/p", nil)
			if fault != testutil.H2ProtocolError {
				require.NoError(t, err, "resent on every Go version")
			}
			if err == nil {
				assert.Equal(t, reply{Status: http.StatusOK, Proto: "HTTP/2.0", Header: r.Header}, r)
				assert.Equal(t, 2, srv.Headers(), "the faulted request and its resend")
			} else {
				assert.Equal(t, 1, srv.Headers(), "failed, so never resent")
			}

			before := srv.Headers()
			r, err = send(t, hc, http.MethodGet, srv.URL()+"/p", nil)
			require.NoError(t, err)
			assert.Equal(t, reply{Status: http.StatusOK, Proto: "HTTP/2.0", Header: r.Header}, r)
			assert.Equal(t, before+1, srv.Headers(), "a later request is answered at once")
		})
	}
}

func TestNewH2ServerRejectsAnUnknownFault(t *testing.T) {
	t.Parallel()
	rec := &recorder{}
	assert.Nil(t, testutil.NewH2Server(rec, "unknown"))
	assert.True(t, rec.failed)
}

// TestH2ServerClosesWhenTheTestEnds proves the server's cleanup returns, with
// its listener closed and no goroutine left behind. It is not parallel: it
// counts the process's goroutines.
func TestH2ServerClosesWhenTheTestEnds(t *testing.T) {
	before := runtime.NumGoroutine()
	var addr string
	t.Run("server", func(t *testing.T) {
		srv := testutil.NewH2Server(t, testutil.H2RefusedStream)
		addr = strings.TrimPrefix(srv.URL(), "https://")
		hc := &http.Client{Transport: srv.Transport()}
		defer hc.CloseIdleConnections()
		_, err := send(t, hc, http.MethodGet, srv.URL(), nil)
		require.NoError(t, err)
	})

	var d net.Dialer
	conn, err := d.DialContext(t.Context(), "tcp", addr)
	if err == nil {
		_ = conn.Close()
	}
	require.Error(t, err, "the subtest's cleanup closed the listener")

	// A plain loop, not assert.Eventually, whose own goroutines would count.
	tick := time.NewTicker(5 * time.Millisecond)
	defer tick.Stop()
	for deadline := time.Now().Add(5 * time.Second); runtime.NumGoroutine() > before && time.Now().Before(deadline); {
		<-tick.C
	}
	assert.LessOrEqual(t, runtime.NumGoroutine(), before, "every server and client goroutine ended")
}
