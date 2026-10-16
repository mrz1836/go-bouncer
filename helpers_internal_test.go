package bouncer

import (
	"crypto/x509"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/mrz1836/go-bouncer/internal/testutil"
)

// testKey is the synthetic API key of the internal tests. It doubles as a
// leak marker.
const testKey = testutil.APIKey

// loopbackOrigin is a test base URL for in-memory transports, which never
// dial.
const loopbackOrigin = "https://127.0.0.1"

// verifyAnswer is the smallest successful Verify answer, and one record of a
// batch-sync or Results answer.
const verifyAnswer = `{"email":"avery.example@example.com","status":"deliverable","reason":"accepted_email"}`

// jsonAnswer is a scripted answer with status and a JSON content type.
func jsonAnswer(status int, body string) testutil.Step {
	return testutil.Step{Status: status, Header: http.Header{"Content-Type": {mediaJSON}}, Body: body}
}

// newTestClient returns a Client with the test key that sends every call to
// the in-memory transport rt, never dialing, with opts after the test
// settings. A test that makes no call may pass a nil rt.
func newTestClient(tb testing.TB, rt http.RoundTripper, opts ...Option) *Client {
	tb.Helper()
	all := append([]Option{WithTestBaseURL(loopbackOrigin), WithHTTPClient(&http.Client{Transport: rt})}, opts...)
	c, err := NewClient(testKey, all...)
	require.NoError(tb, err)
	return c
}

// requireDecodeError fails t unless err is a *decodeError, not a nil one,
// with kind, cause and field. It takes a *decodeError as well as an error that
// wraps one.
func requireDecodeError(t *testing.T, err error, kind FailureKind, cause error, field string) {
	t.Helper()
	derr := testutil.RequireErrorAs[*decodeError](t, err)
	require.NotNil(t, derr, "want a decode failure")
	assert.Equal(t, kind, derr.kind, "kind")
	assert.Equal(t, cause, derr.cause, "cause")
	assert.Equal(t, field, derr.field, "field")
}

// ownTransportClient returns a Client for the loopback server at baseURL that
// uses the SDK's own transport, exactly as NewClient builds it without
// WithHTTPClient, except that it trusts pool so that it can reach a test
// server. It returns that transport too. Its idle connections are closed when
// the test ends.
func ownTransportClient(tb testing.TB, baseURL string, pool *x509.CertPool) (*Client, *http.Transport) {
	tb.Helper()
	c, err := NewClient(testKey, WithTestBaseURL(baseURL))
	require.NoError(tb, err)
	var o options
	hc := o.client()
	guard, ok := hc.Transport.(redirectGuard)
	require.True(tb, ok, "the transport is wrapped in the redirect guard")
	own, ok := guard.next.(*http.Transport)
	require.True(tb, ok, "the guard wraps the SDK's own *http.Transport")
	own.TLSClientConfig.RootCAs = pool
	c.send = newSender(hc, strings.TrimPrefix(baseURL, "https://"), testKey, defaultUserAgent)
	c.closeIdle = hc.CloseIdleConnections
	tb.Cleanup(c.CloseIdleConnections)
	return c, own
}
