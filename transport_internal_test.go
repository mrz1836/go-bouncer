package bouncer

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"reflect"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"testing/synctest"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/mrz1836/go-bouncer/internal/testutil"
)

func TestNewTransportSettings(t *testing.T) {
	t.Parallel()
	tr := newTransport()
	assert.Nil(t, tr.Proxy, "no proxy: the environment is never read")
	require.NotNil(t, tr.Protocols)
	assert.True(t, tr.Protocols.HTTP1())
	assert.False(t, tr.Protocols.HTTP2())
	assert.False(t, tr.Protocols.UnencryptedHTTP2())
	require.NotNil(t, tr.TLSNextProto, "an empty, non-nil map disables HTTP/2")
	assert.Empty(t, tr.TLSNextProto)
	require.NotNil(t, tr.TLSClientConfig)
	assert.Equal(t, uint16(tls.VersionTLS12), tr.TLSClientConfig.MinVersion)
	assert.Equal(t, []string{"http/1.1"}, tr.TLSClientConfig.NextProtos)
	assert.False(t, tr.TLSClientConfig.InsecureSkipVerify)
	assert.Nil(t, tr.TLSClientConfig.RootCAs, "the system roots")
	assert.False(t, tr.ForceAttemptHTTP2)
	assert.NotNil(t, tr.DialContext)
	assert.Nil(t, tr.DialTLSContext)
	assert.Equal(t, 10*time.Second, tr.TLSHandshakeTimeout)
	assert.Equal(t, 8, tr.MaxIdleConnsPerHost)
	assert.Equal(t, 8, tr.MaxIdleConns)
	assert.Zero(t, tr.MaxConnsPerHost)
	assert.Equal(t, 4*time.Second, tr.IdleConnTimeout)
	assert.Equal(t, int64(64<<10), tr.MaxResponseHeaderBytes)
	assert.Zero(t, tr.ResponseHeaderTimeout, "the call's context deadline is the one clock")
	assert.Zero(t, tr.ExpectContinueTimeout)
	assert.False(t, tr.DisableKeepAlives)
	assert.False(t, tr.DisableCompression)
	assert.Nil(t, tr.OnProxyConnectResponse)
	assert.Nil(t, tr.GetProxyConnectHeader)

	assert.NotSame(t, newTransport(), tr, "each Client gets its own transport and pool")
	assert.NotSame(t, newTransport().TLSClientConfig, tr.TLSClientConfig)

	assert.Equal(t, 10*time.Second, dialTimeout)
	assert.Equal(t, 30*time.Second, dialKeepAlive)
}

// transportRT is an injected transport for options.client.
type transportRT struct{}

// RoundTrip is never called.
func (transportRT) RoundTrip(*http.Request) (*http.Response, error) { return nil, errUnusedTransport }

var errUnusedTransport = errors.New("transport test: unused transport")

func TestOptionsClient(t *testing.T) {
	t.Parallel()
	t.Run("own transport", func(t *testing.T) {
		t.Parallel()
		hc := (&options{}).client()
		guard, ok := hc.Transport.(redirectGuard)
		require.True(t, ok, "the transport is wrapped in the redirect guard")
		_, ok = guard.next.(*http.Transport)
		require.True(t, ok, "the guard wraps the SDK's own *http.Transport")
		require.NotNil(t, hc.CheckRedirect)
		require.ErrorIs(t, hc.CheckRedirect(nil, nil), http.ErrUseLastResponse)
		assert.Nil(t, hc.Jar)
		assert.Zero(t, hc.Timeout)
	})

	t.Run("injected client is copied", func(t *testing.T) {
		t.Parallel()
		jar, err := cookiejar.New(nil)
		require.NoError(t, err)
		rt := transportRT{}
		injected := &http.Client{Transport: rt, Jar: jar, Timeout: 9 * time.Second}
		o := &options{httpClient: injected, httpClientSet: true}
		hc := o.client()
		assert.NotSame(t, injected, hc)
		assert.Equal(t, redirectGuard{next: rt}, hc.Transport)
		require.NotNil(t, hc.CheckRedirect)
		require.ErrorIs(t, hc.CheckRedirect(nil, nil), http.ErrUseLastResponse)
		assert.Nil(t, hc.Jar)
		assert.Equal(t, 9*time.Second, hc.Timeout)

		assert.Equal(t, rt, injected.Transport, "the caller's client keeps its transport")
		assert.Nil(t, injected.CheckRedirect)
		assert.Same(t, jar, injected.Jar)
		assert.Equal(t, 9*time.Second, injected.Timeout)
	})

	t.Run("nil transport means the default", func(t *testing.T) {
		t.Parallel()
		o := &options{httpClient: &http.Client{}, httpClientSet: true}
		assert.Equal(t, redirectGuard{next: http.DefaultTransport}, o.client().Transport)
	})

	t.Run("a custom CheckRedirect is replaced on the copy only", func(t *testing.T) {
		t.Parallel()
		called := false
		injected := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
			called = true
			return nil
		}}
		hc := (&options{httpClient: injected, httpClientSet: true}).client()
		require.ErrorIs(t, hc.CheckRedirect(nil, nil), http.ErrUseLastResponse)
		assert.False(t, called)
		assert.NotEqual(t, reflect.ValueOf(injected.CheckRedirect).Pointer(), reflect.ValueOf(hc.CheckRedirect).Pointer())
	})
}

// transportTLSServer starts a TLS server that may offer HTTP/2 and counts its
// new connections, and returns a Client on the SDK's own transport that
// trusts it, so that the transport's settings meet a real TLS server.
func transportTLSServer(t *testing.T, enableHTTP2 bool, h http.HandlerFunc) (
	*httptest.Server, *atomic.Int32, *Client, *http.Transport,
) {
	t.Helper()
	var conns atomic.Int32
	srv := httptest.NewUnstartedServer(h)
	srv.EnableHTTP2 = enableHTTP2
	srv.Config.ConnState = func(_ net.Conn, s http.ConnState) {
		if s == http.StateNew {
			conns.Add(1)
		}
	}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	c, tr := ownTransportClient(t, srv.URL, pool)
	return srv, &conns, c, tr
}

// TestOwnTransportSpeaksHTTP1Only checks that the SDK's own transport
// negotiates HTTP/1.1, on its own and through a Client, even with a server
// that offers HTTP/2.
func TestOwnTransportSpeaksHTTP1Only(t *testing.T) {
	t.Parallel()
	var (
		mu     sync.Mutex
		protos []string
	)
	srv, _, c, tr := transportTLSServer(t, true, func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		protos = append(protos, r.Proto)
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"credits":7}`)
	})

	// Control: a client that offers h2 gets it, so the server does offer it.
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, srv.URL, nil)
	require.NoError(t, err)
	resp, err := srv.Client().Do(req)
	require.NoError(t, err)
	_, _ = io.Copy(io.Discard, resp.Body)
	require.NoError(t, resp.Body.Close())
	require.Equal(t, "HTTP/2.0", resp.Proto)

	raw, err := http.NewRequestWithContext(t.Context(), http.MethodGet, srv.URL, nil)
	require.NoError(t, err)
	resp, err = (&http.Client{Transport: tr}).Do(raw)
	require.NoError(t, err)
	_, _ = io.Copy(io.Discard, resp.Body)
	require.NoError(t, resp.Body.Close())
	assert.Equal(t, "HTTP/1.1", resp.Proto)
	require.NotNil(t, resp.TLS)
	assert.Contains(t, []string{"", "http/1.1"}, resp.TLS.NegotiatedProtocol)
	assert.GreaterOrEqual(t, resp.TLS.Version, uint16(tls.VersionTLS12))

	_, err = c.Credits(t.Context())
	require.NoError(t, err)
	mu.Lock()
	defer mu.Unlock()
	assert.Equal(t, []string{"HTTP/2.0", "HTTP/1.1", "HTTP/1.1"}, protos)
}

func TestOwnTransportReusesConnections(t *testing.T) {
	t.Parallel()
	_, conns, c, _ := transportTLSServer(t, false, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"credits":7}`)
	})
	for range 3 {
		_, err := c.Credits(t.Context())
		require.NoError(t, err)
	}
	assert.Equal(t, int32(1), conns.Load(), "the SDK reads and closes each body, so the connection is reused")

	c.CloseIdleConnections()
	_, err := c.Credits(t.Context())
	require.NoError(t, err)
	assert.Equal(t, int32(2), conns.Load(), "CloseIdleConnections drops the pooled connection")
}

func TestOwnTransportReusesAfterAnErrorStatus(t *testing.T) {
	t.Parallel()
	_, conns, c, _ := transportTLSServer(t, false, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Query().Get("email") != "" {
			w.WriteHeader(http.StatusPaymentRequired)
			_, _ = io.WriteString(w, `{"status":"402","error":"Payment Required","message":"synthetic"}`)
			return
		}
		_, _ = io.WriteString(w, `{"credits":7}`)
	})
	_, err := c.Verify(t.Context(), VerifyRequest{Email: "avery.example@example.com"})
	require.ErrorIs(t, err, ErrPaymentRequired)
	_, err = c.Credits(t.Context())
	require.NoError(t, err)
	assert.Equal(t, int32(1), conns.Load(), "an error excerpt is read whole, so the connection is reused")
}

// transportStatusRT answers with a status and a Location header.
type transportStatusRT struct {
	status int
	idle   atomic.Int32
}

// RoundTrip answers with the configured status and a Location.
func (s *transportStatusRT) RoundTrip(r *http.Request) (*http.Response, error) {
	resp := testutil.Response(r, s.status, http.NoBody, 0)
	resp.Header.Set("Location", "https://other.example.org/"+testKey)
	return resp, nil
}

// CloseIdleConnections counts the call.
func (s *transportStatusRT) CloseIdleConnections() { s.idle.Add(1) }

func TestRedirectGuard(t *testing.T) {
	t.Parallel()
	for status := 100; status < 600; status++ {
		if http.StatusText(status) == "" {
			continue
		}
		next := &transportStatusRT{status: status}
		g := redirectGuard{next: next}
		req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "https://127.0.0.1/", nil)
		require.NoError(t, err)
		resp, err := g.RoundTrip(req)
		require.NoError(t, err)
		require.NoError(t, resp.Body.Close())
		if status >= 300 && status < 400 {
			assert.Empty(t, resp.Header.Values("Location"), "HTTP %d", status)
		} else {
			assert.NotEmpty(t, resp.Header.Values("Location"), "HTTP %d keeps its headers", status)
		}
	}

	t.Run("an error passes through", func(t *testing.T) {
		t.Parallel()
		g := redirectGuard{next: transportRT{}}
		req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "https://127.0.0.1/", nil)
		require.NoError(t, err)
		resp, err := g.RoundTrip(req) //nolint:bodyclose // there is no response
		assert.Nil(t, resp)
		require.ErrorIs(t, err, errUnusedTransport)
	})

	t.Run("a nil header is tolerated", func(t *testing.T) {
		t.Parallel()
		g := redirectGuard{next: testutil.RoundTripFunc(func(r *http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: http.StatusFound, Body: http.NoBody, Request: r}, nil
		})}
		req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "https://127.0.0.1/", nil)
		require.NoError(t, err)
		resp, err := g.RoundTrip(req)
		require.NoError(t, err)
		require.NoError(t, resp.Body.Close())
	})

	t.Run("CloseIdleConnections is forwarded", func(t *testing.T) {
		t.Parallel()
		next := &transportStatusRT{status: http.StatusOK}
		redirectGuard{next: next}.CloseIdleConnections()
		assert.Equal(t, int32(1), next.idle.Load())
		assert.NotPanics(t, redirectGuard{next: transportRT{}}.CloseIdleConnections)
	})
}

// transportMarker is planted in synthetic errors; it must never surface.
const transportMarker = "marker.example.org/" + testKey

// Synthetic errors whose text must never surface.
var (
	errTransportTestMarker     = errors.New(transportMarker)
	errTransportTestClosedBody = errors.New("http: read on closed response body")
)

func TestClassify(t *testing.T) {
	t.Parallel()
	bg := context.Background()
	canceled, cancel := context.WithCancel(bg)
	cancel()
	expired, cancelExpired := context.WithDeadline(bg, time.Now().Add(-time.Second))
	t.Cleanup(cancelExpired)

	urlErr := func(err error) error { return &url.Error{Op: "Get", URL: "https://" + transportMarker, Err: err} }
	tests := []struct {
		name    string
		caller  context.Context //nolint:containedctx // a test table
		callCtx context.Context //nolint:containedctx // a test table
		err     error
		kind    FailureKind
		cause   error
		class   string
	}{
		{"DNS", bg, bg, urlErr(&net.DNSError{Err: "no such host", Name: transportMarker}), FailureTransport, errTransportDNS, "dns"},
		{
			"DNS inside a dial error", bg, bg,
			urlErr(&net.OpError{Op: "dial", Net: "tcp", Err: &net.DNSError{Err: "no such host", Name: transportMarker}}),
			FailureTransport, errTransportDNS, "dns",
		},
		{
			"dial", bg, bg, urlErr(&net.OpError{Op: "dial", Net: "tcp", Err: errTransportTestMarker}),
			FailureTransport, errTransportDial, "dial",
		},
		{
			"proxy", bg, bg, urlErr(&net.OpError{Op: "proxyconnect", Net: "tcp", Err: errTransportTestMarker}),
			FailureTransport, errTransportProxy, "proxy",
		},
		{
			"reset", bg, bg, urlErr(&net.OpError{Op: "read", Net: "tcp", Err: syscall.ECONNRESET}),
			FailureTransport, errTransportReset, "reset",
		},
		{"broken pipe", bg, bg, urlErr(&net.OpError{Op: "write", Err: syscall.EPIPE}), FailureTransport, errTransportReset, "reset"},
		{"aborted", bg, bg, urlErr(syscall.ECONNABORTED), FailureTransport, errTransportReset, "reset"},
		{"EOF", bg, bg, urlErr(io.EOF), FailureTransport, errTransportClosed, "closed"},
		{"unexpected EOF", bg, bg, io.ErrUnexpectedEOF, FailureTransport, errTransportClosed, "closed"},
		{"closed", bg, bg, fmt.Errorf("read %s: %w", transportMarker, net.ErrClosed), FailureTransport, errTransportClosed, "closed"},
		{"TLS record", bg, bg, urlErr(tls.RecordHeaderError{Msg: transportMarker}), FailureTransport, errTransportTLS, "tls"},
		{"TLS alert", bg, bg, urlErr(&net.OpError{Op: "remote error", Err: tls.AlertError(40)}), FailureTransport, errTransportTLS, "tls"},
		{
			"TLS verification", bg, bg,
			urlErr(&tls.CertificateVerificationError{Err: x509.UnknownAuthorityError{}}),
			FailureTransport, errTransportTLS, "tls",
		},
		{"stalled", bg, bg, errTransportStalled, FailureTransport, errTransportStalled, "stalled"},
		{"build request", bg, bg, errBuildRequest, FailureTransport, errTransportOther, "other"},
		{"anything else", bg, bg, urlErr(errTransportTestMarker), FailureTransport, errTransportOther, "other"},
		{"net timeout", bg, bg, urlErr(testutil.TimeoutError{Msg: transportMarker}), FailureTimeout, context.DeadlineExceeded, ""},
		{"deadline error", bg, bg, urlErr(context.DeadlineExceeded), FailureTimeout, context.DeadlineExceeded, ""},
		{"too large", bg, bg, errResponseTooLarge, FailureResponseTooLarge, errResponseTooLarge, ""},
		{"caller canceled", canceled, canceled, urlErr(context.Canceled), FailureCanceled, context.Canceled, ""},
		{
			"caller canceled wins over a transport error", canceled, canceled, urlErr(io.EOF),
			FailureCanceled, context.Canceled, "",
		},
		{"caller deadline", expired, expired, urlErr(context.DeadlineExceeded), FailureDeadlineExceeded, context.DeadlineExceeded, ""},
		{"call deadline", bg, expired, urlErr(io.EOF), FailureTimeout, context.DeadlineExceeded, ""},
		{"call deadline canceled body", bg, expired, errTransportTestClosedBody, FailureTimeout, context.DeadlineExceeded, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ce := classify(tt.caller, tt.callCtx, OpVerify, tt.err, 200)
			require.NotNil(t, ce)
			assert.Equal(t, tt.kind, ce.Kind)
			assert.Equal(t, OpVerify, ce.Op)
			assert.Equal(t, 200, ce.StatusCode)
			assert.Equal(t, tt.cause, ce.Unwrap(), "the cause is a fixed error, never the original")
			assert.Equal(t, tt.class, ce.detail().class)
			if tt.class != "" {
				assert.Equal(t, "bouncer: verify: transport (HTTP 200): "+tt.class, ce.Error())
			}

			var err error = ce
			assert.NotContains(t, err.Error(), transportMarker)
			assert.NotContains(t, fmt.Sprintf("%+v %#v", err, err), transportMarker)
			_, isURL := errors.AsType[*url.Error](err)
			assert.False(t, isURL)
			_, isOp := errors.AsType[*net.OpError](err)
			assert.False(t, isOp)
			_, isDNS := errors.AsType[*net.DNSError](err)
			assert.False(t, isDNS)
			if ne, isNet := errors.AsType[net.Error](err); isNet {
				// context.DeadlineExceeded is itself a net.Error: the only one
				// a CallError may hold.
				assert.Equal(t, context.DeadlineExceeded, ne)
			}
			if !errors.Is(tt.cause, tt.err) {
				assert.NotErrorIs(t, err, tt.err, "the original error is not reachable")
			}
		})
	}
}

// TestSenderNeverSendsAnUnbuildableRequest checks the one way building a
// request can fail, an invalid method, which no call uses: nothing reaches
// the transport, and the error is the fixed errBuildRequest, whose transport
// class is "other".
func TestSenderNeverSendsAnUnbuildableRequest(t *testing.T) {
	t.Parallel()
	counter := &testutil.CountingTransport{Next: testutil.StaticTransport(http.StatusOK, `{}`)}
	send := newSender(&http.Client{Transport: counter}, "127.0.0.1", testKey, defaultUserAgent)
	resp, err := send(t.Context(), &outgoing{op: OpCredits, method: "BAD METHOD", path: pathCredits}) //nolint:bodyclose // there is no response
	assert.Nil(t, resp)
	require.ErrorIs(t, err, errBuildRequest)
	assert.Zero(t, counter.Attempts())
	assert.Equal(t, errTransportOther, transportClass(err))
}

func TestOpenClassifiesSendErrors(t *testing.T) {
	t.Parallel()
	send := sender(func(context.Context, *outgoing) (*http.Response, error) {
		return nil, &url.Error{Op: "Get", URL: "https://" + transportMarker, Err: io.EOF}
	})
	ctx := context.Background()
	resp, release, cerr := open(ctx, ctx, send, &outgoing{op: OpCredits}) //nolint:bodyclose // there is no response
	assert.Nil(t, resp)
	assert.Nil(t, release)
	require.NotNil(t, cerr)
	assert.Equal(t, FailureTransport, cerr.Kind)
	assert.Zero(t, cerr.StatusCode)
	assert.NotContains(t, cerr.Error(), transportMarker)
}

func TestOpenClosesTheBodyOnceAtTheDeadline(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		body := testutil.NewBody("{}")
		send := sender(func(ctx context.Context, out *outgoing) (*http.Response, error) {
			req, err := out.request(ctx, "127.0.0.1")
			if err != nil {
				return nil, err
			}
			return testutil.Response(req, http.StatusOK, body, 2), nil
		})
		ctx := context.Background()
		callCtx, cancel := context.WithCancel(ctx)
		resp, guard, cerr := open(ctx, callCtx, send, &outgoing{op: OpCredits, method: http.MethodGet, path: pathCredits}) //nolint:bodyclose // closed by guard.release
		require.Nil(t, cerr)
		require.NotNil(t, resp)
		assert.Zero(t, body.Closes())
		cancel()
		synctest.Wait()
		assert.Equal(t, 1, body.Closes(), "the end of the call closes the body")
		guard.release()
		guard.release()
		assert.Equal(t, 1, body.Closes(), "the body is closed exactly once")
	})

	t.Run("release without a deadline", func(t *testing.T) {
		t.Parallel()
		body := testutil.NewBody("{}")
		send := sender(func(ctx context.Context, out *outgoing) (*http.Response, error) {
			req, err := out.request(ctx, "127.0.0.1")
			if err != nil {
				return nil, err
			}
			return testutil.Response(req, http.StatusOK, body, 2), nil
		})
		ctx := context.Background()
		callCtx, cancel := context.WithCancel(ctx)
		defer cancel()
		_, guard, cerr := open(ctx, callCtx, send, &outgoing{op: OpCredits, method: http.MethodGet, path: pathCredits}) //nolint:bodyclose // closed by guard.release
		require.Nil(t, cerr)
		guard.release()
		cancel()
		assert.Equal(t, 1, body.Closes(), "the stopped AfterFunc never closes it again")
	})
}

// TestRealTLSAlertIsClassifiedAsTLS drives a real TLS alert over TCP: a
// server that requires a client certificate the client does not send. The
// alert reaches the SDK as a *net.OpError ("remote error"), which must be
// classified as the tls transport class.
func TestRealTLSAlertIsClassifiedAsTLS(t *testing.T) {
	t.Parallel()
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	srv.TLS = &tls.Config{ClientAuth: tls.RequireAnyClientCert, MinVersion: tls.VersionTLS12}
	srv.Config.ErrorLog = log.New(io.Discard, "", 0)
	srv.StartTLS()
	defer srv.Close()

	c, err := NewClient(testKey, WithTestBaseURL(srv.URL), WithHTTPClient(srv.Client()))
	require.NoError(t, err)
	_, err = c.Credits(t.Context())
	ce := testutil.RequireErrorAs[*CallError](t, err)
	assert.Equal(t, FailureTransport, ce.Kind)
	assert.Equal(t, "bouncer: credits: transport: tls", ce.Error())
}
