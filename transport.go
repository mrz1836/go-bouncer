package bouncer

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"syscall"
	"time"
)

// Transport settings of the SDK's own transport.
const (
	// dialTimeout and tlsHandshakeTimeout bound connection setup, 20 seconds
	// together, which DefaultTimeout leaves room for.
	dialTimeout         = 10 * time.Second
	dialKeepAlive       = 30 * time.Second
	tlsHandshakeTimeout = 10 * time.Second

	// idleConnTimeout is short, so that a pooled connection the server is
	// about to close is rarely picked for the next call: such a call fails
	// with a transport error, and the SDK never resends it.
	idleConnTimeout     = 4 * time.Second
	maxIdleConnsPerHost = 8

	// maxResponseHeaderBytes bounds the response headers on the SDK's own
	// transport.
	maxResponseHeaderBytes = 64 << 10
)

// sender makes the one attempt of a call. Everything it needs, the API key
// included, is captured inside the function: fmt prints a func value only as
// an address, and reflection-based dumpers cannot see what a closure captures.
// An error is errBuildRequest or the http.Client's own error, which the caller
// classifies and drops.
type sender func(ctx context.Context, out *outgoing) (*http.Response, error)

// newSender returns the sender for a validated configuration.
func newSender(hc *http.Client, host, apiKey, userAgent string) sender {
	return func(ctx context.Context, out *outgoing) (*http.Response, error) {
		req, err := out.request(ctx, host)
		if err != nil {
			return nil, errBuildRequest
		}
		req.Header = out.header(apiKey, userAgent)
		return hc.Do(req)
	}
}

// client returns the HTTP client calls use: a copy of the injected client, or a
// new one on a fresh transport, that never follows a redirect and keeps no
// cookies.
func (o *options) client() *http.Client {
	var c http.Client
	if o.httpClientSet {
		c = *o.httpClient
	} else {
		c.Transport = newTransport()
	}
	next := c.Transport
	if next == nil {
		next = http.DefaultTransport
	}
	c.Transport = redirectGuard{next: next}
	c.CheckRedirect = refuseRedirect
	c.Jar = nil
	return &c
}

// newTransport returns the SDK's own transport, built from scratch rather
// than cloned from http.DefaultTransport, whose settings would bring HTTP/2
// and the proxy environment variables back in:
//   - HTTP/1.1 only, so that the HTTP/2 client's own retries (after a refused
//     stream, a GOAWAY or, depending on the Go version, a protocol error)
//     never apply;
//   - TLS 1.2 or later;
//   - no proxy: the proxy environment variables are never read (inject an
//     http.Client to use a proxy);
//   - its own small connection pool with a short idle timeout;
//   - no response-header timeout: the call's context deadline is the one
//     clock.
func newTransport() *http.Transport {
	var protocols http.Protocols
	protocols.SetHTTP1(true)
	dialer := &net.Dialer{Timeout: dialTimeout, KeepAlive: dialKeepAlive}
	return &http.Transport{
		Proxy:       nil,
		DialContext: dialer.DialContext,
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
			NextProtos: []string{"http/1.1"},
		},
		TLSNextProto:           map[string]func(string, *tls.Conn) http.RoundTripper{},
		Protocols:              &protocols,
		TLSHandshakeTimeout:    tlsHandshakeTimeout,
		MaxIdleConns:           maxIdleConnsPerHost,
		MaxIdleConnsPerHost:    maxIdleConnsPerHost,
		IdleConnTimeout:        idleConnTimeout,
		MaxResponseHeaderBytes: maxResponseHeaderBytes,
	}
}

// refuseRedirect stops the client at the first response, so the API key is
// never sent to another URL.
func refuseRedirect(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

// redirectGuard removes the Location header from every 3xx response before the
// http.Client sees it. The client then returns the response as it is: it
// neither follows the redirect, which would resend the API key header and the
// body to the new URL, with a Referer quoting the old one, nor fails on an
// unparsable Location with an error that quotes it.
type redirectGuard struct {
	next http.RoundTripper
}

// RoundTrip passes r to the wrapped transport and strips Location from a 3xx.
func (g redirectGuard) RoundTrip(r *http.Request) (*http.Response, error) {
	resp, err := g.next.RoundTrip(r)
	if resp != nil && resp.StatusCode >= http.StatusMultipleChoices && resp.StatusCode < http.StatusBadRequest {
		resp.Header.Del("Location")
	}
	return resp, err
}

// CloseIdleConnections closes the wrapped transport's idle connections, if it
// has any, so that (*http.Client).CloseIdleConnections still reaches it.
func (g redirectGuard) CloseIdleConnections() {
	if c, ok := g.next.(interface{ CloseIdleConnections() }); ok {
		c.CloseIdleConnections()
	}
}

// classify maps a failed exchange onto a CallError: the caller's context
// first, then a timeout (this call's deadline, an http.Client Timeout, or any
// network timeout), else a transport failure of a fixed class. The original
// error is never kept.
func classify(caller, callCtx context.Context, op Operation, err error, status int) *CallError {
	if cerr := caller.Err(); cerr != nil {
		return contextFailure(op, cerr, status)
	}
	if callCtx.Err() != nil || errors.Is(err, context.DeadlineExceeded) || isNetTimeout(err) {
		return newCallError(op, FailureTimeout, status, context.DeadlineExceeded)
	}
	if errors.Is(err, errResponseTooLarge) {
		return newCallError(op, FailureResponseTooLarge, status, errResponseTooLarge)
	}
	return newCallError(op, FailureTransport, status, transportClass(err))
}

// isNetTimeout reports whether err is a network error that timed out, such as
// a dial or TLS handshake timeout, or an http.Client Timeout.
func isNetTimeout(err error) bool {
	ne, ok := errors.AsType[net.Error](err)
	return ok && ne.Timeout()
}

// transportClass reduces a transport error to one of a few fixed classes.
func transportClass(err error) error {
	if errors.Is(err, errTransportStalled) {
		return errTransportStalled
	}
	if errors.Is(err, errBuildRequest) {
		return errTransportOther
	}
	if _, ok := errors.AsType[*net.DNSError](err); ok {
		return errTransportDNS
	}
	var op string
	if oe, ok := errors.AsType[*net.OpError](err); ok {
		op = oe.Op
	}
	if op == "proxyconnect" {
		return errTransportProxy
	}
	if isTLSError(err) {
		return errTransportTLS
	}
	if errors.Is(err, syscall.ECONNRESET) || errors.Is(err, syscall.ECONNABORTED) || errors.Is(err, syscall.EPIPE) {
		return errTransportReset
	}
	if op == "dial" {
		return errTransportDial
	}
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, net.ErrClosed) {
		return errTransportClosed
	}
	return errTransportOther
}

// isTLSError reports whether err comes from the TLS handshake or record layer.
// Over TCP, crypto/tls reports an alert as a *net.OpError whose Op is
// "remote error" (received) or "local error" (sent), wrapping an unexported
// type.
func isTLSError(err error) bool {
	if oe, ok := errors.AsType[*net.OpError](err); ok && (oe.Op == "remote error" || oe.Op == "local error") {
		return true
	}
	if _, ok := errors.AsType[*tls.CertificateVerificationError](err); ok {
		return true
	}
	if _, ok := errors.AsType[tls.RecordHeaderError](err); ok {
		return true
	}
	_, ok := errors.AsType[tls.AlertError](err)
	return ok
}
