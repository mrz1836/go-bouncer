package bouncer

import (
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Defaults and limits.
const (
	// DefaultTimeout bounds each buffered call, including reading the whole
	// response body: up to 20 seconds of dial and TLS handshake, the
	// provider's 30-second verification maximum and a margin. WithTimeout
	// accepts more than 0 and at most 10 minutes.
	DefaultTimeout = 60 * time.Second

	// DefaultMaxResponseBytes limits a buffered response body.
	// WithMaxResponseBytes accepts 1 byte to 64 MiB. Every buffered call except
	// VerifyBatchSync is also capped at 1 MiB, far above any documented answer.
	DefaultMaxResponseBytes = 16 << 20

	// DefaultDownloadTimeout bounds a whole Results or Download call,
	// streaming included. WithDownloadTimeout accepts more than 0 and at most
	// 12 hours.
	DefaultDownloadTimeout = 30 * time.Minute

	// DefaultMaxDownloadBytes limits the bytes Results reads and Download
	// copies to its writer. WithMaxDownloadBytes accepts 1 byte to 64 GiB.
	DefaultMaxDownloadBytes = 1 << 30

	// DefaultWaitInterval is Wait's pause between polls when
	// WaitBatchRequest.Interval is 0.
	DefaultWaitInterval = 10 * time.Second

	// MaxVerifyTimeout is the provider's documented maximum for
	// VerifyRequest.Timeout.
	MaxVerifyTimeout = 30 * time.Second

	// MaxEmailBytes is the longest address, in bytes, any call accepts.
	MaxEmailBytes = 1024

	// MaxBatchEntries is the provider's documented maximum number of entries
	// in one batch. Its technical documentation says 100,000; a marketing page
	// says 500,000, which the SDK does not use.
	MaxBatchEntries = 100_000

	// MaxSyncEmails is the provider's documented maximum number of addresses
	// in one VerifyBatchSync call.
	MaxSyncEmails = 10_000
)

// Internal bounds.
const (
	// productionHost is the only server the provider documents. Calls to it are
	// live and may be billed.
	productionHost = "api.usebouncer.com"

	// apiRoot is the path prefix of every call: API version 1.1 only.
	apiRoot = "/v1.1"

	// defaultUserAgent is the User-Agent header when WithUserAgent is not set.
	defaultUserAgent = "go-bouncer"

	maxTimeout            = 10 * time.Minute
	maxResponseBytesLimit = 64 << 20
	smallResponseCap      = 1 << 20
	maxDownloadTimeout    = 12 * time.Hour
	maxDownloadBytesLimit = 64 << 30
	maxKeyBytes           = 256
	maxUserAgentBytes     = 256
)

// Client calls the Bouncer API v1.1. Create it with NewClient; the zero Client
// and a nil *Client return ErrInvalidConfig without any I/O. A Client is
// immutable and safe for concurrent use.
//
// Its fields are unexported and the API key is held only inside function
// values, so formatting a Client, or a struct holding one, with any fmt verb or
// a reflection-based dumper never prints it.
type Client struct {
	send      sender
	closeIdle func()
	scrub     func(string) string

	userAgent        string
	timeout          time.Duration
	maxResponseBytes int64
	downloadTimeout  time.Duration
	maxDownloadBytes int64
	testBaseURL      bool
	diagnostics      bool
}

// NewClient returns a Client that authenticates with a Bouncer API key.
//
// Parameters:
//   - apiKey: the key from the Bouncer dashboard, sent only in the x-api-key
//     header of every call, never in a URL or body
//   - opts: optional settings; see the With functions
//
// The key must be 1 to 256 bytes of visible ASCII (0x21 to 0x7E). The
// application decides where the key comes from: NewClient reads no
// environment variables or files and performs no I/O.
//
// Errors are *ValidationError values matching ErrInvalidConfig. They name the
// argument or option, never its value.
func NewClient(apiKey string, opts ...Option) (*Client, error) {
	if err := checkKey(apiKey); err != nil {
		return nil, err
	}
	o := options{
		timeout:          DefaultTimeout,
		maxResponseBytes: DefaultMaxResponseBytes,
		downloadTimeout:  DefaultDownloadTimeout,
		maxDownloadBytes: DefaultMaxDownloadBytes,
		userAgent:        defaultUserAgent,
	}
	for _, opt := range opts {
		if opt != nil {
			opt(&o)
		}
	}
	host, err := o.validate()
	if err != nil {
		return nil, err
	}
	hc := o.client()
	return &Client{
		send:             newSender(hc, host, apiKey, o.userAgent),
		closeIdle:        hc.CloseIdleConnections,
		scrub:            scrubber(apiKey),
		userAgent:        o.userAgent,
		timeout:          o.timeout,
		maxResponseBytes: o.maxResponseBytes,
		downloadTimeout:  o.downloadTimeout,
		maxDownloadBytes: o.maxDownloadBytes,
		testBaseURL:      o.testBaseURLSet,
		diagnostics:      o.diagnostics,
	}, nil
}

// String describes the Client's settings, such as
// `bouncer.Client{timeout: 1m0s, maxResponseBytes: 16777216, ...}`. It never
// includes the API key or the base URL.
func (c *Client) String() string {
	if c == nil {
		return "bouncer.Client(nil)"
	}
	var b strings.Builder
	b.WriteString("bouncer.Client{timeout: ")
	b.WriteString(c.timeout.String())
	b.WriteString(", maxResponseBytes: ")
	b.WriteString(strconv.FormatInt(c.maxResponseBytes, 10))
	b.WriteString(", downloadTimeout: ")
	b.WriteString(c.downloadTimeout.String())
	b.WriteString(", maxDownloadBytes: ")
	b.WriteString(strconv.FormatInt(c.maxDownloadBytes, 10))
	b.WriteString(", userAgent: ")
	b.WriteString(strconv.Quote(c.userAgent))
	b.WriteString(", testBaseURL: ")
	b.WriteString(strconv.FormatBool(c.testBaseURL))
	b.WriteString(", providerDiagnostics: ")
	b.WriteString(strconv.FormatBool(c.diagnostics))
	b.WriteString("}")
	return b.String()
}

// GoString returns the same text as String, so that %#v prints settings only.
func (c *Client) GoString() string { return c.String() }

// Batches returns the asynchronous batch calls. The BatchService is a small
// value that refers to c; a BatchService from a nil or zero Client, and the
// zero BatchService, return ErrInvalidConfig without any I/O.
func (c *Client) Batches() BatchService { return BatchService{c: c} }

// CloseIdleConnections closes the idle keep-alive connections of the
// Client's transport: the SDK's own, or the one an injected http.Client
// uses, when it has such a method. Calls in flight are not affected, and
// later calls dial again as needed. It is a no-op on a nil or zero Client.
func (c *Client) CloseIdleConnections() {
	if c != nil && c.closeIdle != nil {
		c.closeIdle()
	}
}

// ready reports ErrInvalidConfig for a nil Client or one not built by
// NewClient.
func (c *Client) ready() error {
	if c == nil || c.send == nil || c.scrub == nil {
		return invalidConfig("Client", reasonNotInitialized)
	}
	return nil
}

// responseLimit returns the body limit for op: the configured limit for
// VerifyBatchSync, 4 KiB for a Finish or Delete acknowledgement, and at most
// 1 MiB for every other buffered call.
func (c *Client) responseLimit(op Operation) int64 {
	switch {
	case op == OpBatchSync:
		return c.maxResponseBytes
	case isAck(op):
		return maxErrorBodyBytes
	}
	return min(c.maxResponseBytes, smallResponseCap)
}

// scrubber returns a function that replaces every occurrence of key in a
// text with "[redacted]". A text in which the replacement itself forms the key
// again, as it can for a key that shares characters with "[redacted]", is
// dropped instead: the result never contains the key.
func scrubber(key string) func(string) string {
	return func(s string) string {
		out := strings.ReplaceAll(s, key, "[redacted]")
		if strings.Contains(out, key) {
			return ""
		}
		return out
	}
}

// checkKey validates the API key: 1 to 256 bytes of visible ASCII, which a
// header value can hold as it is. The error names the argument, never its
// value.
func checkKey(key string) error {
	switch {
	case key == "":
		return invalidConfig("apiKey", reasonRequired)
	case len(key) > maxKeyBytes || !asciiRange(key, 0x21, 0x7e):
		return invalidConfig("apiKey", reasonInvalidFormat)
	}
	return nil
}

// asciiRange reports whether every byte of s is from lo to hi.
func asciiRange(s string, lo, hi byte) bool {
	for i := range len(s) {
		if s[i] < lo || s[i] > hi {
			return false
		}
	}
	return true
}

// testHost validates a loopback test URL and returns its host and port.
func testHost(raw string) (string, bool) {
	if raw == "" || strings.ContainsAny(raw, "?#@\\") {
		return "", false
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Opaque != "" || u.User != nil ||
		u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.RawPath != "" ||
		(u.Path != "" && u.Path != "/") {
		return "", false
	}
	if !loopbackHostPort(u.Host) {
		return "", false
	}
	return u.Host, true
}

// loopbackHostPort accepts "ip[:port]" for a canonical IPv4 address in
// 127.0.0.0/8, or "[::1][:port]", with a canonical port from 1 to 65535.
func loopbackHostPort(hostport string) bool {
	host, port := hostport, ""
	if end := strings.LastIndexByte(hostport, ']'); end >= 0 {
		host, port = hostport[:end+1], hostport[end+1:]
	} else if i := strings.LastIndexByte(hostport, ':'); i >= 0 {
		host, port = hostport[:i], hostport[i:]
	}
	if host != "[::1]" {
		ip, err := netip.ParseAddr(host)
		if err != nil || !ip.Is4() || !ip.IsLoopback() || ip.String() != host {
			return false
		}
	}
	if port == "" {
		return true
	}
	digits, ok := strings.CutPrefix(port, ":")
	if !ok {
		return false
	}
	n, err := strconv.ParseUint(digits, 10, 16)
	return err == nil && n != 0 && strconv.FormatUint(n, 10) == digits
}
