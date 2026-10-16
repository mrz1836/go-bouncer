package bouncer_test

import (
	"io"
	"net/http"
	"net/http/cookiejar"
	"reflect"
	"strings"
	"testing"
	"testing/synctest"
	"time"
	"unicode/utf8"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/mrz1836/go-bouncer"
	"github.com/mrz1836/go-bouncer/internal/testutil"
)

func TestOptionBounds(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		opt    bouncer.Option
		field  string
		reason string // "" means accepted
	}{
		{"Timeout zero", bouncer.WithTimeout(0), "Timeout", reasonOutOfRange},
		{"Timeout negative", bouncer.WithTimeout(-time.Second), "Timeout", reasonOutOfRange},
		{"Timeout minimum", bouncer.WithTimeout(time.Nanosecond), "Timeout", ""},
		{"Timeout maximum", bouncer.WithTimeout(10 * time.Minute), "Timeout", ""},
		{"Timeout above maximum", bouncer.WithTimeout(10*time.Minute + time.Nanosecond), "Timeout", reasonOutOfRange},

		{"MaxResponseBytes zero", bouncer.WithMaxResponseBytes(0), "MaxResponseBytes", reasonOutOfRange},
		{"MaxResponseBytes negative", bouncer.WithMaxResponseBytes(-1), "MaxResponseBytes", reasonOutOfRange},
		{"MaxResponseBytes minimum", bouncer.WithMaxResponseBytes(1), "MaxResponseBytes", ""},
		{"MaxResponseBytes maximum", bouncer.WithMaxResponseBytes(64 << 20), "MaxResponseBytes", ""},
		{"MaxResponseBytes above maximum", bouncer.WithMaxResponseBytes(64<<20 + 1), "MaxResponseBytes", reasonOutOfRange},

		{"DownloadTimeout zero", bouncer.WithDownloadTimeout(0), "DownloadTimeout", reasonOutOfRange},
		{"DownloadTimeout negative", bouncer.WithDownloadTimeout(-time.Minute), "DownloadTimeout", reasonOutOfRange},
		{"DownloadTimeout minimum", bouncer.WithDownloadTimeout(time.Nanosecond), "DownloadTimeout", ""},
		{"DownloadTimeout maximum", bouncer.WithDownloadTimeout(12 * time.Hour), "DownloadTimeout", ""},
		{
			"DownloadTimeout above maximum", bouncer.WithDownloadTimeout(12*time.Hour + time.Nanosecond),
			"DownloadTimeout", reasonOutOfRange,
		},

		{"MaxDownloadBytes zero", bouncer.WithMaxDownloadBytes(0), "MaxDownloadBytes", reasonOutOfRange},
		{"MaxDownloadBytes negative", bouncer.WithMaxDownloadBytes(-1), "MaxDownloadBytes", reasonOutOfRange},
		{"MaxDownloadBytes minimum", bouncer.WithMaxDownloadBytes(1), "MaxDownloadBytes", ""},
		{"MaxDownloadBytes maximum", bouncer.WithMaxDownloadBytes(64 << 30), "MaxDownloadBytes", ""},
		{"MaxDownloadBytes above maximum", bouncer.WithMaxDownloadBytes(64<<30 + 1), "MaxDownloadBytes", reasonOutOfRange},

		{"UserAgent empty", bouncer.WithUserAgent(""), "UserAgent", reasonOutOfRange},
		{"UserAgent 256 bytes", bouncer.WithUserAgent(strings.Repeat("u", 256)), "UserAgent", ""},
		{"UserAgent 257 bytes", bouncer.WithUserAgent(strings.Repeat("u", 257)), "UserAgent", reasonOutOfRange},
		{"UserAgent inner space", bouncer.WithUserAgent("acme signup/1.4 (ops)"), "UserAgent", ""},
		{"UserAgent leading space", bouncer.WithUserAgent(" acme/1"), "UserAgent", reasonInvalidFormat},
		{"UserAgent trailing space", bouncer.WithUserAgent("acme/1 "), "UserAgent", reasonInvalidFormat},
		{"UserAgent only a space", bouncer.WithUserAgent(" "), "UserAgent", reasonInvalidFormat},
		{"UserAgent tab", bouncer.WithUserAgent("acme\t1"), "UserAgent", reasonInvalidFormat},
		{"UserAgent newline", bouncer.WithUserAgent("acme/1\r\nX-Evil: 1"), "UserAgent", reasonInvalidFormat},
		{"UserAgent DEL", bouncer.WithUserAgent("acme\x7f"), "UserAgent", reasonInvalidFormat},
		{"UserAgent non-ASCII", bouncer.WithUserAgent("acmé/1"), "UserAgent", reasonInvalidFormat},
		{"UserAgent one byte", bouncer.WithUserAgent("a"), "UserAgent", ""},

		{"HTTPClient nil", bouncer.WithHTTPClient(nil), "HTTPClient", reasonNil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			c, err := bouncer.NewClient(testKey, tt.opt)
			if tt.reason == "" {
				require.NoError(t, err)
				require.NotNil(t, c)
				return
			}
			assert.Nil(t, c)
			requireValidation(t, err, bouncer.ErrInvalidConfig, tt.field, tt.reason)
		})
	}
}

func TestOptionOrderAndRepetition(t *testing.T) {
	t.Parallel()
	t.Run("nil options are skipped", func(t *testing.T) {
		t.Parallel()
		c, err := bouncer.NewClient(testKey, nil, bouncer.WithTimeout(5*time.Second), nil)
		require.NoError(t, err)
		assert.Contains(t, c.String(), "timeout: 5s")
	})

	t.Run("the last option wins", func(t *testing.T) {
		t.Parallel()
		c, err := bouncer.NewClient(testKey, bouncer.WithTimeout(0), bouncer.WithTimeout(5*time.Second))
		require.NoError(t, err, "a later valid value replaces an earlier invalid one")
		assert.Contains(t, c.String(), "timeout: 5s")

		_, err = bouncer.NewClient(testKey, bouncer.WithTimeout(5*time.Second), bouncer.WithTimeout(0))
		requireValidation(t, err, bouncer.ErrInvalidConfig, "Timeout", reasonOutOfRange)

		c, err = bouncer.NewClient(testKey, bouncer.WithUserAgent("first/1"), bouncer.WithUserAgent("second/2"))
		require.NoError(t, err)
		assert.Contains(t, c.String(), `userAgent: "second/2"`)

		_, err = bouncer.NewClient(testKey, bouncer.WithTestBaseURL("http://127.0.0.1"), bouncer.WithTestBaseURL(loopbackOrigin))
		require.NoError(t, err)
	})

	t.Run("options are checked in a fixed order", func(t *testing.T) {
		t.Parallel()
		_, err := bouncer.NewClient(testKey, bouncer.WithTestBaseURL("bad"), bouncer.WithUserAgent(""),
			bouncer.WithMaxDownloadBytes(0), bouncer.WithDownloadTimeout(0), bouncer.WithMaxResponseBytes(0),
			bouncer.WithTimeout(0), bouncer.WithHTTPClient(nil))
		requireValidation(t, err, bouncer.ErrInvalidConfig, "HTTPClient", reasonNil)
		_, err = bouncer.NewClient(testKey, bouncer.WithTestBaseURL("bad"), bouncer.WithUserAgent(""),
			bouncer.WithMaxDownloadBytes(0), bouncer.WithDownloadTimeout(0), bouncer.WithMaxResponseBytes(0),
			bouncer.WithTimeout(0))
		requireValidation(t, err, bouncer.ErrInvalidConfig, "Timeout", reasonOutOfRange)
		_, err = bouncer.NewClient(testKey, bouncer.WithTestBaseURL("bad"), bouncer.WithUserAgent(""),
			bouncer.WithMaxDownloadBytes(0), bouncer.WithDownloadTimeout(0), bouncer.WithMaxResponseBytes(0))
		requireValidation(t, err, bouncer.ErrInvalidConfig, "MaxResponseBytes", reasonOutOfRange)
		_, err = bouncer.NewClient(testKey, bouncer.WithTestBaseURL("bad"), bouncer.WithUserAgent(""),
			bouncer.WithMaxDownloadBytes(0), bouncer.WithDownloadTimeout(0))
		requireValidation(t, err, bouncer.ErrInvalidConfig, "DownloadTimeout", reasonOutOfRange)
		_, err = bouncer.NewClient(testKey, bouncer.WithTestBaseURL("bad"), bouncer.WithUserAgent(""),
			bouncer.WithMaxDownloadBytes(0))
		requireValidation(t, err, bouncer.ErrInvalidConfig, "MaxDownloadBytes", reasonOutOfRange)
		_, err = bouncer.NewClient(testKey, bouncer.WithTestBaseURL("bad"), bouncer.WithUserAgent(""))
		requireValidation(t, err, bouncer.ErrInvalidConfig, "UserAgent", reasonOutOfRange)
		_, err = bouncer.NewClient(testKey, bouncer.WithTestBaseURL("bad"))
		requireValidation(t, err, bouncer.ErrInvalidConfig, "TestBaseURL", reasonInvalidURL)
	})

	t.Run("the key is checked before the options", func(t *testing.T) {
		t.Parallel()
		_, err := bouncer.NewClient("", bouncer.WithHTTPClient(nil))
		requireValidation(t, err, bouncer.ErrInvalidConfig, "apiKey", reasonRequired)
	})
}

func TestUserAgentIsSent(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		opts []bouncer.Option
		want string
	}{
		{"default", nil, "go-bouncer"},
		{"custom", []bouncer.Option{bouncer.WithUserAgent("acme-signup/1.4")}, "acme-signup/1.4"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			script := testutil.NewScript(jsonStep(creditsOK))
			c := newClient(t, script, tt.opts...)
			_, err := c.Credits(t.Context())
			require.NoError(t, err)
			assert.Equal(t, []string{tt.want}, testutil.OnlyRequest(t, script).Header.Values("User-Agent"))
		})
	}
}

func TestWithTestBaseURL(t *testing.T) {
	t.Parallel()
	accepted := []string{
		"https://127.0.0.1",
		"https://127.0.0.1/",
		"https://127.0.0.2:8443",
		"https://127.255.255.254:65535",
		"https://[::1]",
		"https://[::1]:1",
		"https://[::1]:443/",
		"HTTPS://127.0.0.1", // URL schemes are case-insensitive
	}
	for _, raw := range accepted {
		t.Run("accepts "+raw, func(t *testing.T) {
			t.Parallel()
			c, err := bouncer.NewClient(testKey, bouncer.WithTestBaseURL(raw))
			require.NoError(t, err)
			assert.Contains(t, c.String(), "testBaseURL: true")
		})
	}

	rejected := []string{
		"",
		"http://127.0.0.1",
		"https://localhost",
		"https://localhost:8443",
		"https://10.0.0.1",
		"https://192.168.1.10",
		"https://[::2]",
		"https://[::ffff:127.0.0.1]",
		"https://127.1",
		"https://127.000.000.001",
		"https://0127.0.0.1",
		"https://api.usebouncer.com",
		"https://user@127.0.0.1",
		"https://user:pass@127.0.0.1",
		"https://127.0.0.1?x=1",
		"https://127.0.0.1/?",
		"https://127.0.0.1#frag",
		"https://127.0.0.1/v1.1",
		"https://127.0.0.1//",
		"https://127.0.0.1/%2F",
		"https://127.0.0.1:0",
		"https://127.0.0.1:65536",
		"https://127.0.0.1:08443",
		"https://127.0.0.1:",
		"https://127.0.0.1:port",
		"https://127.0.0.1\\",
		"https:\\\\127.0.0.1",
		"https:127.0.0.1",
		"//127.0.0.1",
		"127.0.0.1",
		"https://[::1",
		"https://[::1]x",
		"https:// 127.0.0.1",
	}
	for _, raw := range rejected {
		t.Run("rejects "+raw, func(t *testing.T) {
			t.Parallel()
			c, err := bouncer.NewClient(testKey, bouncer.WithTestBaseURL(raw))
			assert.Nil(t, c)
			requireValidation(t, err, bouncer.ErrInvalidConfig, "TestBaseURL", reasonInvalidURL)
			if raw != "" {
				assert.NotContains(t, err.Error(), raw, "the error never quotes the URL")
			}
			assert.NotContains(t, err.Error(), "127.0.0.1")
		})
	}
}

// optionsRoundTripper is an injected transport with state of its own, to show
// that the SDK neither replaces nor modifies it.
type optionsRoundTripper struct {
	Label string
	calls int
}

// RoundTrip answers with the credits answer.
func (o *optionsRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) {
	o.calls++
	return testutil.StaticTransport(http.StatusOK, creditsOK)(r)
}

func TestInjectedClientIsNeverModified(t *testing.T) {
	t.Parallel()
	jar, err := cookiejar.New(nil)
	require.NoError(t, err)
	rt := &optionsRoundTripper{Label: "caller"}
	redirects := 0
	checkRedirect := func(*http.Request, []*http.Request) error {
		redirects++
		return nil
	}
	hc := &http.Client{Transport: rt, Jar: jar, Timeout: 7 * time.Second, CheckRedirect: checkRedirect}
	checkPtr := reflect.ValueOf(hc.CheckRedirect).Pointer()

	c := newClientAt(t, loopbackOrigin, hc)
	_, err = c.Credits(t.Context())
	require.NoError(t, err)

	assert.Same(t, rt, hc.Transport, "the transport is wrapped in a copy, never replaced")
	assert.Equal(t, "caller", rt.Label)
	assert.Equal(t, 1, rt.calls, "calls go through the injected transport")
	assert.Same(t, jar, hc.Jar, "the caller's jar stays on the caller's client")
	assert.Equal(t, 7*time.Second, hc.Timeout)
	assert.Equal(t, checkPtr, reflect.ValueOf(hc.CheckRedirect).Pointer())

	// A redirect is never followed, even though the caller's CheckRedirect
	// would allow it.
	redirect := testutil.StaticTransport(http.StatusFound, "")
	hc2 := &http.Client{Transport: redirect, CheckRedirect: checkRedirect}
	_, err = newClientAt(t, loopbackOrigin, hc2).Credits(t.Context())
	requireCallError(t, err, wantCall{Kind: bouncer.FailureUnexpectedResponse, Op: bouncer.OpCredits, StatusCode: http.StatusFound})
	assert.Zero(t, redirects, "the caller's CheckRedirect is never consulted")
	assert.NotNil(t, hc2.CheckRedirect)
}

func TestInjectedClientCookiesAreNotSent(t *testing.T) {
	t.Parallel()
	// The copy has no jar, so cookies a caller's jar holds never ride along.
	srv := testutil.NewServer(t, testutil.Serve(jsonStep(creditsOK)))
	jar, err := cookiejar.New(nil)
	require.NoError(t, err)
	hc := srv.Client()
	hc.Jar = jar
	seed, err := http.NewRequestWithContext(t.Context(), http.MethodGet, srv.URL()+"/v1.1/credits", nil)
	require.NoError(t, err)
	jar.SetCookies(seed.URL, []*http.Cookie{{
		Name: "session", Value: "cookie-marker", Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode,
	}})

	// Control: the caller's own client sends the cookie.
	resp, err := hc.Do(seed)
	require.NoError(t, err)
	require.NoError(t, resp.Body.Close())

	_, err = newClientAt(t, srv.URL(), hc).Credits(t.Context())
	require.NoError(t, err)
	reqs := srv.Requests()
	require.Len(t, reqs, 2)
	assert.Equal(t, []string{"session=cookie-marker"}, reqs[0].Header.Values("Cookie"))
	assert.Empty(t, reqs[1].Header.Values("Cookie"), "the SDK's copy has no jar")
	assert.Same(t, jar, hc.Jar)
}

// TestInjectedClientTimeoutApplies checks that an injected http.Client's own
// Timeout ends the call, and that the standard library's error for it, which
// reports the timeout only as text, is classified as the SDK's timeout kind.
func TestInjectedClientTimeoutApplies(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		hc := &http.Client{Transport: testutil.RoundTripFunc(testutil.BlockUntilDone), Timeout: 2 * time.Second}
		c := newClientAt(t, loopbackOrigin, hc)
		start := time.Now()
		_, err := c.Credits(t.Context())
		ce := requireCallError(t, err, wantCall{Kind: bouncer.FailureTimeout, Op: bouncer.OpCredits})
		assert.True(t, ce.Timeout())
		assert.Equal(t, 2*time.Second, time.Since(start), "the injected Timeout ends the call, before the SDK's own")
	})
}

// optionsPadded returns body padded with trailing spaces to n bytes.
func optionsPadded(body string, n int) string { return body + strings.Repeat(" ", n-len(body)) }

func TestWithMaxResponseBytes(t *testing.T) {
	t.Parallel()
	call := func(t *testing.T, body string, declared bool, opts ...bouncer.Option) error {
		t.Helper()
		length := int64(-1)
		if declared {
			length = int64(len(body))
		}
		rt := testutil.Transport(http.StatusOK, length, func() io.ReadCloser { return io.NopCloser(strings.NewReader(body)) })
		c := newClient(t, rt, opts...)
		_, err := c.Credits(t.Context())
		return err
	}
	for _, declared := range []bool{true, false} {
		name := "unknown length"
		if declared {
			name = "declared length"
		}
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			limit := bouncer.WithMaxResponseBytes(64)
			require.NoError(t, call(t, optionsPadded(creditsOK, 64), declared, limit), "exactly the limit")
			err := call(t, optionsPadded(creditsOK, 65), declared, limit)
			requireCallError(t, err, wantCall{Kind: bouncer.FailureResponseTooLarge, Op: bouncer.OpCredits, StatusCode: 200})

			const mib = 1 << 20
			require.NoError(t, call(t, optionsPadded(creditsOK, mib), declared), "the 1 MiB cap of a non-sync call")
			err = call(t, optionsPadded(creditsOK, mib+1), declared)
			requireCallError(t, err, wantCall{Kind: bouncer.FailureResponseTooLarge, Op: bouncer.OpCredits, StatusCode: 200})
			err = call(t, optionsPadded(creditsOK, mib+1), declared, bouncer.WithMaxResponseBytes(8<<20))
			requireCallError(t, err, wantCall{Kind: bouncer.FailureResponseTooLarge, Op: bouncer.OpCredits, StatusCode: 200})
		})
	}

	t.Run("VerifyBatchSync uses the configured limit", func(t *testing.T) {
		t.Parallel()
		sync := func(t *testing.T, body string, opts ...bouncer.Option) error {
			t.Helper()
			c := newClient(t, testutil.StaticTransport(http.StatusOK, body), opts...)
			_, err := c.VerifyBatchSync(t.Context(), bouncer.BatchSyncRequest{Emails: []string{testEmail}})
			return err
		}
		const mib = 1 << 20
		require.NoError(t, sync(t, optionsPadded(resultsOK, mib+1)), "above 1 MiB, within the 16 MiB default")
		limit := bouncer.WithMaxResponseBytes(2 * mib)
		require.NoError(t, sync(t, optionsPadded(resultsOK, 2*mib), limit))
		err := sync(t, optionsPadded(resultsOK, 2*mib+1), limit)
		requireCallError(t, err, wantCall{Kind: bouncer.FailureResponseTooLarge, Op: bouncer.OpBatchSync, StatusCode: 200})
		small := bouncer.WithMaxResponseBytes(int64(len(resultsOK)))
		require.NoError(t, sync(t, resultsOK, small))
		err = sync(t, resultsOK+" ", small)
		requireCallError(t, err, wantCall{Kind: bouncer.FailureResponseTooLarge, Op: bouncer.OpBatchSync, StatusCode: 200})
	})
}

func TestWithProviderDiagnostics(t *testing.T) {
	t.Parallel()
	failWith := func(t *testing.T, message string, opts ...bouncer.Option) bouncer.CallError {
		t.Helper()
		body := `{"status":"402","error":"Payment Required","message":` + optionsJSONString(message) + `}`
		c := newClient(t, testutil.StaticTransport(http.StatusPaymentRequired, body), opts...)
		_, err := c.Credits(t.Context())
		return requireCallError(t, err, wantCall{
			Kind: bouncer.FailurePaymentRequired, Op: bouncer.OpCredits, StatusCode: 402, APIStatus: 402,
		})
	}

	t.Run("off by default", func(t *testing.T) {
		t.Parallel()
		ce := failWith(t, "synthetic message for "+testEmail)
		assert.Equal(t, bouncer.ProviderDiagnostics{}, ce.Diagnostics())
		assert.NotContains(t, ce.Error(), "synthetic message")
	})

	t.Run("on", func(t *testing.T) {
		t.Parallel()
		ce := failWith(t, "synthetic message", bouncer.WithProviderDiagnostics())
		assert.Equal(t, "synthetic message", ce.Diagnostics().Message)
		assert.NotContains(t, ce.Error(), "synthetic message", "diagnostics never reach Error()")
	})

	t.Run("the key is scrubbed", func(t *testing.T) {
		t.Parallel()
		ce := failWith(t, "key "+testKey+" refused; again "+testKey, bouncer.WithProviderDiagnostics())
		assert.Equal(t, "key [redacted] refused; again [redacted]", ce.Diagnostics().Message)
	})

	t.Run("cut to 1 KiB on a UTF-8 boundary", func(t *testing.T) {
		t.Parallel()
		message := strings.Repeat("a", 1023) + "é" + strings.Repeat("b", 100)
		ce := failWith(t, message, bouncer.WithProviderDiagnostics())
		got := ce.Diagnostics().Message
		assert.Equal(t, strings.Repeat("a", 1023), got, "the two-byte rune across the limit is dropped whole")
		assert.True(t, utf8.ValidString(got))

		exact := strings.Repeat("c", 1024)
		whole := failWith(t, exact, bouncer.WithProviderDiagnostics())
		assert.Equal(t, exact, whole.Diagnostics().Message)
	})

	t.Run("a message that is not a string is ignored", func(t *testing.T) {
		t.Parallel()
		body := `{"status":402,"error":"Payment Required","message":{"text":"nested"}}`
		c := newClient(t, testutil.StaticTransport(http.StatusPaymentRequired, body), bouncer.WithProviderDiagnostics())
		_, err := c.Credits(t.Context())
		ce := requireCallError(t, err, wantCall{
			Kind: bouncer.FailurePaymentRequired, Op: bouncer.OpCredits, StatusCode: 402, APIStatus: 402,
		})
		assert.Empty(t, ce.Diagnostics().Message)
	})
}

// optionsJSONString quotes s as a JSON string; s holds no characters that need
// escaping beyond those it escapes.
func optionsJSONString(s string) string {
	return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(s) + `"`
}
