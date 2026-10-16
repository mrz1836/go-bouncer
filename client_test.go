package bouncer_test

import (
	"fmt"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/mrz1836/go-bouncer"
	"github.com/mrz1836/go-bouncer/internal/testutil"
)

func TestNewClientKey(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		key    string
		reason string
	}{
		{"empty", "", reasonRequired},
		{"257 bytes", strings.Repeat("k", 257), reasonInvalidFormat},
		{"inner space", "bk-SYNTHETIC KEY", reasonInvalidFormat},
		{"leading space", " bk-SYNTHETIC-KEY", reasonInvalidFormat},
		{"tab", "bk-SYNTHETIC\tKEY", reasonInvalidFormat},
		{"newline", "bk-SYNTHETIC-KEY\n", reasonInvalidFormat},
		{"NUL", "bk-SYNTHETIC\x00KEY", reasonInvalidFormat},
		{"DEL", "bk-SYNTHETIC\x7fKEY", reasonInvalidFormat},
		{"non-ASCII", "bk-SYNTHETIC-KÉY", reasonInvalidFormat},
		{"invalid UTF-8", "bk-SYNTHETIC-\xffKEY", reasonInvalidFormat},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			c, err := bouncer.NewClient(tt.key)
			assert.Nil(t, c)
			requireValidation(t, err, bouncer.ErrInvalidConfig, "apiKey", tt.reason)
			if tt.key != "" {
				assert.NotContains(t, err.Error(), tt.key, "the error names the argument, never its value")
			}
		})
	}

	accepted := []struct {
		name string
		key  string
	}{
		{"one byte", "k"},
		{"256 visible bytes", strings.Repeat("~", 256)},
		{"quotes and backslash", `bk-"SYNTHETIC"\KEY`},
		{"every visible byte", clientVisibleASCII()},
		{"test key", testKey},
	}
	for _, tt := range accepted {
		t.Run("accepts "+tt.name, func(t *testing.T) {
			t.Parallel()
			c, err := bouncer.NewClient(tt.key)
			require.NoError(t, err)
			require.NotNil(t, c)
		})
	}
}

// clientVisibleASCII returns every byte from 0x21 to 0x7E once.
func clientVisibleASCII() string {
	var b strings.Builder
	for c := byte(0x21); c <= 0x7e; c++ {
		b.WriteByte(c)
	}
	return b.String()
}

func TestNewClientKeySentOnlyInHeader(t *testing.T) {
	t.Parallel()
	quoted := `bk-"SYNTHETIC"\KEY`
	script := testutil.NewScript(jsonStep(creditsOK))
	c, err := bouncer.NewClient(quoted, bouncer.WithTestBaseURL(loopbackOrigin),
		bouncer.WithHTTPClient(&http.Client{Transport: script}))
	require.NoError(t, err)
	_, err = c.Credits(t.Context())
	require.NoError(t, err)
	req := testutil.OnlyRequest(t, script)
	assert.Equal(t, []string{quoted}, req.Header.Values("X-Api-Key"), "a key with quotes travels as is in the header")
	assert.NotContains(t, req.URL, "SYNTHETIC")
	assert.Empty(t, req.Body)
}

func TestClientString(t *testing.T) {
	t.Parallel()
	c, err := bouncer.NewClient(testKey, bouncer.WithTestBaseURL("https://127.0.0.9:8443"))
	require.NoError(t, err)
	want := `bouncer.Client{timeout: 1m0s, maxResponseBytes: 16777216, downloadTimeout: 30m0s, ` +
		`maxDownloadBytes: 1073741824, userAgent: "go-bouncer", testBaseURL: true, providerDiagnostics: false}`
	assert.Equal(t, want, c.String())
	assert.Equal(t, want, c.GoString())
	assert.Equal(t, want, fmt.Sprintf("%v", c))
	assert.Equal(t, want, fmt.Sprintf("%#v", c))

	custom, err := bouncer.NewClient(testKey, bouncer.WithTimeout(40*time.Second), bouncer.WithUserAgent("acme-signup/1.4"),
		bouncer.WithProviderDiagnostics(), bouncer.WithMaxResponseBytes(2048), bouncer.WithMaxDownloadBytes(4096),
		bouncer.WithDownloadTimeout(20*time.Minute))
	require.NoError(t, err)
	assert.Equal(t, `bouncer.Client{timeout: 40s, maxResponseBytes: 2048, downloadTimeout: 20m0s, `+
		`maxDownloadBytes: 4096, userAgent: "acme-signup/1.4", testBaseURL: false, providerDiagnostics: true}`,
		custom.String())

	var nilClient *bouncer.Client
	assert.Equal(t, "bouncer.Client(nil)", nilClient.String())
	assert.Equal(t, "bouncer.Client(nil)", nilClient.GoString())
}

func TestClientNeverPrintsKeyOrBaseURL(t *testing.T) {
	t.Parallel()
	c, err := bouncer.NewClient(testKey, bouncer.WithTestBaseURL("https://127.0.0.9:8443"))
	require.NoError(t, err)
	// The port is matched with its colon: the bare digits can turn up in a
	// pointer's address, which %p, %d and %x print.
	secrets := []string{testKey, "127.0.0.9", ":8443", "api.usebouncer.com"}
	testutil.AssertShapesNeverPrint(t, c, secrets...)
	testutil.AssertNeverPrints(t, c, secrets...)
	testutil.AssertNeverPrints(t, *c, secrets...)
	for _, s := range testutil.ReflectStrings(c) {
		for _, secret := range secrets {
			assert.NotContains(t, s, secret, "a reflection walk reaches no secret")
		}
	}

	other, err := bouncer.NewClient("bk-SYNTHETIC-KEY-other", bouncer.WithTimeout(30*time.Second))
	require.NoError(t, err)
	testutil.AssertDiffRedacted(t, c, other, testKey, "bk-SYNTHETIC-KEY-other", "127.0.0.9")

	batches := c.Batches()
	testutil.AssertShapesNeverPrint(t, &batches, secrets...)
}

func TestBatchesFromNilOrZeroClient(t *testing.T) {
	t.Parallel()
	ctx := t.Context()
	for name, c := range map[string]*bouncer.Client{"nil": nil, "zero": {}} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			_, err := c.Batches().Status(ctx, bouncer.BatchStatusRequest{BatchID: testBatchID})
			requireValidation(t, err, bouncer.ErrInvalidConfig, "Client", reasonNotInitialized)
		})
	}
}

// clientIdleSpy is a RoundTripper that counts CloseIdleConnections.
type clientIdleSpy struct {
	closes atomic.Int32
}

// RoundTrip answers every request with the credits answer.
func (s *clientIdleSpy) RoundTrip(r *http.Request) (*http.Response, error) {
	return testutil.StaticTransport(http.StatusOK, creditsOK)(r)
}

// CloseIdleConnections counts the call.
func (s *clientIdleSpy) CloseIdleConnections() { s.closes.Add(1) }

func TestCloseIdleConnections(t *testing.T) {
	t.Parallel()
	t.Run("nil and zero clients", func(t *testing.T) {
		t.Parallel()
		var nilClient *bouncer.Client
		assert.NotPanics(t, nilClient.CloseIdleConnections)
		assert.NotPanics(t, (&bouncer.Client{}).CloseIdleConnections)
	})

	t.Run("reaches the injected transport", func(t *testing.T) {
		t.Parallel()
		spy := &clientIdleSpy{}
		c := newClient(t, spy)
		c.CloseIdleConnections()
		assert.Equal(t, int32(1), spy.closes.Load())
		_, err := c.Credits(t.Context())
		require.NoError(t, err, "calls still work afterward")
		c.CloseIdleConnections()
		assert.Equal(t, int32(2), spy.closes.Load())
	})

	t.Run("a transport without the method", func(t *testing.T) {
		t.Parallel()
		c := newClient(t, testutil.StaticTransport(http.StatusOK, creditsOK))
		assert.NotPanics(t, c.CloseIdleConnections)
	})

	t.Run("the SDK's own transport", func(t *testing.T) {
		t.Parallel()
		c, err := bouncer.NewClient(testKey)
		require.NoError(t, err)
		assert.NotPanics(t, c.CloseIdleConnections)
	})
}
