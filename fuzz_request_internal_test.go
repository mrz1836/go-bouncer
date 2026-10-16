package bouncer

import (
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/mrz1836/go-bouncer/internal/testutil"
)

func FuzzBatchIDPath(f *testing.F) {
	for _, s := range []string{
		"5f0c2b9e8d7a6b5c4d3e2f1a", "a", "a:b", "a:b@c", `a"b`, "a[b]", "a{b}", "a|b", "a^b", "a`b", "a<b>", "a;b", "a,b",
		"a+b", "a=b", "a&b", "a$b", "...", "-", "~", ".a", "a.", "syn", "sync", "SYNC", "Sync1", "a/b", `a\b`, "a?b",
		"a#b", "a%2Fb", "%", ".", "..", "", "a b", "é", "a\x00", strings.Repeat("f", 128), strings.Repeat("f", 129),
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		if len(s) > fuzzMaxInput {
			return
		}
		id := BatchID(s)
		if reason := batchIDProblem(id); reason != "" {
			fuzzCheckRefusedID(t, id, reason)
			return
		}
		wantPath := "/v1.1/email/verify/batch/" + s + "/download"
		path, rawPath := batchPath(id, "/download")
		u := url.URL{Scheme: "https", Host: "127.0.0.1", Path: apiRoot + path}
		if rawPath != "" {
			u.RawPath = apiRoot + rawPath
		}
		fuzzCheckIDURL(t, u.String(), s, wantPath)

		script := testutil.NewScript(testutil.Step{Header: http.Header{"Content-Type": {mediaCSV}}, Body: "email\r\n"})
		c := newTestClient(t, script)
		_, err := c.Batches().Download(t.Context(), DownloadBatchRequest{BatchID: id, Format: FormatCSV}, io.Discard)
		require.NoError(t, err)
		reqs := script.Requests()
		require.Len(t, reqs, 1)
		fuzzCheckIDURL(t, reqs[0].URL, s, wantPath)
	})
}

// fuzzCheckIDURL checks that raw, a URL of a batch call, parses back to
// wantPath, with the batch ID as one whole path segment.
func fuzzCheckIDURL(t *testing.T, raw, id, wantPath string) {
	t.Helper()
	back, err := url.Parse(raw)
	require.NoError(t, err)
	require.Equal(t, wantPath, back.Path)
	segments := strings.Split(back.EscapedPath(), "/")
	require.Len(t, segments, 7, "the ID is exactly one segment: %q", back.EscapedPath())
	segment, err := url.PathUnescape(segments[5])
	require.NoError(t, err)
	require.Equal(t, id, segment)
}

// fuzzCheckRefusedID checks that a refused batch ID fails validation without
// any I/O, with an error that names the field and reason only.
func fuzzCheckRefusedID(t *testing.T, id BatchID, reason string) {
	t.Helper()
	counter := &testutil.CountingTransport{Next: testutil.StaticTransport(http.StatusOK, verifyAnswer)}
	c := newTestClient(t, counter)
	_, err := c.Batches().Status(t.Context(), BatchStatusRequest{BatchID: id})
	require.EqualError(t, err, "bouncer: invalid request: BatchID: "+reason)
	require.ErrorIs(t, err, ErrInvalidRequest)
	require.Zero(t, counter.Attempts())
}

func FuzzEmailQuery(f *testing.F) {
	for _, s := range []string{
		"avery.example@example.com", "blake+tag@example.net", "a b@example.org", "a%20b@example.com", "a&b=c@example.com",
		"a;b@example.com", "a#b?c@example.com", "é@example.com", "a\x00b@example.com", "\t", "~-._", "+", "%", "",
		"a\xffb@example.com", strings.Repeat("a", MaxEmailBytes), strings.Repeat("a", MaxEmailBytes+1),
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, email string) {
		if len(email) > fuzzMaxInput {
			return
		}
		if reason := emailProblem(email); reason != "" {
			fuzzCheckRefusedEmail(t, email, reason)
			return
		}
		req := VerifyRequest{Email: email}
		out, err := req.outgoing(DefaultTimeout)
		require.NoError(t, err)
		values, err := url.ParseQuery(out.query)
		require.NoError(t, err)
		require.Len(t, values, 1, "only email is sent without a timeout")
		require.Equal(t, email, values.Get("email"))
		fuzzCheckStrictQuery(t, out.query)

		var got string
		rt := testutil.RoundTripFunc(func(r *http.Request) (*http.Response, error) {
			got = r.URL.RawQuery
			testutil.Drain(r)
			body := io.NopCloser(strings.NewReader(verifyAnswer))
			return testutil.Response(r, http.StatusOK, body, int64(len(verifyAnswer))), nil
		})
		_, err = newTestClient(t, rt).Verify(t.Context(), req)
		require.NoError(t, err)
		require.Equal(t, out.query, got, "the query reaches the transport as encoded")
	})
}

// fuzzCheckStrictQuery checks that q is "email=" and a value in which every
// byte is unreserved or a percent escape, in uppercase hex, of a byte that is
// not.
func fuzzCheckStrictQuery(t *testing.T, q string) {
	t.Helper()
	value, ok := strings.CutPrefix(q, "email=")
	require.True(t, ok)
	require.NotContains(t, value, "+")
	require.NotContains(t, value, " ")
	for i := 0; i < len(value); i++ {
		c := value[i]
		if unreserved(c) {
			continue
		}
		require.Equal(t, byte('%'), c, "byte %d of %q is neither unreserved nor an escape", i, value)
		require.Less(t, i+2, len(value))
		hex := value[i+1 : i+3]
		require.Regexp(t, `^[0-9A-F]{2}$`, hex)
		n, err := strconv.ParseUint(hex, 16, 8)
		require.NoError(t, err)
		require.False(t, unreserved(byte(n)), "an unreserved byte is never escaped")
		i += 2
	}
}

// fuzzCheckRefusedEmail checks that a refused address fails validation
// without any I/O, with an error that names the field and reason only.
func fuzzCheckRefusedEmail(t *testing.T, email, reason string) {
	t.Helper()
	counter := &testutil.CountingTransport{Next: testutil.StaticTransport(http.StatusOK, verifyAnswer)}
	_, err := newTestClient(t, counter).Verify(t.Context(), VerifyRequest{Email: email})
	require.EqualError(t, err, "bouncer: invalid request: Email: "+reason)
	require.ErrorIs(t, err, ErrInvalidRequest)
	require.Zero(t, counter.Attempts())
}

func FuzzTestBaseURL(f *testing.F) {
	for _, s := range []string{
		"https://127.0.0.1", "https://127.0.0.1/", "https://127.0.0.2:8443", "https://127.255.255.255:65535",
		"https://[::1]", "https://[::1]:1", "HTTPS://127.0.0.1", "http://127.0.0.1", "https://localhost",
		"https://10.0.0.1", "https://[::2]", "https://127.1", "https://127.0.0.01", "https://127.0.0.1:0",
		"https://127.0.0.1:65536", "https://127.0.0.1:0443", "https://127.0.0.1:", "https://user@127.0.0.1",
		"https://127.0.0.1?q", "https://127.0.0.1#f", "https://127.0.0.1/p", "https://127.0.0.1//", `https://127.0.0.1\`,
		"https://127.0.0.%31", "https://[0:0::1]", "https:127.0.0.1", "https://", "", " https://127.0.0.1",
		"https://" + testKey + "@127.0.0.1",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		if len(s) > fuzzMaxInput {
			return
		}
		host, ok := testHost(s)
		wantHost, wantOK := fuzzLoopbackOracle(s)
		require.Equal(t, wantOK, ok, "testHost(%q)", s)
		require.Equal(t, wantHost, host)
		c, err := NewClient(testKey, WithTestBaseURL(s))
		if ok {
			require.NoError(t, err)
			require.NotNil(t, c)
			return
		}
		require.EqualError(t, err, "bouncer: invalid configuration: TestBaseURL: invalid_url")
	})
}

// TestLoopbackHostPort covers inputs that url.Parse refuses before
// loopbackHostPort sees them, so that FuzzTestBaseURL cannot reach them.
func TestLoopbackHostPort(t *testing.T) {
	t.Parallel()
	for hostport, ok := range map[string]bool{
		"127.0.0.1":      true,
		"[::1]":          true,
		"[::1]:443":      true,
		"[::1]x":         false,
		"[::1]:":         false,
		"[::2]":          false,
		"127.0.0.1:0443": false,
	} {
		assert.Equal(t, ok, loopbackHostPort(hostport), hostport)
	}
}

// fuzzLoopbackOracle is an independent statement of WithTestBaseURL's rule:
// the scheme https in any ASCII case, then a canonical IPv4 address in
// 127.0.0.0/8 or exactly [::1], an optional canonical port from 1 to 65535,
// and at most one trailing "/". It returns the host and port.
func fuzzLoopbackOracle(s string) (string, bool) {
	scheme, rest, found := strings.Cut(s, "://")
	if !found || !asciiRange(scheme, 0x21, 0x7e) || strings.ToLower(scheme) != "https" {
		return "", false
	}
	rest = strings.TrimSuffix(rest, "/")
	host, port := rest, ""
	if after, isV6 := strings.CutPrefix(rest, "[::1]"); isV6 {
		host, port = "[::1]", after
	} else if i := strings.LastIndexByte(rest, ':'); i >= 0 {
		host, port = rest[:i], rest[i:]
	}
	if host != "[::1]" && !fuzzCanonicalLoopbackV4(host) {
		return "", false
	}
	if port != "" && !fuzzCanonicalPort(port) {
		return "", false
	}
	return rest, true
}

// fuzzCanonicalLoopbackV4 reports whether host is four decimal octets without
// leading zeros, the first of them 127.
func fuzzCanonicalLoopbackV4(host string) bool {
	parts := strings.Split(host, ".")
	if len(parts) != 4 || parts[0] != "127" {
		return false
	}
	for _, p := range parts {
		if !fuzzCanonicalNumber(p, 255) {
			return false
		}
	}
	return true
}

// fuzzCanonicalPort reports whether port is ":" and a canonical number from 1
// to 65535.
func fuzzCanonicalPort(port string) bool {
	digits, ok := strings.CutPrefix(port, ":")
	return ok && digits != "0" && fuzzCanonicalNumber(digits, 65535)
}

// fuzzCanonicalNumber reports whether s is a decimal number without leading
// zeros, at most limit.
func fuzzCanonicalNumber(s string, limit int) bool {
	if s == "" || len(s) > 5 || !asciiRange(s, '0', '9') || (len(s) > 1 && s[0] == '0') {
		return false
	}
	n, err := strconv.Atoi(s)
	return err == nil && n <= limit
}
