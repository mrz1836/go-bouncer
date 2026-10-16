package bouncer_test

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/mrz1836/go-bouncer"
	"github.com/mrz1836/go-bouncer/internal/testutil"
)

// privacyPlusEmail is an address whose plus sign and space change form under
// every percent-encoding: the strict query encoding Verify sends puts it in the
// URL as "leak%2Bmarker%20tag%40example.com".
const privacyPlusEmail = "leak+marker tag@example.com"

// privacyHostMarker is a host name planted in transport errors.
const privacyHostMarker = "leak-marker-host.invalid"

// privacyBases returns every marker whose forms must never surface.
func privacyBases() []string {
	return append(markers(), privacyPlusEmail, privacyHostMarker)
}

// privacyStrictEscape percent-encodes s as the SDK's query encoding does:
// everything but the unreserved characters.
func privacyStrictEscape(s string) string {
	return strings.ReplaceAll(url.QueryEscape(s), "+", "%20")
}

// privacyForms returns every form of every marker a leak could take: plain,
// form-encoded, path-encoded and strictly encoded, and for an address its
// local part in the same forms.
func privacyForms() []string {
	var forms []string
	add := func(s string) {
		if s != "" && !slices.Contains(forms, s) {
			forms = append(forms, s)
		}
	}
	for _, m := range privacyBases() {
		variants := []string{m}
		if local, _, ok := strings.Cut(m, "@"); ok && !strings.Contains(m, "://") {
			variants = append(variants, local)
		}
		for _, v := range variants {
			add(v)
			add(url.QueryEscape(v))
			add(url.PathEscape(v))
			add(privacyStrictEscape(v))
		}
	}
	return forms
}

// privacyMarkerText is free text holding every marker, as a hostile or
// echoing server or transport would send it.
func privacyMarkerText() string {
	return "synthetic: " + strings.Join(privacyBases(), " | ")
}

// privacyError is a transport error whose text a test chooses, so that it
// can plant markers in it.
type privacyError struct{ msg string }

// Error returns the planted text.
func (e privacyError) Error() string { return e.msg }

// privacyJSON returns s as a JSON string.
func privacyJSON(s string) string {
	b, err := json.Marshal(s)
	if err != nil {
		panic(err)
	}
	return string(b)
}

// privacyScan fails t when text, or its hex encoding in either case, holds any
// marker form. It names the rendering and the form, never the text.
func privacyScan(tb testing.TB, label, text string, forms []string) {
	tb.Helper()
	for _, f := range forms {
		h := hex.EncodeToString([]byte(f))
		for _, form := range []string{f, h, strings.ToUpper(h)} {
			if strings.Contains(text, form) {
				tb.Errorf("%s holds the marker form %q", label, form)
			}
		}
	}
}

// privacyChain returns err and every error its Unwrap methods reach, both the
// single and the multiple form.
func privacyChain(err error) []error {
	var out []error
	var walk func(e error, depth int)
	walk = func(e error, depth int) {
		if e == nil || depth > 32 {
			return
		}
		out = append(out, e)
		switch u := e.(type) { //nolint:errorlint // walking the chain by hand is the point
		case interface{ Unwrap() []error }:
			for _, inner := range u.Unwrap() {
				walk(inner, depth+1)
			}
		case interface{ Unwrap() error }:
			walk(u.Unwrap(), depth+1)
		}
	}
	walk(err, 0)
	return out
}

// privacyAssertClean checks every way a caller might render or inspect err:
// Error, every fmt verb on the error and on two wrappers, GoString, every
// error in the Unwrap chain, JSON, and a reflection walk. None may hold a
// marker form, and none of the standard library's quoting error types may be
// reachable.
func privacyAssertClean(t *testing.T, err error, forms []string) {
	t.Helper()
	require.Error(t, err)
	privacyScan(t, "Error()", err.Error(), forms)
	wrappers := map[string]error{
		"error":   err,
		"joined":  errors.Join(err, errUnrelated),
		"wrapped": fmt.Errorf("context: %w", err),
	}
	for name, w := range wrappers {
		for _, verb := range testutil.FormatVerbs() {
			privacyScan(t, name+" "+verb, fmt.Sprintf(verb, w), forms)
		}
		for _, s := range testutil.ReflectStrings(w) {
			privacyScan(t, name+" reflection", s, forms)
		}
	}
	if gs, ok := err.(fmt.GoStringer); ok {
		privacyScan(t, "GoString", gs.GoString(), forms)
	}
	for i, e := range privacyChain(err) {
		label := "chain[" + strconv.Itoa(i) + "]"
		privacyScan(t, label+" Error()", e.Error(), forms)
		privacyScan(t, label+" %+v", fmt.Sprintf("%+v", e), forms)
		privacyScan(t, label+" %#v", fmt.Sprintf("%#v", e), forms)
	}
	data, jerr := json.Marshal(err)
	require.NoError(t, jerr)
	privacyScan(t, "json.Marshal", string(data), forms)

	_, isURL := errors.AsType[*url.Error](err)
	assert.False(t, isURL, "*url.Error is unreachable")
	_, isOp := errors.AsType[*net.OpError](err)
	assert.False(t, isOp, "*net.OpError is unreachable")
	_, isDNS := errors.AsType[*net.DNSError](err)
	assert.False(t, isDNS, "*net.DNSError is unreachable")
	if ne, isNet := errors.AsType[net.Error](err); isNet {
		assert.Equal(t, context.DeadlineExceeded, ne, "the only net.Error reachable is context.DeadlineExceeded")
	}
	_, isSyntax := errors.AsType[*json.SyntaxError](err)
	assert.False(t, isSyntax, "*json.SyntaxError is unreachable")
	_, isType := errors.AsType[*json.UnmarshalTypeError](err)
	assert.False(t, isType, "*json.UnmarshalTypeError is unreachable")
	_, isCert := errors.AsType[*tls.CertificateVerificationError](err)
	assert.False(t, isCert, "*tls.CertificateVerificationError is unreachable")
}

// privacyOp is one operation called with requests that carry markers where
// the request allows them.
type privacyOp struct {
	name string
	call func(ctx context.Context, c *bouncer.Client) error
}

// privacyOps returns every operation of opCases, with Verify, VerifyBatchSync
// and Create carrying marker addresses, names and the marker callback URL,
// plus a JSON Download.
func privacyOps() []privacyOp {
	overrides := map[string]func(ctx context.Context, c *bouncer.Client) error{
		"Verify": func(ctx context.Context, c *bouncer.Client) error {
			return noValue(c.Verify(ctx, bouncer.VerifyRequest{Email: privacyPlusEmail}))
		},
		"VerifyBatchSync": func(ctx context.Context, c *bouncer.Client) error {
			return noValue(c.VerifyBatchSync(ctx, bouncer.BatchSyncRequest{
				Emails: []string{testEmail, testEmail2, privacyPlusEmail},
			}))
		},
		"Create": func(ctx context.Context, c *bouncer.Client) error {
			return noValue(c.Batches().Create(ctx, bouncer.CreateBatchRequest{
				Entries:     []bouncer.BatchEntry{{Email: testEmail, Name: testName}, {Email: privacyPlusEmail}},
				CallbackURL: testCallback,
			}))
		},
	}
	var ops []privacyOp
	for _, oc := range opCases() {
		call := oc.call
		if o, ok := overrides[oc.name]; ok {
			call = o
		}
		ops = append(ops, privacyOp{name: oc.name, call: call})
	}
	return append(ops, privacyOp{name: "DownloadJSON", call: func(ctx context.Context, c *bouncer.Client) error {
		var w bytes.Buffer
		n, err := c.Batches().Download(ctx,
			bouncer.DownloadBatchRequest{BatchID: testBatchID, Format: bouncer.FormatJSON}, &w)
		if n != int64(w.Len()) {
			return errBrokenCall
		}
		return err
	}})
}

// privacyAnswer is one hostile answer: every operation must fail on it.
// diagnostics marks answers whose error envelope every operation reads, so
// that WithProviderDiagnostics keeps its message.
type privacyAnswer struct {
	name        string
	step        testutil.Step
	diagnostics bool
}

// privacyHeaders returns response headers that carry markers, on top of
// contentType.
func privacyHeaders(contentType string) http.Header {
	text := privacyMarkerText()
	return http.Header{
		"Content-Type": {contentType},
		"X-Echo":       {text},
		"Set-Cookie":   {"session=" + url.QueryEscape(text)},
		"Location":     {"https://example.org/?k=" + testKey},
		"Retry-After":  {text},
		"Www-Auth":     {"Bearer " + testKey},
	}
}

// privacyAnswers returns every hostile answer.
func privacyAnswers() []privacyAnswer {
	text := privacyMarkerText()
	envelope := func(status string) string {
		return `{"status":` + status + `,"error":` + privacyJSON(text) + `,"message":` + privacyJSON(text) + `}`
	}
	record := `{"email":` + privacyJSON(testEmail) + `,"status":"deliverable","reason":"accepted_email","name":` +
		privacyJSON(testName) + `}`
	huge := `[{"email":"` + strings.Repeat(testEmail+" "+testKey+" ", (1<<20)/40+1000) + `"}`
	var answers []privacyAnswer

	transport := map[string]error{
		"plain error":     privacyError{"dial failed: " + text},
		"net.OpError":     &net.OpError{Op: "dial", Net: "tcp", Err: privacyError{text}},
		"net.DNSError":    &net.DNSError{Err: text, Name: privacyHostMarker},
		"unexpected EOF":  fmt.Errorf("%w: %s", io.ErrUnexpectedEOF, text),
		"reset":           fmt.Errorf("%s: %w", text, syscall.ECONNRESET),
		"timeout":         testutil.TimeoutError{Msg: text},
		"url.Error":       &url.Error{Op: "Get", URL: "https://127.0.0.1/?email=" + url.QueryEscape(testEmail) + "&k=" + testKey, Err: privacyError{text}},
		"TLS certificate": &tls.CertificateVerificationError{Err: privacyError{text}},
	}
	for name, err := range transport {
		answers = append(answers, privacyAnswer{name: "transport " + name, step: testutil.Step{Err: err}})
	}

	for _, status := range []int{400, 401, 402, 403, 404, 405, 409, 429, 500, 502, 503} {
		answers = append(answers, privacyAnswer{
			name:        "HTTP " + strconv.Itoa(status),
			step:        testutil.Step{Status: status, Header: privacyHeaders(mediaJSON), Body: envelope(`"` + strconv.Itoa(status) + `"`)},
			diagnostics: true,
		})
	}
	answers = append(answers,
		privacyAnswer{
			name:        "HTTP 400 marker status",
			step:        testutil.Step{Status: 400, Header: privacyHeaders(mediaJSON), Body: envelope(privacyJSON(text))},
			diagnostics: true,
		},
		privacyAnswer{
			name: "HTTP 400 non-JSON body",
			step: testutil.Step{Status: 400, Header: privacyHeaders(mediaHTML), Body: "<p>" + text + "</p>"},
		},
		privacyAnswer{
			name:        "200 envelope number",
			step:        testutil.Step{Header: privacyHeaders(mediaJSON), Body: envelope("402")},
			diagnostics: true,
		},
		privacyAnswer{
			name:        "200 envelope string",
			step:        testutil.Step{Header: privacyHeaders(mediaJSON), Body: envelope(`"429"`)},
			diagnostics: true,
		},
		privacyAnswer{
			name: "200 marker content type",
			step: testutil.Step{
				Header: http.Header{"Content-Type": {`text/html; x="` + text + `"`}}, Body: "<p>" + text + "</p>",
			},
		},
		privacyAnswer{
			name: "200 malformed object",
			step: testutil.Step{Header: privacyHeaders(mediaJSON), Body: `{"email":` + privacyJSON(testEmail) +
				`,"status":"deliverable","reason":7,"name":` + privacyJSON(testName) + `,"error":` + privacyJSON(text) +
				`,"message":` + privacyJSON(text) + `}`},
		},
		privacyAnswer{
			name: "200 array with trailing data",
			step: testutil.Step{Header: privacyHeaders(mediaJSON), Body: `[` + record + `]garbage ` + text},
		},
		privacyAnswer{
			name: "200 too large",
			step: testutil.Step{Header: privacyHeaders(mediaJSON), Body: huge},
		},
		privacyAnswer{
			name: "200 JSON object as CSV",
			step: testutil.Step{Header: privacyHeaders(mediaCSV), Body: `{"email":` + privacyJSON(testEmail) +
				`,"error":` + privacyJSON(text) + `}`},
		},
		privacyAnswer{
			name: "200 invalid UTF-8",
			step: testutil.Step{Header: privacyHeaders(mediaJSON), Body: `{"email":"` + testEmail + "\xff" +
				`","status":"x","reason":"y","name":` + privacyJSON(testName) + `}`},
		},
		privacyAnswer{
			name: "200 truncated body",
			step: testutil.Step{Respond: func(r *http.Request) (*http.Response, error) {
				testutil.Drain(r)
				body := `[` + record + `,{"email":` + privacyJSON(text)
				resp := testutil.Response(r, http.StatusOK, testutil.NewBody(body), int64(len(body)+10))
				resp.Header = privacyHeaders(mediaJSON)
				return resp, nil
			}},
		},
	)
	for _, status := range []int{301, 302, 307, 308} {
		answers = append(answers, privacyAnswer{
			name: "HTTP " + strconv.Itoa(status),
			step: testutil.Step{Status: status, Header: privacyHeaders(mediaJSON), Body: envelope(`"` + strconv.Itoa(status) + `"`)},
		})
	}
	return answers
}

// TestPrivacyFailuresNeverLeak drives every operation through every hostile
// answer, with and without WithProviderDiagnostics, and checks that no marker
// form surfaces through any rendering of the error. With diagnostics, the
// provider's message is reachable only through Diagnostics, with the key
// scrubbed.
func TestPrivacyFailuresNeverLeak(t *testing.T) {
	t.Parallel()
	forms := privacyForms()
	for _, ans := range privacyAnswers() {
		for _, op := range privacyOps() {
			for _, diag := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/%s/diagnostics=%t", ans.name, op.name, diag), func(t *testing.T) {
					t.Parallel()
					privacyCheckFailure(t, ans, op, diag, forms)
				})
			}
		}
	}
}

// privacyCheckFailure runs op against ans and checks its error.
func privacyCheckFailure(t *testing.T, ans privacyAnswer, op privacyOp, diag bool, forms []string) {
	t.Helper()
	var opts []bouncer.Option
	if diag {
		opts = append(opts, bouncer.WithProviderDiagnostics())
	}
	c := newClient(t, testutil.NewScript(ans.step), opts...)
	err := op.call(t.Context(), c)
	require.Error(t, err, "every hostile answer fails every operation")
	require.NotErrorIs(t, err, errBrokenCall)
	privacyAssertClean(t, err, forms)

	msg := testutil.RequireErrorAs[*bouncer.CallError](t, err).Diagnostics().Message
	privacyScan(t, "Diagnostics", msg, []string{testKey, url.QueryEscape(testKey), privacyStrictEscape(testKey)})
	switch {
	case !diag:
		assert.Empty(t, msg, "diagnostics are opt-in")
	case ans.diagnostics:
		assert.Contains(t, msg, "[redacted]", "the key is scrubbed from the message")
		assert.Contains(t, msg, testEmail, "the message is kept otherwise")
	}
}

// TestPrivacyDiagnosticsLongMessage checks that a message over 1 KiB that
// holds the key near the cut is scrubbed before it is cut, so that no prefix
// of the key survives.
func TestPrivacyDiagnosticsLongMessage(t *testing.T) {
	t.Parallel()
	for _, pad := range []int{1000, 1010, 1020, 1023, 1024} {
		t.Run(strconv.Itoa(pad), func(t *testing.T) {
			t.Parallel()
			message := strings.Repeat("a", pad) + testKey + strings.Repeat("b", 64)
			body := `{"status":"400","message":` + privacyJSON(message) + `}`
			c := newClient(t, testutil.NewScript(statusStep(http.StatusBadRequest, body)), bouncer.WithProviderDiagnostics())
			_, err := c.Credits(t.Context())
			got := testutil.RequireErrorAs[*bouncer.CallError](t, err).Diagnostics().Message
			assert.LessOrEqual(t, len(got), 1024)
			for i := 4; i <= len(testKey); i++ {
				assert.NotContains(t, got, testKey[:i]+"b", "no part of the key survives next to the text after it")
			}
			assert.NotContains(t, got, testKey)
		})
	}
}

// privacyInvalid is one request or configuration that fails validation and
// embeds markers in the rejected value.
type privacyInvalid struct {
	name string
	call func(ctx context.Context, c *bouncer.Client) error
}

// privacyInvalidInputs returns invalid inputs whose rejected values hold
// markers.
func privacyInvalidInputs() []privacyInvalid {
	longEmail := testEmail + strings.Repeat("x", bouncer.MaxEmailBytes)
	badUTF8 := "\xff" + testEmail
	markedID := bouncer.BatchID("a/" + testEmail)
	return []privacyInvalid{
		{"Verify long email", func(ctx context.Context, c *bouncer.Client) error {
			return noValue(c.Verify(ctx, bouncer.VerifyRequest{Email: longEmail}))
		}},
		{"Verify invalid UTF-8 email", func(ctx context.Context, c *bouncer.Client) error {
			return noValue(c.Verify(ctx, bouncer.VerifyRequest{Email: badUTF8}))
		}},
		{"Verify bad timeout", func(ctx context.Context, c *bouncer.Client) error {
			return noValue(c.Verify(ctx, bouncer.VerifyRequest{Email: privacyPlusEmail, Timeout: 1500 * time.Millisecond}))
		}},
		{"Sync invalid email", func(ctx context.Context, c *bouncer.Client) error {
			return noValue(c.VerifyBatchSync(ctx, bouncer.BatchSyncRequest{Emails: []string{testEmail, "\xff" + testEmail2}}))
		}},
		{"Sync long email", func(ctx context.Context, c *bouncer.Client) error {
			return noValue(c.VerifyBatchSync(ctx, bouncer.BatchSyncRequest{Emails: []string{longEmail}}))
		}},
		{"Create long email", createCall(bouncer.CreateBatchRequest{
			Entries: []bouncer.BatchEntry{{Email: longEmail, Name: testName}}, CallbackURL: testCallback,
		})},
		{"Create invalid name", createCall(bouncer.CreateBatchRequest{
			Entries: []bouncer.BatchEntry{{Email: testEmail, Name: "\xff" + testName}},
		})},
		{"Create long name", createCall(bouncer.CreateBatchRequest{
			Entries: []bouncer.BatchEntry{{Email: testEmail, Name: testName + strings.Repeat("n", 256)}},
		})},
		{"Create http callback", createCall(bouncer.CreateBatchRequest{
			Entries: []bouncer.BatchEntry{{Email: testEmail}}, CallbackURL: "http://" + strings.TrimPrefix(testCallback, "https://"),
		})},
		{"Create callback with fragment", createCall(bouncer.CreateBatchRequest{
			Entries: []bouncer.BatchEntry{{Email: testEmail}}, CallbackURL: testCallback + "#" + testName,
		})},
		{"Create callback with space", createCall(bouncer.CreateBatchRequest{
			Entries: []bouncer.BatchEntry{{Email: testEmail}}, CallbackURL: testCallback + " " + testName,
		})},
		{"Create long callback", createCall(bouncer.CreateBatchRequest{
			Entries: []bouncer.BatchEntry{{Email: testEmail}}, CallbackURL: testCallback + strings.Repeat("p", 2048),
		})},
		{"Status marked ID", func(ctx context.Context, c *bouncer.Client) error {
			return noValue(c.Batches().Status(ctx, bouncer.BatchStatusRequest{BatchID: markedID}))
		}},
		{"Status long ID", func(ctx context.Context, c *bouncer.Client) error {
			return noValue(c.Batches().Status(ctx, bouncer.BatchStatusRequest{
				BatchID: bouncer.BatchID(testName + strings.Repeat("f", 128)),
			}))
		}},
		{"Wait marked ID", func(ctx context.Context, c *bouncer.Client) error {
			return noValue(c.Batches().Wait(ctx, bouncer.WaitBatchRequest{BatchID: markedID, MaxWait: time.Second}))
		}},
		{"Results marked filter", func(ctx context.Context, c *bouncer.Client) error {
			_, err := collect(c.Batches().Results(ctx, bouncer.BatchResultsRequest{
				BatchID: testBatchID, Filter: bouncer.ResultFilter(testName),
			}))
			return err
		}},
		{"Download marked format", func(ctx context.Context, c *bouncer.Client) error {
			_, err := c.Batches().Download(ctx, bouncer.DownloadBatchRequest{
				BatchID: testBatchID, Format: bouncer.DownloadFormat(testEmail),
			}, io.Discard)
			return err
		}},
		{"Finish marked ID", func(ctx context.Context, c *bouncer.Client) error {
			return c.Batches().Finish(ctx, bouncer.FinishBatchRequest{BatchID: markedID})
		}},
		{"Delete marked ID", func(ctx context.Context, c *bouncer.Client) error {
			return c.Batches().Delete(ctx, bouncer.DeleteBatchRequest{BatchID: "sync"})
		}},
	}
}

// TestPrivacyValidationErrorsHoldNoValues checks that a refused request never
// quotes the value it refused, through any rendering, and sends nothing.
func TestPrivacyValidationErrorsHoldNoValues(t *testing.T) {
	t.Parallel()
	forms := privacyForms()
	for _, tc := range privacyInvalidInputs() {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			counter := &testutil.CountingTransport{Next: testutil.StaticTransport(http.StatusOK, verifyOK)}
			c := newClient(t, counter)
			err := tc.call(t.Context(), c)
			_ = testutil.RequireErrorAs[*bouncer.ValidationError](t, err)
			require.ErrorIs(t, err, bouncer.ErrInvalidRequest)
			privacyAssertClean(t, err, forms)
			assert.Zero(t, counter.Attempts())
		})
	}
	for _, tc := range invalidRequestCases() {
		t.Run("table/"+tc.name, func(t *testing.T) {
			t.Parallel()
			c := newClient(t, testutil.StaticTransport(http.StatusOK, verifyOK))
			privacyAssertClean(t, tc.call(t.Context(), c), forms)
		})
	}
}

// TestPrivacyConfigErrorsHoldNoValues checks the same for NewClient: a refused
// key or option never quotes its value.
func TestPrivacyConfigErrorsHoldNoValues(t *testing.T) {
	t.Parallel()
	forms := append(privacyForms(), "127.0.0.9", ":9443") // never a bare number, which a printed pointer can hold
	cases := []struct {
		name string
		key  string
		opts []bouncer.Option
	}{
		{"key with space", testKey + " " + testEmail, nil},
		{"key too long", testKey + strings.Repeat("k", 256), nil},
		{"key with control", testKey + "\n", nil},
		{"key non-ASCII", testKey + "é", nil},
		{"user agent with newline", testKey, []bouncer.Option{bouncer.WithUserAgent(testName + "\n")}},
		{"user agent too long", testKey, []bouncer.Option{bouncer.WithUserAgent(testName + strings.Repeat("u", 256))}},
		{"base URL with userinfo", testKey, []bouncer.Option{bouncer.WithTestBaseURL("https://" + testEmail + ":x@127.0.0.9:9443")}},
		{"base URL with query", testKey, []bouncer.Option{bouncer.WithTestBaseURL("https://127.0.0.9:9443/?k=" + testKey)}},
		{"base URL http", testKey, []bouncer.Option{bouncer.WithTestBaseURL("http://127.0.0.9:9443")}},
		{"base URL name", testKey, []bouncer.Option{bouncer.WithTestBaseURL("https://" + privacyHostMarker)}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			c, err := bouncer.NewClient(tc.key, tc.opts...)
			require.Nil(t, c)
			require.ErrorIs(t, err, bouncer.ErrInvalidConfig)
			privacyAssertClean(t, err, forms)
		})
	}
}

// TestPrivacyVerifyURLStaysOutOfErrors checks the one place the address
// travels in a URL: Verify's query. A transport that fails makes the
// http.Client wrap its error in a *url.Error quoting that URL; the SDK
// replaces it, so neither the strictly encoded address nor the URL surfaces.
func TestPrivacyVerifyURLStaysOutOfErrors(t *testing.T) {
	t.Parallel()
	var sentURL string
	rt := testutil.RoundTripFunc(func(r *http.Request) (*http.Response, error) {
		sentURL = r.URL.String()
		return nil, privacyError{"connection refused"}
	})
	c := newClient(t, rt)
	_, err := c.Verify(t.Context(), bouncer.VerifyRequest{Email: privacyPlusEmail})
	require.ErrorIs(t, err, bouncer.ErrTransport)
	require.Contains(t, sentURL, privacyStrictEscape(privacyPlusEmail), "the address is in the URL")
	privacyAssertClean(t, err, append(privacyForms(), sentURL, "127.0.0.1", "/v1.1/email/verify"))
}

// privacyRecorder is a testing.TB that records a failure instead of failing,
// so that a control test can prove the scan reports a leak.
type privacyRecorder struct {
	testing.TB

	failures int
}

func (r *privacyRecorder) Helper() {}

func (r *privacyRecorder) Errorf(string, ...any) { r.failures++ }

// TestPrivacyScanDetectsLeaks is the control: each form of a marker, and its
// hex encoding, planted in a rendering, is reported, and clean text is not.
func TestPrivacyScanDetectsLeaks(t *testing.T) {
	t.Parallel()
	forms := privacyForms()
	planted := []string{
		testKey,
		url.QueryEscape(privacyPlusEmail),
		privacyStrictEscape(privacyPlusEmail),
		url.PathEscape(privacyPlusEmail),
		"leak+marker tag",
		"avery.example",
		hex.EncodeToString([]byte(testName)),
		strings.ToUpper(hex.EncodeToString([]byte(testCallback))),
		privacyHostMarker,
	}
	for _, p := range planted {
		rec := &privacyRecorder{TB: t}
		privacyScan(rec, "control", "bouncer: verify: transport: "+p, forms)
		assert.Positive(t, rec.failures, "a planted %q is reported", p)
	}
	rec := &privacyRecorder{TB: t}
	privacyScan(rec, "control", "bouncer: verify: transport (HTTP 200): closed", forms)
	assert.Zero(t, rec.failures, "a clean error text is not reported")

	leaky := struct{ hidden string }{hidden: testEmail}
	rec = &privacyRecorder{TB: t}
	for _, s := range testutil.ReflectStrings(leaky) {
		privacyScan(rec, "control reflection", s, forms)
	}
	assert.Positive(t, rec.failures, "a reflection walk reaches unexported fields")
}
