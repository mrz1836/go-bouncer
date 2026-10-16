package bouncer

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"regexp"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/stretchr/testify/require"

	"github.com/mrz1836/go-bouncer/internal/testutil"
)

// fuzzMaxInput bounds every fuzz input.
const fuzzMaxInput = 64 << 10

// fuzzMarkers are the values no error may ever print. The seeds plant them in
// inputs.
func fuzzMarkers() []string {
	return []string{testKey, "avery.example@example.com", "blake.example@example.net", "name-marker-5d1e"}
}

// fuzzFieldPath matches the JSON paths a CallError's Field may hold.
var fuzzFieldPath = regexp.MustCompile(`^(\[\d+\])?([.A-Za-z]*)$`)

// fuzzAssertClean fails t when err's text, in any common format, holds a
// marker.
func fuzzAssertClean(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		return
	}
	for _, out := range []string{err.Error(), fmt.Sprintf("%v", err), fmt.Sprintf("%+v", err), fmt.Sprintf("%#v", err)} {
		for _, m := range fuzzMarkers() {
			if strings.Contains(out, m) {
				t.Fatalf("error output holds a marker: %q", out)
			}
		}
	}
}

// fuzzSeedFixtures adds every synthetic fixture to f's seed corpus.
func fuzzSeedFixtures(f *testing.F) {
	f.Helper()
	for _, name := range []string{
		"verification_full.json", "verification_minimal.json", "results_mixed.json", "sync_partial.json",
		"batch_created.json", "batch_status_completed.json", "credits.json", "envelope_payment.json",
		"envelope_numeric_400.json",
	} {
		f.Add(testutil.Fixture(f, "synthetic/"+name))
	}
}

// fuzzDecodeKind reports whether a decodeError has one of the two decoding
// kinds.
func fuzzDecodeKind(d *decodeError) bool {
	return d.kind == FailureMalformedResponse || d.kind == FailureResponseTooLarge
}

func FuzzScanArray(f *testing.F) {
	fuzzSeedFixtures(f)
	for _, s := range []string{
		``, `[]`, ` [ ] `, `[{}]`, `[{},{}]`, `[null]`, `[1]`, `["x"]`, `[[]]`, `[{},]`, `[{}{}]`, `[{}`, `[{"a":"]}"}]`,
		`[{"a":"\"}"},{"b":"\\"}]`, `[{"a":{"b":[1,{"c":"}"}]}}]`, `{"status":"402","message":"avery.example@example.com"}`,
		`{"a":1} x`, `[] x`, "[\x00]", "\xef\xbb\xbf[]", `[{"email":"` + testKey + `"}]`,
		// Fuzz finding: a closing bracket that does not match the element's
		// opening brace (see TestFuzzFindingMismatchedCloser).
		` {]`, `[{]]`, `[{"a":[}],{}]`,
	} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > fuzzMaxInput {
			return
		}
		elems, end := fuzzScanAll(t, data)
		fuzzCheckFraming(t, data, elems, end)
		fuzzCheckAgainstJSON(t, data, elems, end)
	})
}

// fuzzScanAll drains a scanner over data, reading an object body with object,
// and returns the elements (copied) and the error that ended the scan: io.EOF
// at a clean end. It checks every step's invariants.
func fuzzScanAll(t *testing.T, data []byte) ([][]byte, error) {
	t.Helper()
	sc := newArrayScanner(bytes.NewReader(data))
	var elems [][]byte
	for range len(data) + 2 {
		elem, err := sc.next()
		if errors.Is(err, errObjectBody) {
			elem, err = sc.object()
			if err == nil {
				fuzzCheckElement(t, elem)
				elems = append(elems, bytes.Clone(elem))
				err = io.EOF
			}
		}
		switch {
		case errors.Is(err, io.EOF):
			for range 3 {
				_, again := sc.next()
				require.ErrorIs(t, again, io.EOF, "a scan stays ended")
			}
			return elems, io.EOF
		case err != nil:
			fuzzCheckScanError(t, err)
			return elems, err
		}
		fuzzCheckElement(t, elem)
		elems = append(elems, bytes.Clone(elem))
	}
	t.Fatalf("the scan did not end within %d steps", len(data)+2)
	return nil, nil
}

// fuzzCheckElement checks one element's framing.
func fuzzCheckElement(t *testing.T, elem []byte) {
	t.Helper()
	require.NotEmpty(t, elem)
	require.Equal(t, byte('{'), elem[0])
	require.Equal(t, byte('}'), elem[len(elem)-1], "an element ends at its matching closing brace: %q", elem)
	require.LessOrEqual(t, len(elem), maxRecordBytes)
}

// fuzzCheckScanError checks that a scan failure is one of the scanner's own,
// with a value-free path, and prints nothing it read.
func fuzzCheckScanError(t *testing.T, err error) {
	t.Helper()
	derr := testutil.RequireErrorAs[*decodeError](t, err)
	require.True(t, fuzzDecodeKind(derr), "kind %q", derr.kind)
	require.Regexp(t, `^(\[\d+\])?$`, derr.field)
	fuzzAssertClean(t, derr.callError(OpBatchResults, http.StatusOK))
}

// fuzzCheckFraming checks that a clean scan of valid elements means valid
// JSON: the scanner's framing never accepts what JSON would refuse.
func fuzzCheckFraming(t *testing.T, data []byte, elems [][]byte, end error) {
	t.Helper()
	if !errors.Is(end, io.EOF) {
		return
	}
	for _, e := range elems {
		if !json.Valid(e) {
			return
		}
	}
	require.True(t, json.Valid(data), "a clean scan of valid elements must be valid JSON: %q", data)
}

// fuzzCheckAgainstJSON checks that valid JSON arrays of objects, and valid
// JSON objects, scan to exactly their elements and a clean end.
func fuzzCheckAgainstJSON(t *testing.T, data []byte, elems [][]byte, end error) {
	t.Helper()
	if !json.Valid(data) {
		return
	}
	i := skipSpace(data)
	switch data[i] {
	case '{':
		require.ErrorIs(t, end, io.EOF, "a valid object body is read whole")
		require.Equal(t, [][]byte{bytes.TrimRight(data[i:], " \t\r\n")}, elems)
	case '[':
		var want []json.RawMessage
		require.NoError(t, json.Unmarshal(data, &want))
		for _, w := range want {
			if w[0] != '{' {
				require.Error(t, end, "an element that is not an object fails")
				return
			}
		}
		require.ErrorIs(t, end, io.EOF)
		require.Len(t, elems, len(want))
		for k := range want {
			require.Equal(t, []byte(want[k]), elems[k], "element %d", k)
		}
	default:
		require.Error(t, end, "a valid JSON value that is neither an array nor an object fails")
	}
}

// TestFuzzFindingMismatchedCloser pins a fuzz finding: the scanner counts any
// closing bracket against an element's depth, so `{]` is framed as a whole
// element instead of failing as invalid JSON. Through Results, an object body
// that ends with a mismatched bracket then fails as unexpected_response
// rather than malformed_response.
func TestFuzzFindingMismatchedCloser(t *testing.T) {
	t.Parallel()
	t.Run("object body", func(t *testing.T) {
		t.Parallel()
		sc := newArrayScanner(strings.NewReader(` {]`))
		_, err := sc.next()
		require.ErrorIs(t, err, errObjectBody)
		_, err = sc.object()
		derr := testutil.RequireErrorAs[*decodeError](t, err)
		require.Equal(t, FailureMalformedResponse, derr.kind)
	})

	t.Run("array element", func(t *testing.T) {
		t.Parallel()
		sc := newArrayScanner(strings.NewReader(`[{]]`))
		_, err := sc.next()
		derr := testutil.RequireErrorAs[*decodeError](t, err)
		require.Equal(t, FailureMalformedResponse, derr.kind)
		require.Equal(t, "[0]", derr.field)
	})

	t.Run("through Results", func(t *testing.T) {
		t.Parallel()
		script := testutil.NewScript(jsonAnswer(http.StatusOK, `{"status":"402"]`))
		c := newTestClient(t, script)
		var final error
		for _, err := range c.Batches().Results(t.Context(), BatchResultsRequest{BatchID: "5f0c2b9e8d7a6b5c4d3e2f1a"}) {
			final = err
		}
		require.ErrorIs(t, final, ErrMalformedResponse, "a body that is not valid JSON is malformed")
	})
}

func FuzzDecodeVerification(f *testing.F) {
	fuzzSeedFixtures(f)
	for _, s := range []string{
		verifyAnswer,
		`{"email":"a","status":"s","reason":"r","score":"","toxicity":null,"domain":{},"account":null,"dns":{"type":1}}`,
		`{"email":"a","status":"s","reason":"r","score":1.5}`,
		`{"email":"a","status":"s","reason":"r","score":-0}`,
		`{"email":"a","status":"s","reason":"r","score":99999999999999999999}`,
		`{"email":"A\ud800","status":"s","reason":"r","name":"name-marker-5d1e"}`,
		`{"email":"<&> ","status":"s","reason":"r","EMAIL":"x"}`,
		`{"email":"a","email":"b","status":"s","reason":"r"}`,
		`{"email":"a","status":"s"}`, `[]`, `null`, `"x"`, "{\"email\":\"\xff\"}", `{"email":"` + testKey + `",`,
	} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, raw []byte) {
		if len(raw) > fuzzMaxInput {
			return
		}
		v, derr := decodeVerification(raw, "[3]")
		if derr != nil {
			require.True(t, fuzzDecodeKind(derr), "kind %q", derr.kind)
			require.True(t, strings.HasPrefix(derr.field, "[3]"), "field %q", derr.field)
			require.Regexp(t, fuzzFieldPath, derr.field)
			fuzzAssertClean(t, derr.callError(OpBatchResults, http.StatusOK))
			return
		}
		require.True(t, json.Valid(raw))
		require.True(t, utf8.Valid(raw))
		fuzzCheckVerification(t, v)
		fuzzCheckRoundTrip(t, v)
	})
}

// fuzzCheckVerification checks a decoded record's guarantees: the required
// fields are set, and every text field is within its bound.
func fuzzCheckVerification(t *testing.T, v Verification) {
	t.Helper()
	require.NotEmpty(t, v.Email)
	require.NotEmpty(t, v.Status)
	require.NotEmpty(t, v.Reason)
	texts := []string{
		v.Email, string(v.Status), string(v.Reason), v.Provider, string(v.Toxic), v.RetryAfter, v.DidYouMean, v.Name,
	}
	if d := v.Domain; d != nil {
		texts = append(texts, d.Name, string(d.AcceptAll), string(d.Disposable), string(d.Free))
	}
	if a := v.Account; a != nil {
		texts = append(texts, string(a.Role), string(a.Disabled), string(a.FullMailbox))
	}
	if n := v.DNS; n != nil {
		texts = append(texts, n.Type, n.Record)
	}
	for _, s := range texts {
		require.LessOrEqual(t, len(s), maxTextBytes)
		require.True(t, utf8.ValidString(s))
	}
}

// fuzzCheckRoundTrip checks that a decoded record, marshaled back to JSON,
// decodes to itself.
func fuzzCheckRoundTrip(t *testing.T, v Verification) {
	t.Helper()
	data, err := encodeJSON(v)
	require.NoError(t, err)
	if len(data) > maxRecordBytes {
		// Escaping can lengthen text such as U+2028 past the record bound.
		return
	}
	back, derr := decodeVerification(data, "")
	require.Nil(t, derr, "the re-encoded record must decode: %s", data)
	require.Equal(t, v, back)
}

func FuzzEnvelope(f *testing.F) {
	fuzzSeedFixtures(f)
	for _, s := range []string{
		`{"status":400,"error":"Bad Request","message":"x"}`, `{"status":"404"}`, `{"status":"40"}`, `{"status":4000}`,
		`{"status":400.0}`, `{"status":-400}`, `{"status":"4e2"}`, `{"status":599}`, `{"status":600}`, `{"status":99}`,
		`{"status":"queued","batchId":"x"}`, `{"status":429,"message":"` + testKey + ` for avery.example@example.com"}`,
		`{"status":500,"message":"` + strings.Repeat("é", 700) + `"}`, `{"status":500,"message":"𐀀"}`,
		`{"status":500,"message":1}`, `[]`, ` {"status":402}`, `{"status":402} x`, "{\"message\":\"\xff\"}",
		`{"status":100,"0":0}`, `{"status":"200","message":"ok"}`, `{"status":399}`,
	} {
		f.Add([]byte(s))
	}
	c := newTestClient(f, nil, WithProviderDiagnostics())
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > fuzzMaxInput {
			return
		}
		require.Zero(t, fuzzStatusClass(envelopeStatus(data)), "an envelope status is 0 or 100 to 599")
		env, ok := readEnvelope(data)
		require.Zero(t, fuzzStatusClass(env.status), "an envelope status is 0 or 100 to 599")
		if ok {
			require.True(t, json.Valid(data))
			require.Equal(t, byte('{'), data[skipSpace(data)])
		} else {
			require.Zero(t, env.status)
		}
		diag := c.diagnosticsFrom(env.message)
		require.NotContains(t, diag.Message, testKey)
		require.LessOrEqual(t, len(diag.Message), maxDiagnosticMessageBytes)
		require.True(t, utf8.ValidString(diag.Message))
		fuzzCheckEnvelopeCalls(t, data, env, ok)
	})
}

// fuzzStatusClass returns 0 for an envelope status that is 0 or from 100 to
// 599, and the status itself otherwise.
func fuzzStatusClass(status int) int {
	if status == 0 || (status >= 100 && status <= 599) {
		return 0
	}
	return status
}

// fuzzCheckEnvelopeCalls answers a call with data, as an error body and as a
// success body, and checks that the status and envelope rules hold and that
// no error prints what the body held.
func fuzzCheckEnvelopeCalls(t *testing.T, data []byte, env envelope, ok bool) {
	t.Helper()
	script := testutil.NewScript(jsonAnswer(http.StatusBadRequest, string(data)), jsonAnswer(http.StatusOK, string(data)))
	c := newTestClient(t, script, WithProviderDiagnostics())

	_, err := c.Credits(t.Context())
	ce := testutil.RequireErrorAs[*CallError](t, err)
	require.Equal(t, FailureRejected, ce.Kind, "HTTP 400 decides the kind")
	require.Equal(t, http.StatusBadRequest, ce.StatusCode)
	if len(data) <= maxErrorBodyBytes {
		require.Equal(t, env.status, ce.APIStatus, "the excerpt feeds APIStatus")
	} else {
		require.Zero(t, ce.APIStatus, "a body over the excerpt bound is not read")
	}
	require.NotContains(t, ce.Diagnostics().Message, testKey)
	fuzzAssertClean(t, err)

	_, err = c.Credits(t.Context())
	fuzzAssertClean(t, err)
	if ok && env.failed() {
		ce = testutil.RequireErrorAs[*CallError](t, err)
		require.Equal(t, http.StatusOK, ce.StatusCode)
		require.Equal(t, env.status, ce.APIStatus)
	}
}

func FuzzRetryAfter(f *testing.F) {
	for _, s := range []string{
		"", "0", "1", "000001", "86400", "86401", "99999999999999999999", " 120 ", "\t7", "-1", "1.5", "1e3",
		"Wed, 21 Oct 2026 07:28:00 GMT", "Sunday, 06-Nov-94 08:49:37 GMT", "Sun Nov  6 08:49:37 1994", "garbage",
		"Thu, 01 Jan 1970 00:00:00 GMT", "Fri, 31 Dec 9999 23:59:59 GMT",
	} {
		f.Add(s)
	}
	now := time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC)
	f.Fuzz(func(t *testing.T, v string) {
		if len(v) > fuzzMaxInput {
			return
		}
		d, ok := retryAfter(http.Header{"Retry-After": {v}}, now)
		require.GreaterOrEqual(t, d, time.Duration(0))
		require.LessOrEqual(t, d, maxRetryAfter)
		if !ok {
			require.Zero(t, d)
		}
		digits := strings.Trim(v, " \t")
		if digits == "" || len(digits) > 30 || !asciiRange(digits, '0', '9') {
			return
		}
		require.True(t, ok, "delta-seconds always parse")
		n, _ := new(big.Int).SetString(digits, 10)
		limit := big.NewInt(int64(maxRetryAfter / time.Second))
		if n.Cmp(limit) > 0 {
			n = limit
		}
		require.Equal(t, time.Duration(n.Int64())*time.Second, d)
	})
}
