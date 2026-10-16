package bouncer_test

import (
	"io"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/mrz1836/go-bouncer"
	"github.com/mrz1836/go-bouncer/internal/testutil"
)

// statusEnvelope is an error body whose envelope status is code, as a string.
func statusEnvelope(code int) string {
	return `{"status":"` + strconv.Itoa(code) + `","error":"synthetic error","message":"synthetic message"}`
}

// statusWantKind returns the kind an HTTP status of 400 or more gives o.
func statusWantKind(o opCase, code int) bouncer.FailureKind {
	switch {
	case code == http.StatusUnauthorized:
		return bouncer.FailureUnauthorized
	case code == http.StatusPaymentRequired:
		return bouncer.FailurePaymentRequired
	case code == http.StatusForbidden:
		return bouncer.FailureForbidden
	case code == http.StatusNotFound:
		return bouncer.FailureNotFound
	case code == http.StatusMethodNotAllowed && o.batch:
		return bouncer.FailureBatchState
	case code == http.StatusTooManyRequests:
		return bouncer.FailureRateLimited
	case code == http.StatusServiceUnavailable:
		return bouncer.FailureUnavailable
	case code >= 400 && code < 500:
		return bouncer.FailureRejected
	case code >= 500 && code < 600:
		return bouncer.FailureUpstream
	}
	return bouncer.FailureUnexpectedResponse
}

// TestStatusKindTable answers every operation with each error status and
// checks the kind, the status, the envelope status read from the excerpt,
// the operation and the batch.
func TestStatusKindTable(t *testing.T) {
	t.Parallel()
	codes := []int{400, 401, 402, 403, 404, 405, 409, 413, 418, 429, 500, 502, 503, 504, 599, 600}
	for _, oc := range opCases() {
		for _, code := range codes {
			t.Run(oc.name+"/"+strconv.Itoa(code), func(t *testing.T) {
				t.Parallel()
				c, script := newScriptClient(t, statusStep(code, statusEnvelope(code)))
				err := oc.call(t.Context(), c)
				apiStatus := code
				if code > 599 {
					apiStatus = 0
				}
				requireCallError(t, err, oc.wantFor(wantCall{
					Kind: statusWantKind(oc, code), StatusCode: code, APIStatus: apiStatus,
				}))
				assert.Equal(t, 1, script.Calls())
			})
		}
	}
}

// TestStatus405DependsOnTheCall checks that HTTP 405 is a batch state only on
// a call that names a batch, and a refusal on every other.
func TestStatus405DependsOnTheCall(t *testing.T) {
	t.Parallel()
	batchOps := map[string]bool{
		"Status": true, "Wait": true, "Results": true, "Download": true, "Finish": true, "Delete": true,
	}
	for _, oc := range opCases() {
		t.Run(oc.name, func(t *testing.T) {
			t.Parallel()
			require.Equal(t, batchOps[oc.name], oc.batch, "the operation table and this test must agree")
			c, _ := newScriptClient(t, statusStep(http.StatusMethodNotAllowed, `{}`))
			err := oc.call(t.Context(), c)
			if batchOps[oc.name] {
				require.ErrorIs(t, err, bouncer.ErrBatchState)
				require.NotErrorIs(t, err, bouncer.ErrRejected)
				ce := testutil.RequireErrorAs[*bouncer.CallError](t, err)
				assert.Equal(t, testBatchID, ce.BatchID)
				return
			}
			require.ErrorIs(t, err, bouncer.ErrRejected)
			require.NotErrorIs(t, err, bouncer.ErrBatchState)
		})
	}
}

// TestStatus404CarriesTheBatch checks that a batch the provider does not know
// is reported with the batch's ID.
func TestStatus404CarriesTheBatch(t *testing.T) {
	t.Parallel()
	for _, oc := range opCases() {
		if !oc.batch {
			continue
		}
		t.Run(oc.name, func(t *testing.T) {
			t.Parallel()
			c, _ := newScriptClient(t, statusStep(http.StatusNotFound, `{"status":404,"error":"Not Found"}`))
			err := oc.call(t.Context(), c)
			ce := requireCallError(t, err, oc.wantFor(wantCall{
				Kind: bouncer.FailureNotFound, StatusCode: http.StatusNotFound, APIStatus: http.StatusNotFound,
			}))
			assert.Equal(t, testBatchID, ce.BatchID)
		})
	}
}

// statusUnreadStep answers with status and a body that records reads, and
// a Location that the SDK must neither follow nor read.
func statusUnreadStep(status int, body *testutil.Body) testutil.Step {
	return testutil.Step{Respond: func(r *http.Request) (*http.Response, error) {
		testutil.Drain(r)
		resp := testutil.Response(r, status, body, -1)
		resp.Header.Set("Location", "https://elsewhere.example.org/next")
		return resp, nil
	}}
}

// TestInformationalAndRedirectStatusesAreNeverRead checks that a 1xx or 3xx
// answer is unexpected, and that its body is closed without a single read.
func TestInformationalAndRedirectStatusesAreNeverRead(t *testing.T) {
	t.Parallel()
	codes := []int{100, 101, 103, 300, 301, 302, 303, 304, 307, 308}
	for _, oc := range opCases() {
		for _, code := range codes {
			t.Run(oc.name+"/"+strconv.Itoa(code), func(t *testing.T) {
				t.Parallel()
				body := testutil.NewBody(statusEnvelope(402))
				c, script := newScriptClient(t, statusUnreadStep(code, body))
				err := oc.call(t.Context(), c)
				requireCallError(t, err, oc.wantFor(wantCall{Kind: bouncer.FailureUnexpectedResponse, StatusCode: code}))
				assert.Zero(t, body.Reads(), "the body of a %d is never read", code)
				assert.Positive(t, body.Closes(), "the body is closed")
				assert.Equal(t, 1, script.Calls(), "a redirect is never followed")
			})
		}
	}
}

// statusAccepted lists the 2xx statuses each operation accepts.
func statusAccepted(name string) []int {
	switch name {
	case "Create":
		return []int{200, 201, 202}
	case "Finish", "Delete":
		return []int{200, 202, 204}
	}
	return []int{200}
}

// TestSuccessStatusesPerCall answers every operation with each 2xx status and
// its successful body, and checks that only the documented ones succeed.
func TestSuccessStatusesPerCall(t *testing.T) {
	t.Parallel()
	codes := []int{200, 201, 202, 203, 204, 206}
	for _, oc := range opCases() {
		ok := statusAccepted(oc.name)
		for _, code := range codes {
			t.Run(oc.name+"/"+strconv.Itoa(code), func(t *testing.T) {
				t.Parallel()
				step := oc.ok
				step.Status = code
				c, script := newScriptClient(t, step)
				err := oc.call(t.Context(), c)
				assert.Equal(t, 1, script.Calls())
				if slices.Contains(ok, code) {
					require.NoError(t, err)
					return
				}
				want := oc.wantFor(wantCall{Kind: bouncer.FailureUnexpectedResponse, StatusCode: code})
				if oc.op == bouncer.OpBatchCreate {
					want.BatchID = testBatchID // the unusable answer still names the batch it created
				}
				requireCallError(t, err, want)
			})
		}
	}
}

// TestWaitStopsAtItsFirstFailedPoll checks that Wait returns a failed first
// poll's error as it is, with no status and no second poll.
func TestWaitStopsAtItsFirstFailedPoll(t *testing.T) {
	t.Parallel()
	for _, code := range []int{400, 401, 404, 405, 429, 500, 503} {
		t.Run(strconv.Itoa(code), func(t *testing.T) {
			t.Parallel()
			c, script := newScriptClient(t, statusStep(code, statusEnvelope(code)))
			st, err := c.Batches().Wait(t.Context(), bouncer.WaitBatchRequest{
				BatchID: testBatchID, Interval: time.Second, MaxWait: time.Hour,
			})
			assert.Nil(t, st, "no status was read")
			wait := opCase{op: bouncer.OpBatchStatus, batch: true}
			requireCallError(t, err, wait.wantFor(wantCall{
				Kind: statusWantKind(wait, code), StatusCode: code, APIStatus: code,
			}))
			assert.Equal(t, 1, script.Calls(), "a failed poll is never retried")
		})
	}
}

// statusRetryAfterStep answers with status and the given Retry-After values.
func statusRetryAfterStep(status int, values ...string) testutil.Step {
	h := http.Header{"Content-Type": {mediaJSON}}
	for _, v := range values {
		h.Add("Retry-After", v)
	}
	return testutil.Step{Status: status, Header: h, Body: statusEnvelope(status)}
}

// TestRetryAfterIsReadOn429And503Only checks the Retry-After header on every
// operation: read on 429 and 503, clamped to 24 hours, ignored when there are
// two or it does not parse, and never read on any other status.
func TestRetryAfterIsReadOn429And503Only(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		status int
		values []string
		want   time.Duration
		has    bool
	}{
		{"429 seconds", 429, []string{"120"}, 120 * time.Second, true},
		{"503 seconds", 503, []string{"7"}, 7 * time.Second, true},
		{"429 zero", 429, []string{"0"}, 0, true},
		{"429 clamped", 429, []string{"604800"}, 24 * time.Hour, true},
		{"429 huge", 429, []string{"99999999999999999999999"}, 24 * time.Hour, true},
		{"429 date in the past", 429, []string{"Sat, 01 Jan 2000 00:00:00 GMT"}, 0, true},
		{"429 two headers", 429, []string{"5", "6"}, 0, false},
		{"429 garbage", 429, []string{"soon"}, 0, false},
		{"429 negative", 429, []string{"-5"}, 0, false},
		{"429 fraction", 429, []string{"1.5"}, 0, false},
		{"429 absent", 429, nil, 0, false},
		{"503 absent", 503, nil, 0, false},
		{"400 never", 400, []string{"30"}, 0, false},
		{"500 never", 500, []string{"30"}, 0, false},
		{"502 never", 502, []string{"30"}, 0, false},
		{"401 never", 401, []string{"30"}, 0, false},
	}
	for _, oc := range opCases() {
		for _, tt := range tests {
			t.Run(oc.name+"/"+tt.name, func(t *testing.T) {
				t.Parallel()
				c, _ := newScriptClient(t, statusRetryAfterStep(tt.status, tt.values...))
				err := oc.call(t.Context(), c)
				ce := testutil.RequireErrorAs[*bouncer.CallError](t, err)
				assert.Equal(t, tt.status, ce.StatusCode)
				assert.Equal(t, tt.has, ce.HasRetryAfter, "HasRetryAfter")
				assert.Equal(t, tt.want, ce.RetryAfter, "RetryAfter")
			})
		}
	}
}

// TestRetryAfterHTTPDate checks an HTTP-date Retry-After against the clock,
// inside a bubble whose clock stands still while nothing blocks.
func TestRetryAfterHTTPDate(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		offset time.Duration
		want   time.Duration
	}{
		{"ninety seconds ahead", 90 * time.Second, 90 * time.Second},
		{"two days ahead", 48 * time.Hour, 24 * time.Hour},
		{"ten seconds ago", -10 * time.Second, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			synctest.Test(t, func(t *testing.T) {
				date := time.Now().Add(tt.offset).UTC().Format(http.TimeFormat)
				c, _ := newScriptClient(t, statusRetryAfterStep(http.StatusTooManyRequests, date))
				_, err := c.Verify(t.Context(), bouncer.VerifyRequest{Email: testEmail})
				ce := requireCallError(t, err, wantCall{
					Kind: bouncer.FailureRateLimited, Op: bouncer.OpVerify, StatusCode: 429, APIStatus: 429,
				})
				assert.True(t, ce.HasRetryAfter)
				assert.Equal(t, tt.want, ce.RetryAfter)
			})
		})
	}
}

// statusWithHeader returns oc's successful answer with the header changed by
// edit.
func statusWithHeader(oc opCase, edit func(http.Header)) testutil.Step {
	step := oc.ok
	h := http.Header{}
	for k, v := range step.Header {
		h[k] = append([]string(nil), v...)
	}
	edit(h)
	step.Header = h
	return step
}

// TestContentEncodingThatNobodyDecoded checks every operation against a
// Content-Encoding the transport left in place: identity, alone or with empty
// list elements, is accepted; any real coding is unexpected.
func TestContentEncodingThatNobodyDecoded(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		values []string
		ok     bool
	}{
		{"gzip", []string{"gzip"}, false},
		{"br", []string{"br"}, false},
		{"deflate", []string{"deflate"}, false},
		{"identity", []string{"identity"}, true},
		{"Identity uppercase", []string{"IDENTITY"}, true},
		{"identity then gzip", []string{"identity, gzip"}, false},
		{"empty elements", []string{"identity, , "}, true},
		{"empty value", []string{""}, true},
		{"two headers, one coding", []string{"identity", "gzip"}, false},
	}
	for _, oc := range opCases() {
		for _, tt := range tests {
			t.Run(oc.name+"/"+tt.name, func(t *testing.T) {
				t.Parallel()
				step := statusWithHeader(oc, func(h http.Header) {
					for _, v := range tt.values {
						h.Add("Content-Encoding", v)
					}
				})
				c, _ := newScriptClient(t, step)
				err := oc.call(t.Context(), c)
				if tt.ok {
					require.NoError(t, err)
					return
				}
				code := step.Status
				if code == 0 {
					code = http.StatusOK
				}
				requireCallError(t, err, oc.wantFor(wantCall{Kind: bouncer.FailureUnexpectedResponse, StatusCode: code}))
			})
		}
	}
}

// statusJSONOps returns the operations that answer with JSON data: every one
// but the acknowledgements (Finish, Delete) and Download, which has its own
// content types.
func statusJSONOps() []opCase {
	all := opCases()
	out := make([]opCase, 0, len(all))
	for _, oc := range all {
		switch oc.name {
		case "Finish", "Delete", "Download":
			continue
		}
		out = append(out, oc)
	}
	return out
}

// TestContentTypeGate checks the content types a JSON answer may carry.
func TestContentTypeGate(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		values []string
		ok     bool
	}{
		{"application/json", []string{"application/json"}, true},
		{"with charset", []string{"application/json; charset=utf-8"}, true},
		{"uppercase", []string{"Application/JSON"}, true},
		{"problem+json", []string{"application/problem+json"}, true},
		{"none", nil, true},
		{"text/html", []string{mediaHTML}, false},
		{"text/plain", []string{"text/plain"}, false},
		{"text/csv", []string{mediaCSV}, false},
		{"octet-stream", []string{mediaOctet}, false},
		{"two headers", []string{mediaJSON, mediaJSON}, false},
		{"empty value", []string{""}, false},
		{"unparsable", []string{"application/json; charset"}, false},
	}
	for _, oc := range statusJSONOps() {
		for _, tt := range tests {
			t.Run(oc.name+"/"+tt.name, func(t *testing.T) {
				t.Parallel()
				step := oc.ok
				step.Header = http.Header{}
				for _, v := range tt.values {
					step.Header.Add("Content-Type", v)
				}
				c, _ := newScriptClient(t, step)
				err := oc.call(t.Context(), c)
				if tt.ok {
					require.NoError(t, err)
					return
				}
				want := oc.wantFor(wantCall{Kind: bouncer.FailureUnexpectedResponse, StatusCode: 200})
				if oc.op == bouncer.OpBatchCreate {
					want.BatchID = testBatchID // the unusable answer still names the batch it created
				}
				requireCallError(t, err, want)
			})
		}
	}
}

// TestAcknowledgementContentTypes checks Finish and Delete: an empty
// acknowledgement passes whatever its content type, one with content must be
// JSON.
func TestAcknowledgementContentTypes(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		ctype []string
		body  string
		ok    bool
	}{
		{"empty html", []string{mediaHTML}, "", true},
		{"whitespace html", []string{mediaHTML}, " \r\n", true},
		{"empty plain", []string{"text/plain"}, "", true},
		{"empty two headers", []string{mediaHTML, mediaJSON}, "", true},
		{"empty no type", nil, "", true},
		{"object html", []string{mediaHTML}, `{}`, false},
		{"object plain", []string{"text/plain"}, `{"ok":true}`, false},
		{"object json", []string{mediaJSON}, `{}`, true},
		{"object no type", nil, `{}`, true},
	}
	for _, oc := range opCases() {
		if oc.name != "Finish" && oc.name != "Delete" {
			continue
		}
		for _, tt := range tests {
			t.Run(oc.name+"/"+tt.name, func(t *testing.T) {
				t.Parallel()
				h := http.Header{}
				for _, v := range tt.ctype {
					h.Add("Content-Type", v)
				}
				c, _ := newScriptClient(t, testutil.Step{Status: http.StatusOK, Header: h, Body: tt.body})
				err := oc.call(t.Context(), c)
				if tt.ok {
					require.NoError(t, err)
					return
				}
				requireCallError(t, err, oc.wantFor(wantCall{Kind: bouncer.FailureUnexpectedResponse, StatusCode: 200}))
			})
		}
	}
}

// TestErrorExcerptNeverChangesTheKind checks error bodies the SDK cannot use:
// too long, not JSON, not an object, or truncated. The status decides the
// kind, and the envelope status stays 0.
func TestErrorExcerptNeverChangesTheKind(t *testing.T) {
	t.Parallel()
	padded := `{"status":"404","pad":"` + strings.Repeat("x", 5000) + `"}`
	tests := []struct {
		name string
		step testutil.Step
	}{
		{"over 4 KiB declared", statusStep(http.StatusBadRequest, padded)},
		{"over 4 KiB undeclared", testutil.Step{Respond: func(r *http.Request) (*http.Response, error) {
			testutil.Drain(r)
			return testutil.Response(r, http.StatusBadRequest, io.NopCloser(strings.NewReader(padded)), -1), nil
		}}},
		{"not JSON", statusStep(http.StatusBadRequest, `<html>404</html>`)},
		{"array", statusStep(http.StatusBadRequest, `[{"status":404}]`)},
		{"invalid UTF-8", statusStep(http.StatusBadRequest, "{\"status\":\"404\",\"message\":\"\xff\"}")},
		{"empty", statusStep(http.StatusBadRequest, ``)},
		{"truncated", testutil.Step{Respond: func(r *http.Request) (*http.Response, error) {
			testutil.Drain(r)
			body := testutil.NewBody(`{"status":"404"}`)
			body.End = io.ErrUnexpectedEOF
			return testutil.Response(r, http.StatusBadRequest, body, 400), nil
		}}},
	}
	for _, oc := range opCases() {
		for _, tt := range tests {
			t.Run(oc.name+"/"+tt.name, func(t *testing.T) {
				t.Parallel()
				c, _ := newScriptClient(t, tt.step)
				err := oc.call(t.Context(), c)
				requireCallError(t, err, oc.wantFor(wantCall{
					Kind: bouncer.FailureRejected, StatusCode: http.StatusBadRequest, APIStatus: 0,
				}))
			})
		}
	}
}
