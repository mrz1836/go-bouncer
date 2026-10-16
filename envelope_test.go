package bouncer_test

import (
	"bytes"
	"io"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/mrz1836/go-bouncer"
	"github.com/mrz1836/go-bouncer/internal/testutil"
)

// envelopeSuccessStatus returns the success status oc's minimal answer uses.
func envelopeSuccessStatus(oc opCase) int {
	if oc.ok.Status != 0 {
		return oc.ok.Status
	}
	return http.StatusOK
}

// envelopeKind returns the kind an envelope status gives oc inside a 2xx.
func envelopeKind(oc opCase, apiStatus int) bouncer.FailureKind {
	if apiStatus < 400 {
		return bouncer.FailureUnexpectedResponse
	}
	return statusWantKind(oc, apiStatus)
}

// TestEnvelopeInsideASuccessStatus answers every operation with an error
// envelope inside its success status. The envelope's status decides the
// kind, StatusCode stays the real status, and a Retry-After header beside it
// is never read.
func TestEnvelopeInsideASuccessStatus(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name      string
		body      string
		apiStatus int
	}{
		{"402 as string", `{"status":"402","error":"Payment Required","message":"m"}`, 402},
		{"402 as number", `{"status":402,"error":"Payment Required","message":"m"}`, 402},
		{"400 as number", `{"status":400,"error":"Bad Request"}`, 400},
		{"401 as string", `{"status":"401","error":"Unauthorized"}`, 401},
		{"403", `{"status":403}`, 403},
		{"404", `{"status":404,"error":"Not Found"}`, 404},
		{"405", `{"status":"405","error":"Method Not Allowed"}`, 405},
		{"429", `{"status":429,"error":"Too Many Requests"}`, 429},
		{"500", `{"status":"500","error":"Internal Server Error"}`, 500},
		{"503", `{"status":503,"error":"Service Unavailable"}`, 503},
		{"leading whitespace", " \n\t{\"status\":\"402\"}\r\n", 402},
		{"no error member", `{"status":"429"}`, 429},
	}
	for _, oc := range opCases() {
		for _, tt := range tests {
			t.Run(oc.name+"/"+tt.name, func(t *testing.T) {
				t.Parallel()
				status := envelopeSuccessStatus(oc)
				h := http.Header{"Content-Type": {mediaJSON}, "Retry-After": {"30"}}
				c, script := newScriptClient(t, testutil.Step{Status: status, Header: h, Body: tt.body})
				err := oc.call(t.Context(), c)
				ce := requireCallError(t, err, oc.wantFor(wantCall{
					Kind: envelopeKind(oc, tt.apiStatus), StatusCode: status, APIStatus: tt.apiStatus,
				}))
				assert.False(t, ce.HasRetryAfter, "Retry-After is read only on HTTP 429 and 503")
				assert.Zero(t, ce.RetryAfter)
				assert.Equal(t, 1, script.Calls())
			})
		}
	}
}

// TestEnvelopeStatusMustBeANumber checks the shapes of "status" that are not
// an error envelope: words, numbers outside 100 to 599, fractions and strings
// that are not three digits. A Finish acknowledgement holding one succeeds,
// because it is an object without an "error" member.
func TestEnvelopeStatusMustBeANumber(t *testing.T) {
	t.Parallel()
	bodies := []string{
		`{"status":"queued"}`,
		`{"status":"deliverable"}`,
		`{"status":4000}`,
		`{"status":"4000"}`,
		`{"status":"40"}`,
		`{"status":"4xx"}`,
		`{"status":400.0}`,
		`{"status":4e2}`,
		`{"status":-400}`,
		`{"status":" 400"}`,
		`{"status":99}`,
		`{"status":"099"}`,
		`{"status":600}`,
		`{"status":true}`,
		`{"status":null}`,
		`{"status":["400"]}`,
		`{"status":{"code":400}}`,
	}
	for _, body := range bodies {
		t.Run(body, func(t *testing.T) {
			t.Parallel()
			c, _ := newScriptClient(t, jsonStep(body))
			require.NoError(t, c.Batches().Finish(t.Context(), bouncer.FinishBatchRequest{BatchID: testBatchID}))
		})
	}
}

// TestEnvelopeMismatchingTheHTTPStatus checks an error status whose envelope
// names another: the HTTP status decides the kind, and APIStatus keeps the
// envelope's.
func TestEnvelopeMismatchingTheHTTPStatus(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name      string
		status    int
		body      string
		kind      bouncer.FailureKind
		apiStatus int
	}{
		{"400 says 404", 400, `{"status":"404","error":"Not Found"}`, bouncer.FailureRejected, 404},
		{"400 says 402", 400, `{"status":402}`, bouncer.FailureRejected, 402},
		{"503 says 400", 503, `{"status":400}`, bouncer.FailureUnavailable, 400},
		{"404 says 500", 404, `{"status":"500"}`, bouncer.FailureNotFound, 500},
		{"429 says 200", 429, `{"status":200}`, bouncer.FailureRateLimited, 200},
		{"401 says 403", 401, `{"status":"403"}`, bouncer.FailureUnauthorized, 403},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			c, _ := newScriptClient(t, statusStep(tt.status, tt.body))
			_, err := c.Verify(t.Context(), bouncer.VerifyRequest{Email: testEmail})
			requireCallError(t, err, wantCall{
				Kind: tt.kind, Op: bouncer.OpVerify, StatusCode: tt.status, APIStatus: tt.apiStatus,
			})
		})
	}
}

// TestFinishDocumentedContradiction checks the provider's documented answer
// to Finish that is HTTP 200 with an error body of status 400, written inline
// and read from the synthetic fixture.
func TestFinishDocumentedContradiction(t *testing.T) {
	t.Parallel()
	for name, body := range map[string]string{
		"inline":  `{"status":400,"error":"Bad Request","message":"synthetic message: batch cannot be finished"}`,
		"fixture": string(testutil.Fixture(t, "synthetic/envelope_numeric_400.json")),
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			c, _ := newScriptClient(t, jsonStep(body))
			err := c.Batches().Finish(t.Context(), bouncer.FinishBatchRequest{BatchID: testBatchID})
			requireCallError(t, err, wantCall{
				Kind: bouncer.FailureRejected, Op: bouncer.OpBatchFinish, StatusCode: 200, APIStatus: 400, BatchID: testBatchID,
			})
		})
	}
}

// envelopeAckOps returns Finish and Delete.
func envelopeAckOps() []opCase {
	var out []opCase
	for _, oc := range opCases() {
		if oc.name == "Finish" || oc.name == "Delete" {
			out = append(out, oc)
		}
	}
	return out
}

// TestAcknowledgementBodies checks what a Finish or Delete acknowledgement may
// hold, for each accepted status.
func TestAcknowledgementBodies(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		body string
		kind bouncer.FailureKind // "" for success
	}{
		{"empty", "", ""},
		{"whitespace", "  \n", ""},
		{"empty object", `{}`, ""},
		{"object", `{"ok":true}`, ""},
		{"object with a word status", `{"status":"queued"}`, ""},
		{"null error", `{"error":null}`, ""},
		{"error string", `{"error":"x"}`, bouncer.FailureRejected},
		{"error object", `{"error":{"code":1}}`, bouncer.FailureRejected},
		{"error with message", `{"error":"x","message":"m"}`, bouncer.FailureRejected},
		{"array", `[]`, bouncer.FailureMalformedResponse},
		{"string", `"ok"`, bouncer.FailureMalformedResponse},
		{"boolean", `true`, bouncer.FailureMalformedResponse},
		{"null", `null`, bouncer.FailureMalformedResponse},
		{"number", `1`, bouncer.FailureMalformedResponse},
		{"unclosed", `{`, bouncer.FailureMalformedResponse},
		{"two objects", `{} {}`, bouncer.FailureMalformedResponse},
		{"invalid UTF-8", "{\"a\":\"\xff\"}", bouncer.FailureMalformedResponse},
		{"not JSON", `ok`, bouncer.FailureMalformedResponse},
	}
	for _, oc := range envelopeAckOps() {
		for _, status := range []int{200, 202, 204} {
			for _, tt := range tests {
				t.Run(oc.name+"/"+strconv.Itoa(status)+"/"+tt.name, func(t *testing.T) {
					t.Parallel()
					c, _ := newScriptClient(t, statusStep(status, tt.body))
					err := oc.call(t.Context(), c)
					if tt.kind == "" {
						require.NoError(t, err)
						return
					}
					requireCallError(t, err, oc.wantFor(wantCall{Kind: tt.kind, StatusCode: status}))
				})
			}
		}
	}
}

// TestAcknowledgementOver4KiB checks that an acknowledgement longer than 4 KiB
// is too large, declared or not.
func TestAcknowledgementOver4KiB(t *testing.T) {
	t.Parallel()
	long := `{"ok":"` + strings.Repeat("x", 4<<10) + `"}`
	exact := `{"ok":"` + strings.Repeat("x", 4<<10-9) + `"}`
	require.Len(t, exact, 4<<10)
	for _, oc := range envelopeAckOps() {
		t.Run(oc.name+"/declared", func(t *testing.T) {
			t.Parallel()
			c, _ := newScriptClient(t, jsonStep(long))
			requireCallError(t, oc.call(t.Context(), c), oc.wantFor(wantCall{
				Kind: bouncer.FailureResponseTooLarge, StatusCode: 200,
			}))
		})
		t.Run(oc.name+"/undeclared", func(t *testing.T) {
			t.Parallel()
			c, _ := newScriptClient(t, testutil.Step{Respond: func(r *http.Request) (*http.Response, error) {
				testutil.Drain(r)
				return testutil.Response(r, http.StatusOK, io.NopCloser(strings.NewReader(long)), -1), nil
			}})
			requireCallError(t, oc.call(t.Context(), c), oc.wantFor(wantCall{
				Kind: bouncer.FailureResponseTooLarge, StatusCode: 200,
			}))
		})
		t.Run(oc.name+"/exactly 4 KiB", func(t *testing.T) {
			t.Parallel()
			c, _ := newScriptClient(t, jsonStep(exact))
			require.NoError(t, oc.call(t.Context(), c))
		})
	}
}

// TestResultsEnvelope checks a Results answer that is an object instead of
// the array: an error envelope fails by its status with no record yielded,
// and any other object is unexpected.
func TestResultsEnvelope(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name      string
		body      string
		kind      bouncer.FailureKind
		apiStatus int
	}{
		{"402", `{"status":"402","error":"Payment Required"}`, bouncer.FailurePaymentRequired, 402},
		{"405", `{"status":405,"error":"Method Not Allowed"}`, bouncer.FailureBatchState, 405},
		{"leading whitespace", "\n {\"status\":404}", bouncer.FailureNotFound, 404},
		{"status 200", `{"status":200}`, bouncer.FailureUnexpectedResponse, 0},
		{"not an envelope", `{"batchId":"x","status":"completed"}`, bouncer.FailureUnexpectedResponse, 0},
		{"trailing data", `{"status":402} x`, bouncer.FailureMalformedResponse, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			c, _ := newScriptClient(t, jsonStep(tt.body))
			records, err := collect(c.Batches().Results(t.Context(), bouncer.BatchResultsRequest{BatchID: testBatchID}))
			assert.Empty(t, records)
			requireCallError(t, err, wantCall{
				Kind: tt.kind, Op: bouncer.OpBatchResults, StatusCode: 200, APIStatus: tt.apiStatus,
				BatchID: testBatchID, checkCounts: true,
			})
		})
	}
}

// TestDownloadEnvelopeWritesNothing checks downloads answered with an error
// envelope, in each format and content type: the envelope's kind, and not a
// byte written.
func TestDownloadEnvelopeWritesNothing(t *testing.T) {
	t.Parallel()
	envelope := `{"status":"405","error":"Method Not Allowed","message":"m"}`
	tests := []struct {
		name      string
		format    bouncer.DownloadFormat
		ctype     string
		body      string
		kind      bouncer.FailureKind
		apiStatus int
	}{
		{"json as json", bouncer.FormatJSON, mediaJSON, envelope, bouncer.FailureBatchState, 405},
		{"json without type", bouncer.FormatJSON, "", envelope, bouncer.FailureBatchState, 405},
		{"csv as json", bouncer.FormatCSV, mediaJSON, envelope, bouncer.FailureBatchState, 405},
		{"csv as csv", bouncer.FormatCSV, mediaCSV, envelope, bouncer.FailureBatchState, 405},
		{"csv as octet-stream", bouncer.FormatCSV, mediaOctet, " " + envelope + "\n", bouncer.FailureBatchState, 405},
		{"csv as text/plain", bouncer.FormatCSV, "text/plain", `{"status":402}`, bouncer.FailurePaymentRequired, 402},
		{"csv as json, not an envelope", bouncer.FormatCSV, mediaJSON, `{"ok":true}`, bouncer.FailureUnexpectedResponse, 0},
		{"csv as csv, not an envelope", bouncer.FormatCSV, mediaCSV, `{"ok":true}`, bouncer.FailureUnexpectedResponse, 0},
		{"json, not an envelope", bouncer.FormatJSON, mediaJSON, `{"ok":true}`, bouncer.FailureUnexpectedResponse, 0},
		{"csv as json, status 200", bouncer.FormatCSV, mediaJSON, `{"status":200}`, bouncer.FailureUnexpectedResponse, 0},
		{
			"csv as json, over 64 KiB", bouncer.FormatCSV, mediaJSON,
			`{"status":402,"pad":"` + strings.Repeat("x", 64<<10) + `"}`, bouncer.FailureUnexpectedResponse, 0,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			h := http.Header{}
			if tt.ctype != "" {
				h.Set("Content-Type", tt.ctype)
			}
			c, _ := newScriptClient(t, testutil.Step{Header: h, Body: tt.body})
			w := &testutil.CountingWriter{}
			n, err := c.Batches().Download(t.Context(), bouncer.DownloadBatchRequest{
				BatchID: testBatchID, Format: tt.format,
			}, w)
			assert.Zero(t, n)
			assert.Zero(t, w.Len(), "nothing is written before the answer is classified")
			assert.Zero(t, w.Writes())
			requireCallError(t, err, wantCall{
				Kind: tt.kind, Op: bouncer.OpBatchDownload, StatusCode: 200, APIStatus: tt.apiStatus,
				BatchID: testBatchID, checkCounts: true,
			})
		})
	}
}

// TestCSVThatLooksLikeJSONIsStreamed checks that a CSV body is refused as an
// envelope only when it is wholly a JSON object: a CSV body that merely starts
// with a brace, or an object followed by more, is the file.
func TestCSVThatLooksLikeJSONIsStreamed(t *testing.T) {
	t.Parallel()
	for _, body := range []string{
		"{\"status\":402}\r\nemail\r\n",
		"{not json}\r\n",
		"email,status\r\n" + testEmail + ",deliverable\r\n",
	} {
		t.Run(body[:5], func(t *testing.T) {
			t.Parallel()
			c, _ := newScriptClient(t, csvStep(body))
			var w bytes.Buffer
			n, err := c.Batches().Download(t.Context(), bouncer.DownloadBatchRequest{
				BatchID: testBatchID, Format: bouncer.FormatCSV,
			}, &w)
			require.NoError(t, err)
			assert.Equal(t, int64(len(body)), n)
			assert.Equal(t, body, w.String())
		})
	}
}

// envelopeDiagClient returns a client with diagnostics on or off, over steps.
func envelopeDiagClient(t *testing.T, on bool, steps ...testutil.Step) *bouncer.Client {
	t.Helper()
	var opts []bouncer.Option
	if on {
		opts = append(opts, bouncer.WithProviderDiagnostics())
	}
	return newClient(t, testutil.NewScript(steps...), opts...)
}

// TestDiagnostics checks the opt-in provider message: off by default, taken
// from "message" only, a JSON string, with the API key scrubbed, and never in
// Error().
func TestDiagnostics(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		step testutil.Step
		want string
	}{
		{
			"non-2xx message", statusStep(402, `{"status":"402","error":"E","message":"not enough credits"}`),
			"not enough credits",
		},
		{"escaped message", statusStep(400, `{"status":400,"message":"line\nbreak é"}`), "line\nbreak é"},
		{"error only", statusStep(402, `{"status":"402","error":"Payment Required"}`), ""},
		{"message not a string", statusStep(402, `{"status":"402","message":42}`), ""},
		{"message null", statusStep(402, `{"status":"402","message":null}`), ""},
		{"body not JSON", statusStep(402, `not enough credits`), ""},
		{"message without status", statusStep(500, `{"message":"down"}`), "down"},
		{
			"key scrubbed", statusStep(401, `{"status":401,"message":"key `+testKey+` refused, `+testKey+`"}`),
			"key [redacted] refused, [redacted]",
		},
		{"envelope in a 200", jsonStep(`{"status":"429","message":"slow down"}`), "slow down"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			off := envelopeDiagClient(t, false, tt.step)
			_, err := off.Verify(t.Context(), bouncer.VerifyRequest{Email: testEmail})
			ce := testutil.RequireErrorAs[*bouncer.CallError](t, err)
			assert.Empty(t, ce.Diagnostics().Message, "diagnostics are off by default")

			on := envelopeDiagClient(t, true, tt.step)
			_, err = on.Verify(t.Context(), bouncer.VerifyRequest{Email: testEmail})
			ce = testutil.RequireErrorAs[*bouncer.CallError](t, err)
			assert.Equal(t, tt.want, ce.Diagnostics().Message)
			assert.NotContains(t, ce.Diagnostics().Message, testKey)
			if tt.want != "" {
				assert.NotContains(t, err.Error(), tt.want, "the provider's message never reaches Error()")
			}
			assert.NotContains(t, err.Error(), testKey)
		})
	}
}

// TestDiagnosticsOnBatchCalls checks the provider message on a Finish
// envelope inside a 200, and on an acknowledgement that names an error.
func TestDiagnosticsOnBatchCalls(t *testing.T) {
	t.Parallel()
	for _, tt := range []struct {
		name string
		body string
	}{
		{"envelope", `{"status":400,"error":"Bad Request","message":"cannot finish"}`},
		{"error member", `{"error":"Bad Request","message":"cannot finish"}`},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			c := envelopeDiagClient(t, true, jsonStep(tt.body))
			err := c.Batches().Finish(t.Context(), bouncer.FinishBatchRequest{BatchID: testBatchID})
			ce := testutil.RequireErrorAs[*bouncer.CallError](t, err)
			assert.Equal(t, bouncer.FailureRejected, ce.Kind)
			assert.Equal(t, "cannot finish", ce.Diagnostics().Message)
		})
	}
	t.Run("download envelope", func(t *testing.T) {
		t.Parallel()
		c := envelopeDiagClient(t, true, csvStep(`{"status":"405","message":"not completed"}`))
		_, err := c.Batches().Download(t.Context(), bouncer.DownloadBatchRequest{
			BatchID: testBatchID, Format: bouncer.FormatCSV,
		}, io.Discard)
		ce := testutil.RequireErrorAs[*bouncer.CallError](t, err)
		assert.Equal(t, bouncer.FailureBatchState, ce.Kind)
		assert.Equal(t, "not completed", ce.Diagnostics().Message)
	})
	t.Run("results envelope", func(t *testing.T) {
		t.Parallel()
		c := envelopeDiagClient(t, true, jsonStep(`{"status":"405","message":"not completed"}`))
		_, err := collect(c.Batches().Results(t.Context(), bouncer.BatchResultsRequest{BatchID: testBatchID}))
		ce := testutil.RequireErrorAs[*bouncer.CallError](t, err)
		assert.Equal(t, bouncer.FailureBatchState, ce.Kind)
		assert.Equal(t, "not completed", ce.Diagnostics().Message)
	})
}

// TestDiagnosticsAreCutOnARuneBoundary checks the 1 KiB bound on a message
// whose multi-byte characters straddle it.
func TestDiagnosticsAreCutOnARuneBoundary(t *testing.T) {
	t.Parallel()
	message := "a" + strings.Repeat("é", 600) // 1201 bytes; byte 1024 is a continuation byte
	c := envelopeDiagClient(t, true, statusStep(400, `{"status":400,"message":"`+message+`"}`))
	_, err := c.Verify(t.Context(), bouncer.VerifyRequest{Email: testEmail})
	ce := testutil.RequireErrorAs[*bouncer.CallError](t, err)
	got := ce.Diagnostics().Message
	assert.LessOrEqual(t, len(got), 1<<10)
	assert.True(t, utf8.ValidString(got), "the cut never splits a character")
	assert.True(t, strings.HasPrefix(message, got))
	assert.Len(t, got, 1023)

	short := strings.Repeat("b", 1<<10)
	c = envelopeDiagClient(t, true, statusStep(400, `{"status":400,"message":"`+short+`"}`))
	_, err = c.Verify(t.Context(), bouncer.VerifyRequest{Email: testEmail})
	ce = testutil.RequireErrorAs[*bouncer.CallError](t, err)
	assert.Equal(t, short, ce.Diagnostics().Message, "exactly 1 KiB is kept whole")
}

// TestStatusBelow400IsNotAnErrorEnvelope checks that an object whose status
// is a number below 400 is an ordinary answer, judged by its call: a Finish
// or Delete acknowledgement without an error member succeeds, and every
// other call fails as its own decoding rules say, without an APIStatus.
func TestStatusBelow400IsNotAnErrorEnvelope(t *testing.T) {
	t.Parallel()
	type outcome struct {
		kind  bouncer.FailureKind // "" for success
		field string
	}
	want := map[bouncer.Operation]outcome{
		bouncer.OpVerify:        {bouncer.FailureMalformedResponse, "email"},
		bouncer.OpBatchSync:     {bouncer.FailureUnexpectedResponse, ""},
		bouncer.OpCredits:       {bouncer.FailureMalformedResponse, "credits"},
		bouncer.OpBatchCreate:   {bouncer.FailureMalformedResponse, "batchId"},
		bouncer.OpBatchStatus:   {bouncer.FailureMalformedResponse, "batchId"},
		bouncer.OpBatchResults:  {bouncer.FailureUnexpectedResponse, ""},
		bouncer.OpBatchDownload: {bouncer.FailureUnexpectedResponse, ""},
		bouncer.OpBatchFinish:   {},
		bouncer.OpBatchDelete:   {},
	}
	for _, body := range []string{`{"status":200,"message":"ok"}`, `{"status":"202"}`, `{"status":302}`, `{"status":"100"}`} {
		for _, oc := range opCases() {
			t.Run(oc.name+"/"+body, func(t *testing.T) {
				t.Parallel()
				status := envelopeSuccessStatus(oc)
				c, script := newScriptClient(t, statusStep(status, body))
				err := oc.call(t.Context(), c)
				w := want[oc.op]
				if w.kind == "" {
					require.NoError(t, err)
				} else {
					requireCallError(t, err, oc.wantFor(wantCall{Kind: w.kind, StatusCode: status, Field: w.field}))
				}
				assert.Equal(t, 1, script.Calls())
			})
		}
	}
}

// TestEmptyAcknowledgementWithAnEncoding checks that a Finish or Delete
// acknowledgement with an empty body succeeds even when it still carries a
// Content-Encoding, which the transport leaves in place on an empty body.
func TestEmptyAcknowledgementWithAnEncoding(t *testing.T) {
	t.Parallel()
	for _, oc := range opCases() {
		if oc.op != bouncer.OpBatchFinish && oc.op != bouncer.OpBatchDelete {
			continue
		}
		for _, status := range []int{http.StatusOK, http.StatusAccepted, http.StatusNoContent} {
			t.Run(oc.name+"/"+http.StatusText(status), func(t *testing.T) {
				t.Parallel()
				h := http.Header{"Content-Type": {mediaJSON}, "Content-Encoding": {"gzip"}}
				c, _ := newScriptClient(t, testutil.Step{Status: status, Header: h})
				require.NoError(t, oc.call(t.Context(), c))
			})
		}
	}
}

// TestStreamContentTypeBeforeDeclaredLength checks the classification order
// of Results and Download: a content type that does not match fails as such,
// before a declared length over the download limit is considered.
func TestStreamContentTypeBeforeDeclaredLength(t *testing.T) {
	t.Parallel()
	for _, oc := range opCases() {
		if oc.op != bouncer.OpBatchResults && oc.op != bouncer.OpBatchDownload {
			continue
		}
		t.Run(oc.name, func(t *testing.T) {
			t.Parallel()
			body := testutil.NewBody("<html></html>")
			rt := testutil.TransportWith(http.StatusOK, http.Header{"Content-Type": {mediaHTML}}, 1<<20, body)
			c := newClient(t, rt, bouncer.WithMaxDownloadBytes(1024))
			err := oc.call(t.Context(), c)
			requireCallError(t, err, oc.wantFor(wantCall{Kind: bouncer.FailureUnexpectedResponse, StatusCode: http.StatusOK}))
			assert.Zero(t, body.BytesRead(), "nothing is read")
		})
	}
}
