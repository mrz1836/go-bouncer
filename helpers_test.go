package bouncer_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"iter"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/mrz1836/go-bouncer"
	"github.com/mrz1836/go-bouncer/internal/testutil"
)

// Synthetic test values. They double as leak markers: no error, formatted
// value or reflection walk may ever contain them. They are not real secrets.
const (
	testKey      = testutil.APIKey
	testEmail    = "avery.example@example.com"
	testEmail2   = "blake.example@example.net"
	testName     = "name-marker-5d1e"
	testCallback = "https://hooks.example.org/bouncer?token=cbmarker-91aa"

	testBatchID bouncer.BatchID = "5f0c2b9e8d7a6b5c4d3e2f1a"
)

// loopbackOrigin is a test base URL for in-memory transports, which never dial.
const loopbackOrigin = "https://127.0.0.1"

// The path of each call, as the server sees it.
const (
	pathVerify   = "/v1.1/email/verify"
	pathSync     = "/v1.1/email/verify/batch/sync"
	pathCredits  = "/v1.1/credits"
	pathBatch    = "/v1.1/email/verify/batch"
	pathBatchID  = pathBatch + "/" + string(testBatchID)
	pathDownload = pathBatchID + "/download"
	pathFinish   = pathBatchID + "/finish"
)

// The smallest successful answer of each call.
const (
	verifyOK        = `{"email":"avery.example@example.com","status":"deliverable","reason":"accepted_email"}`
	batchQueued     = `{"batchId":"5f0c2b9e8d7a6b5c4d3e2f1a","status":"queued"}`
	batchCompleted  = `{"batchId":"5f0c2b9e8d7a6b5c4d3e2f1a","status":"completed"}`
	batchProcessing = `{"batchId":"5f0c2b9e8d7a6b5c4d3e2f1a","status":"processing"}`
	creditsOK       = `{"credits":7}` //nolint:gosec // a synthetic answer, not a credential
	resultsOK       = `[` + verifyOK + `]`
	csvFile         = "email,status\r\navery.example@example.com,deliverable\r\n"
)

// Media types the SDK sends, accepts and refuses.
const (
	mediaJSON  = "application/json"
	mediaCSV   = "text/csv"
	mediaOctet = "application/octet-stream"
	mediaHTML  = "text/html"
)

// Validation reasons, as ValidationError.Reason reports them.
const (
	reasonRequired       = "required"
	reasonNil            = "nil"
	reasonNotInitialized = "not_initialized"
	reasonOutOfRange     = "out_of_range"
	reasonInvalidFormat  = "invalid_format"
	reasonInvalidURL     = "invalid_url"
	reasonInvalidUTF8    = "invalid_utf8"
	reasonInvalidValue   = "invalid_value"
	reasonTooLong        = "too_long"
	reasonTooMany        = "too_many"
)

// errUnrelated is an error no CallError may ever match.
var errUnrelated = errors.New("unrelated test error")

// errBrokenCall reports an operation case whose call broke its own contract,
// such as a download that returned a count other than the bytes its writer
// received.
var errBrokenCall = errors.New("the call broke its contract")

// markers returns every synthetic value that must never leak.
func markers() []string {
	return []string{testKey, testEmail, testEmail2, testName, testCallback, "cbmarker-91aa"}
}

// jsonStep is a scripted 200 answer with a JSON content type.
func jsonStep(body string) testutil.Step {
	return testutil.Step{Header: http.Header{"Content-Type": {mediaJSON}}, Body: body}
}

// statusStep is a scripted answer with status and a JSON content type.
func statusStep(status int, body string) testutil.Step {
	return testutil.Step{Status: status, Header: http.Header{"Content-Type": {mediaJSON}}, Body: body}
}

// csvStep is a scripted 200 CSV answer.
func csvStep(body string) testutil.Step {
	return testutil.Step{Header: http.Header{"Content-Type": {mediaCSV}}, Body: body}
}

// newClientAt returns a client with the test key that sends every call to the
// loopback base URL origin through hc, with opts after the test settings.
func newClientAt(tb testing.TB, origin string, hc *http.Client, opts ...bouncer.Option) *bouncer.Client {
	tb.Helper()
	all := append([]bouncer.Option{bouncer.WithTestBaseURL(origin), bouncer.WithHTTPClient(hc)}, opts...)
	c, err := bouncer.NewClient(testKey, all...)
	require.NoError(tb, err)
	return c
}

// newClient returns a client with the test key that sends every call to the
// in-memory transport rt, never dialing, with opts after the test settings.
func newClient(tb testing.TB, rt http.RoundTripper, opts ...bouncer.Option) *bouncer.Client {
	tb.Helper()
	return newClientAt(tb, loopbackOrigin, &http.Client{Transport: rt}, opts...)
}

// newScriptClient returns a client over a Script that answers with steps.
func newScriptClient(tb testing.TB, steps ...testutil.Step) (*bouncer.Client, *testutil.Script) {
	tb.Helper()
	s := testutil.NewScript(steps...)
	return newClient(tb, s), s
}

// newServerClient starts a recording TLS server speaking proto and returns a
// client for it, with opts after the test settings.
func newServerClient(tb testing.TB, proto testutil.Protocol, h http.HandlerFunc, opts ...bouncer.Option,
) (*bouncer.Client, *testutil.Server) {
	tb.Helper()
	srv := testutil.NewServerProto(tb, proto, h)
	return newClientAt(tb, srv.URL(), srv.Client(), opts...), srv
}

// opCase is one public method that calls the provider, called with a minimal
// valid request and reduced to its error. Every suite that runs all the
// methods shares it.
type opCase struct {
	name   string            // the method's name
	op     bouncer.Operation // the operation of its CallErrors
	method string            // its HTTP method
	path   string            // its URL path
	batch  bool              // its request names testBatchID, which its CallErrors carry
	paid   bool              // the provider may bill it
	helper bool              // Wait, which loops over Status
	ok     testutil.Step     // an answer that ends it successfully
	call   func(ctx context.Context, c *bouncer.Client) error
}

// opCases returns every method that calls the provider, in the order of the
// package's operations table.
func opCases() []opCase {
	return []opCase{
		{
			name: "Verify", op: bouncer.OpVerify, method: http.MethodGet, path: pathVerify, paid: true,
			ok: jsonStep(verifyOK),
			call: func(ctx context.Context, c *bouncer.Client) error {
				return noValue(c.Verify(ctx, bouncer.VerifyRequest{Email: testEmail}))
			},
		},
		{
			name: "VerifyBatchSync", op: bouncer.OpBatchSync, method: http.MethodPost, path: pathSync, paid: true,
			ok: jsonStep(resultsOK),
			call: func(ctx context.Context, c *bouncer.Client) error {
				return noValue(c.VerifyBatchSync(ctx, bouncer.BatchSyncRequest{Emails: []string{testEmail}}))
			},
		},
		{
			name: "Credits", op: bouncer.OpCredits, method: http.MethodGet, path: pathCredits,
			ok: jsonStep(creditsOK),
			call: func(ctx context.Context, c *bouncer.Client) error {
				return noValue(c.Credits(ctx))
			},
		},
		{
			name: "Create", op: bouncer.OpBatchCreate, method: http.MethodPost, path: pathBatch, paid: true,
			ok: jsonStep(batchQueued),
			call: func(ctx context.Context, c *bouncer.Client) error {
				return noValue(c.Batches().Create(ctx, bouncer.CreateBatchRequest{
					Entries: []bouncer.BatchEntry{{Email: testEmail}},
				}))
			},
		},
		{
			name: "Status", op: bouncer.OpBatchStatus, method: http.MethodGet, path: pathBatchID, batch: true,
			ok: jsonStep(batchCompleted),
			call: func(ctx context.Context, c *bouncer.Client) error {
				return noValue(c.Batches().Status(ctx, bouncer.BatchStatusRequest{BatchID: testBatchID}))
			},
		},
		{
			name: "Wait", op: bouncer.OpBatchStatus, method: http.MethodGet, path: pathBatchID, batch: true,
			helper: true, ok: jsonStep(batchCompleted),
			call: func(ctx context.Context, c *bouncer.Client) error {
				// Wait returns the last status it read alongside its error, so
				// only a refused request must come without one.
				st, err := c.Batches().Wait(ctx, bouncer.WaitBatchRequest{BatchID: testBatchID, MaxWait: time.Hour})
				if _, refused := errors.AsType[*bouncer.ValidationError](err); refused && st != nil {
					return errBrokenCall
				}
				return err
			},
		},
		{
			name: "Results", op: bouncer.OpBatchResults, method: http.MethodGet, path: pathDownload, batch: true,
			ok: jsonStep(resultsOK),
			call: func(ctx context.Context, c *bouncer.Client) error {
				_, err := collect(c.Batches().Results(ctx, bouncer.BatchResultsRequest{BatchID: testBatchID}))
				return err
			},
		},
		{
			name: "Download", op: bouncer.OpBatchDownload, method: http.MethodGet, path: pathDownload, batch: true,
			ok: csvStep(csvFile),
			call: func(ctx context.Context, c *bouncer.Client) error {
				var w bytes.Buffer
				req := bouncer.DownloadBatchRequest{BatchID: testBatchID, Format: bouncer.FormatCSV}
				n, err := c.Batches().Download(ctx, req, &w)
				if n != int64(w.Len()) || (err == nil && w.String() != csvFile) {
					return errBrokenCall
				}
				return err
			},
		},
		{
			name: "Finish", op: bouncer.OpBatchFinish, method: http.MethodPost, path: pathFinish, batch: true,
			ok: statusStep(http.StatusAccepted, `{}`),
			call: func(ctx context.Context, c *bouncer.Client) error {
				return c.Batches().Finish(ctx, bouncer.FinishBatchRequest{BatchID: testBatchID})
			},
		},
		{
			name: "Delete", op: bouncer.OpBatchDelete, method: http.MethodDelete, path: pathBatchID, batch: true,
			ok: jsonStep(`{}`),
			call: func(ctx context.Context, c *bouncer.Client) error {
				return c.Batches().Delete(ctx, bouncer.DeleteBatchRequest{BatchID: testBatchID})
			},
		},
	}
}

// noValue drops a call's result and keeps its error, checking that a failed
// call returned no value.
func noValue[T any](v *T, err error) error {
	if err != nil && v != nil {
		return errBrokenCall
	}
	return err
}

// callFunc is one public call, reduced to its error.
type callFunc = func(ctx context.Context, c *bouncer.Client) error

// verifyCall returns a Verify call with req.
func verifyCall(req bouncer.VerifyRequest) callFunc {
	return func(ctx context.Context, c *bouncer.Client) error { return noValue(c.Verify(ctx, req)) }
}

// createCall returns a Create call with req.
func createCall(req bouncer.CreateBatchRequest) callFunc {
	return func(ctx context.Context, c *bouncer.Client) error { return noValue(c.Batches().Create(ctx, req)) }
}

// downloadCall returns a Download call with req that writes to w.
func downloadCall(req bouncer.DownloadBatchRequest, w io.Writer) callFunc {
	return func(ctx context.Context, c *bouncer.Client) error {
		_, err := c.Batches().Download(ctx, req, w)
		return err
	}
}

// collect ranges over a Results sequence and returns its records and its
// error, checking that nothing follows the error.
func collect(seq iter.Seq2[bouncer.Verification, error]) ([]bouncer.Verification, error) {
	var (
		out      []bouncer.Verification
		finalErr error
	)
	for v, err := range seq {
		if finalErr != nil {
			return out, errBrokenCall
		}
		if err != nil {
			if v != (bouncer.Verification{}) {
				return out, errBrokenCall
			}
			finalErr = err
			continue
		}
		out = append(out, v)
	}
	return out, finalErr
}

// wantCall is the expected exported state of a CallError. Records and
// BytesWritten are checked only when the test sets checkCounts.
type wantCall struct {
	Kind         bouncer.FailureKind
	Op           bouncer.Operation
	StatusCode   int
	APIStatus    int
	BatchID      bouncer.BatchID
	Field        string
	Records      int64
	BytesWritten int64
	checkCounts  bool
}

// kindTarget returns the error a CallError of kind must match with errors.Is.
func kindTarget(kind bouncer.FailureKind) error {
	switch kind {
	case bouncer.FailureUnauthorized:
		return bouncer.ErrUnauthorized
	case bouncer.FailurePaymentRequired:
		return bouncer.ErrPaymentRequired
	case bouncer.FailureForbidden:
		return bouncer.ErrForbidden
	case bouncer.FailureNotFound:
		return bouncer.ErrNotFound
	case bouncer.FailureBatchState:
		return bouncer.ErrBatchState
	case bouncer.FailureRateLimited:
		return bouncer.ErrRateLimited
	case bouncer.FailureRejected:
		return bouncer.ErrRejected
	case bouncer.FailureUnavailable:
		return bouncer.ErrUnavailable
	case bouncer.FailureUpstream:
		return bouncer.ErrUpstream
	case bouncer.FailureUnexpectedResponse:
		return bouncer.ErrUnexpectedResponse
	case bouncer.FailureMalformedResponse:
		return bouncer.ErrMalformedResponse
	case bouncer.FailureResponseTooLarge:
		return bouncer.ErrResponseTooLarge
	case bouncer.FailureTransport:
		return bouncer.ErrTransport
	case bouncer.FailureTimeout:
		return bouncer.ErrTimeout
	case bouncer.FailureCanceled:
		return context.Canceled
	case bouncer.FailureDeadlineExceeded:
		return context.DeadlineExceeded
	case bouncer.FailureWriteFailed:
		return bouncer.ErrWriteFailed
	case bouncer.FailureUnknownBatchState:
		return bouncer.ErrUnknownBatchState
	case bouncer.FailureBudgetExhausted:
		return bouncer.ErrBudgetExhausted
	}
	return nil
}

// requireCallError fails tb unless err is a *CallError with want's exported
// state that matches its kind's target with errors.Is, and returns a copy of
// it (a value, so that a caller may ignore it).
func requireCallError(tb testing.TB, err error, want wantCall) bouncer.CallError {
	tb.Helper()
	ce := testutil.RequireErrorAs[*bouncer.CallError](tb, err)
	assert.Equal(tb, want.Kind, ce.Kind, "Kind")
	assert.Equal(tb, want.Op, ce.Op, "Op")
	assert.Equal(tb, want.StatusCode, ce.StatusCode, "StatusCode")
	assert.Equal(tb, want.APIStatus, ce.APIStatus, "APIStatus")
	assert.Equal(tb, want.BatchID, ce.BatchID, "BatchID")
	assert.Equal(tb, want.Field, ce.Field, "Field")
	if want.checkCounts {
		assert.Equal(tb, want.Records, ce.Records, "Records")
		assert.Equal(tb, want.BytesWritten, ce.BytesWritten, "BytesWritten")
	}
	if target := kindTarget(want.Kind); target != nil {
		require.ErrorIs(tb, err, target)
	}
	require.NotErrorIs(tb, err, errUnrelated)
	return *ce
}

// requireValidation fails tb unless err is a *ValidationError for sentinel
// with field and reason, and returns a copy of it (a value, so that a caller
// may ignore it).
func requireValidation(tb testing.TB, err, sentinel error, field, reason string) bouncer.ValidationError {
	tb.Helper()
	ve := testutil.RequireErrorAs[*bouncer.ValidationError](tb, err)
	require.ErrorIs(tb, err, sentinel)
	assert.Equal(tb, field, ve.Field, "Field")
	assert.Equal(tb, reason, ve.Reason, "Reason")
	return *ve
}

// wantFor completes w, the CallError of a failed call of o, with o's Op and
// BatchID.
func (o opCase) wantFor(w wantCall) wantCall {
	w.Op = o.op
	if o.batch {
		w.BatchID = testBatchID
	}
	return w
}
