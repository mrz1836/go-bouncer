package bouncer_test

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/mrz1836/go-bouncer"
	"github.com/mrz1836/go-bouncer/internal/testutil"
)

// TestEverySuccessIsOneAttempt runs every operation against its minimal
// successful answer and checks that it made exactly one round trip, with the
// method and path its documentation names.
func TestEverySuccessIsOneAttempt(t *testing.T) {
	t.Parallel()
	for _, oc := range opCases() {
		t.Run(oc.name, func(t *testing.T) {
			t.Parallel()
			c, script := newScriptClient(t, oc.ok)
			require.NoError(t, oc.call(t.Context(), c))
			req := testutil.OnlyRequest(t, script)
			assert.Equal(t, oc.method, req.Method)
			assert.Equal(t, oc.path, req.Path)
		})
	}
}

// TestEverySuccessOverTLS runs every operation against a recording TLS
// server, over HTTP/1.1 and HTTP/2, and checks that the server saw exactly one
// request.
func TestEverySuccessOverTLS(t *testing.T) {
	t.Parallel()
	for _, proto := range testutil.Protocols() {
		for _, oc := range opCases() {
			t.Run(proto.Name()+"/"+oc.name, func(t *testing.T) {
				t.Parallel()
				c, srv := newServerClient(t, proto, testutil.Serve(oc.ok))
				require.NoError(t, oc.call(t.Context(), c))
				req := testutil.OnlyRequest(t, srv)
				assert.Equal(t, oc.method, req.Method)
				assert.Equal(t, oc.path, req.Path)
				assert.Equal(t, string(proto), req.Proto)
			})
		}
	}
}

// TestFailedCallsAreOneAttempt answers every operation with an error status
// and checks that it made exactly one round trip and never retried.
func TestFailedCallsAreOneAttempt(t *testing.T) {
	t.Parallel()
	statuses := []int{
		http.StatusBadRequest, http.StatusUnauthorized, http.StatusPaymentRequired, http.StatusTooManyRequests,
		http.StatusInternalServerError, http.StatusServiceUnavailable,
	}
	for _, oc := range opCases() {
		for _, status := range statuses {
			t.Run(oc.name+"/"+http.StatusText(status), func(t *testing.T) {
				t.Parallel()
				c, script := newScriptClient(t, statusStep(status, `{"status":"`+http.StatusText(status)+`"}`))
				err := oc.call(t.Context(), c)
				require.Error(t, err)
				assert.Equal(t, 1, script.Calls(), "exactly one attempt, never a retry")
			})
		}
	}
}

// TestTransportFailuresAreOneAttempt fails every round trip in transit and
// checks that the SDK never tries again.
func TestTransportFailuresAreOneAttempt(t *testing.T) {
	t.Parallel()
	for _, oc := range opCases() {
		t.Run(oc.name, func(t *testing.T) {
			t.Parallel()
			c, script := newScriptClient(t, testutil.Step{Err: io.ErrUnexpectedEOF})
			err := oc.call(t.Context(), c)
			requireCallError(t, err, oc.wantFor(wantCall{Kind: bouncer.FailureTransport}))
			assert.Equal(t, 1, script.Calls())
		})
	}
}

// TestNoIOWithoutAValidCall checks every way a call can be refused before any
// I/O: a nil or zero Client, a zero BatchService, a nil context, a context
// already done, and an invalid request. None reaches the transport.
func TestNoIOWithoutAValidCall(t *testing.T) {
	t.Parallel()
	t.Run("nil and zero clients", func(t *testing.T) {
		t.Parallel()
		for _, oc := range opCases() {
			for name, c := range map[string]*bouncer.Client{"nil": nil, "zero": {}} {
				t.Run(oc.name+"/"+name, func(t *testing.T) {
					t.Parallel()
					requireValidation(t, oc.call(t.Context(), c), bouncer.ErrInvalidConfig, "Client", reasonNotInitialized)
				})
			}
		}
	})

	t.Run("zero BatchService", func(t *testing.T) {
		t.Parallel()
		var s bouncer.BatchService
		for name, call := range map[string]func(ctx context.Context) error{
			"Create": func(ctx context.Context) error {
				return noValue(s.Create(ctx, bouncer.CreateBatchRequest{Entries: []bouncer.BatchEntry{{Email: testEmail}}}))
			},
			"Status": func(ctx context.Context) error {
				return noValue(s.Status(ctx, bouncer.BatchStatusRequest{BatchID: testBatchID}))
			},
			"Wait": func(ctx context.Context) error {
				return noValue(s.Wait(ctx, bouncer.WaitBatchRequest{BatchID: testBatchID, MaxWait: time.Minute}))
			},
			"Results": func(ctx context.Context) error {
				_, err := collect(s.Results(ctx, bouncer.BatchResultsRequest{BatchID: testBatchID}))
				return err
			},
			"Download": func(ctx context.Context) error {
				_, err := s.Download(ctx, bouncer.DownloadBatchRequest{BatchID: testBatchID, Format: bouncer.FormatCSV}, io.Discard)
				return err
			},
			"Finish": func(ctx context.Context) error {
				return s.Finish(ctx, bouncer.FinishBatchRequest{BatchID: testBatchID})
			},
			"Delete": func(ctx context.Context) error {
				return s.Delete(ctx, bouncer.DeleteBatchRequest{BatchID: testBatchID})
			},
		} {
			t.Run(name, func(t *testing.T) {
				t.Parallel()
				requireValidation(t, call(t.Context()), bouncer.ErrInvalidConfig, "Client", reasonNotInitialized)
			})
		}
	})

	t.Run("nil context", func(t *testing.T) {
		t.Parallel()
		for _, oc := range opCases() {
			t.Run(oc.name, func(t *testing.T) {
				t.Parallel()
				counter := &testutil.CountingTransport{Next: testutil.StaticTransport(http.StatusOK, verifyOK)}
				c := newClient(t, counter)
				requireValidation(t, oc.call(nil, c), bouncer.ErrInvalidRequest, "ctx", reasonNil)
				assert.Zero(t, counter.Attempts())
			})
		}
	})

	t.Run("context already done", func(t *testing.T) {
		t.Parallel()
		canceled, cancel := context.WithCancel(t.Context())
		cancel()
		expired, cancelExpired := context.WithDeadline(t.Context(), time.Now().Add(-time.Second))
		t.Cleanup(cancelExpired)
		for _, oc := range opCases() {
			for _, tc := range []struct {
				name string
				ctx  context.Context //nolint:containedctx // a table of contexts to call with
				kind bouncer.FailureKind
			}{
				{"canceled", canceled, bouncer.FailureCanceled},
				{"expired", expired, bouncer.FailureDeadlineExceeded},
			} {
				t.Run(oc.name+"/"+tc.name, func(t *testing.T) {
					t.Parallel()
					counter := &testutil.CountingTransport{Next: testutil.StaticTransport(http.StatusOK, verifyOK)}
					c := newClient(t, counter)
					err := oc.call(tc.ctx, c)
					requireCallError(t, err, oc.wantFor(wantCall{Kind: tc.kind}))
					assert.Zero(t, counter.Attempts(), "a context already done sends nothing")
				})
			}
		}
	})

	t.Run("invalid requests", func(t *testing.T) {
		t.Parallel()
		for _, tc := range invalidRequestCases() {
			t.Run(tc.name, func(t *testing.T) {
				t.Parallel()
				counter := &testutil.CountingTransport{Next: testutil.StaticTransport(http.StatusOK, verifyOK)}
				c := newClient(t, counter)
				requireValidation(t, tc.call(t.Context(), c), bouncer.ErrInvalidRequest, tc.field, tc.reason)
				assert.Zero(t, counter.Attempts(), "an invalid request sends nothing")
			})
		}
	})
}

// invalidCase is one request that fails validation.
type invalidCase struct {
	name   string
	field  string
	reason string
	call   func(ctx context.Context, c *bouncer.Client) error
}

// invalidRequestCases returns at least one invalid request per operation,
// and each rule of the validation table.
func invalidRequestCases() []invalidCase {
	sync := func(emails []string) func(context.Context, *bouncer.Client) error {
		return func(ctx context.Context, c *bouncer.Client) error {
			return noValue(c.VerifyBatchSync(ctx, bouncer.BatchSyncRequest{Emails: emails}))
		}
	}
	status := func(id bouncer.BatchID) func(context.Context, *bouncer.Client) error {
		return func(ctx context.Context, c *bouncer.Client) error {
			return noValue(c.Batches().Status(ctx, bouncer.BatchStatusRequest{BatchID: id}))
		}
	}
	wait := func(req bouncer.WaitBatchRequest) func(context.Context, *bouncer.Client) error {
		return func(ctx context.Context, c *bouncer.Client) error { return noValue(c.Batches().Wait(ctx, req)) }
	}
	entries := func(e ...bouncer.BatchEntry) []bouncer.BatchEntry { return e }
	long := strings.Repeat("a", bouncer.MaxEmailBytes+1)
	return []invalidCase{
		{"Verify empty email", "Email", reasonRequired, verifyCall(bouncer.VerifyRequest{})},
		{"Verify long email", "Email", reasonTooLong, verifyCall(bouncer.VerifyRequest{Email: long})},
		{"Verify invalid UTF-8", "Email", reasonInvalidUTF8, verifyCall(bouncer.VerifyRequest{Email: "a\xffb@example.com"})},
		{"Verify timeout below 1s", "Timeout", reasonOutOfRange, verifyCall(bouncer.VerifyRequest{
			Email: testEmail, Timeout: 500 * time.Millisecond,
		})},
		{"Verify timeout above 30s", "Timeout", reasonOutOfRange, verifyCall(bouncer.VerifyRequest{
			Email: testEmail, Timeout: 31 * time.Second,
		})},
		{"Verify negative timeout", "Timeout", reasonOutOfRange, verifyCall(bouncer.VerifyRequest{
			Email: testEmail, Timeout: -time.Second,
		})},
		{"Verify fractional timeout", "Timeout", "not_whole_seconds", verifyCall(bouncer.VerifyRequest{
			Email: testEmail, Timeout: 1500 * time.Millisecond,
		})},
		{"Create no entries", "Entries", reasonRequired, createCall(bouncer.CreateBatchRequest{})},
		{"Create empty email", "Entries[1].Email", reasonRequired, createCall(bouncer.CreateBatchRequest{
			Entries: entries(bouncer.BatchEntry{Email: testEmail}, bouncer.BatchEntry{}),
		})},
		{"Create invalid name", "Entries[0].Name", reasonInvalidUTF8, createCall(bouncer.CreateBatchRequest{
			Entries: entries(bouncer.BatchEntry{Email: testEmail, Name: "\xff"}),
		})},
		{"Create long name", "Entries[0].Name", reasonTooLong, createCall(bouncer.CreateBatchRequest{
			Entries: entries(bouncer.BatchEntry{Email: testEmail, Name: strings.Repeat("n", 257)}),
		})},
		{"Create http callback", "CallbackURL", "unsupported_scheme", createCall(bouncer.CreateBatchRequest{
			Entries: entries(bouncer.BatchEntry{Email: testEmail}), CallbackURL: "http://hooks.example.org/x",
		})},
		{"Create relative callback", "CallbackURL", reasonInvalidURL, createCall(bouncer.CreateBatchRequest{
			Entries: entries(bouncer.BatchEntry{Email: testEmail}), CallbackURL: "/hooks",
		})},
		{"Create callback with fragment", "CallbackURL", reasonInvalidURL, createCall(bouncer.CreateBatchRequest{
			Entries: entries(bouncer.BatchEntry{Email: testEmail}), CallbackURL: "https://hooks.example.org/x#f",
		})},
		{"Create callback without a hostname", "CallbackURL", reasonInvalidURL, createCall(bouncer.CreateBatchRequest{
			Entries: entries(bouncer.BatchEntry{Email: testEmail}), CallbackURL: "https://:8443/hooks",
		})},
		{"Create opaque callback", "CallbackURL", "unsupported_scheme", createCall(bouncer.CreateBatchRequest{
			Entries: entries(bouncer.BatchEntry{Email: testEmail}), CallbackURL: "mailto:hooks@example.org",
		})},
		{"Create callback with space", "CallbackURL", reasonInvalidURL, createCall(bouncer.CreateBatchRequest{
			Entries: entries(bouncer.BatchEntry{Email: testEmail}), CallbackURL: "https://hooks.example.org/a b",
		})},
		{"Create long callback", "CallbackURL", reasonTooLong, createCall(bouncer.CreateBatchRequest{
			Entries:     entries(bouncer.BatchEntry{Email: testEmail}),
			CallbackURL: "https://hooks.example.org/" + strings.Repeat("p", 2048),
		})},
		{"Create too many entries", "Entries", reasonTooMany, createCall(bouncer.CreateBatchRequest{
			Entries: make([]bouncer.BatchEntry, bouncer.MaxBatchEntries+1),
		})},
		{"Sync no emails", "Emails", reasonRequired, sync(nil)},
		{"Sync too many emails", "Emails", reasonTooMany, sync(make([]string, bouncer.MaxSyncEmails+1))},
		{"Sync empty email", "Emails[2]", reasonRequired, sync([]string{testEmail, testEmail2, ""})},
		{"Status empty ID", "BatchID", reasonRequired, status("")},
		{"Status ID with slash", "BatchID", reasonInvalidFormat, status("a/b")},
		{"Status ID with percent", "BatchID", reasonInvalidFormat, status("a%2Fb")},
		{"Status ID with query", "BatchID", reasonInvalidFormat, status("a?b")},
		{"Status ID dot", "BatchID", reasonInvalidFormat, status(".")},
		{"Status ID dot dot", "BatchID", reasonInvalidFormat, status("..")},
		{"Status ID sync", "BatchID", reasonInvalidFormat, status("SYNC")},
		{"Status ID with space", "BatchID", reasonInvalidFormat, status("a b")},
		{"Status long ID", "BatchID", reasonTooLong, status(bouncer.BatchID(strings.Repeat("f", 129)))},
		{"Download no format", "Format", reasonRequired, downloadCall(bouncer.DownloadBatchRequest{BatchID: testBatchID}, io.Discard)},
		{"Download bad format", "Format", reasonInvalidValue, downloadCall(bouncer.DownloadBatchRequest{
			BatchID: testBatchID, Format: "xml",
		}, io.Discard)},
		{"Download bad filter", "Filter", reasonInvalidValue, downloadCall(bouncer.DownloadBatchRequest{
			BatchID: testBatchID, Filter: "valid", Format: bouncer.FormatJSON,
		}, io.Discard)},
		{"Download empty ID", "BatchID", reasonRequired, downloadCall(bouncer.DownloadBatchRequest{
			Format: bouncer.FormatCSV,
		}, io.Discard)},
		{"Download nil writer", "w", reasonNil, downloadCall(bouncer.DownloadBatchRequest{
			BatchID: testBatchID, Format: bouncer.FormatCSV,
		}, nil)},
		{"Results bad filter", "Filter", reasonInvalidValue, func(ctx context.Context, c *bouncer.Client) error {
			_, err := collect(c.Batches().Results(ctx, bouncer.BatchResultsRequest{BatchID: testBatchID, Filter: "ALL"}))
			return err
		}},
		{"Results ID with slash", "BatchID", reasonInvalidFormat, func(ctx context.Context, c *bouncer.Client) error {
			_, err := collect(c.Batches().Results(ctx, bouncer.BatchResultsRequest{BatchID: "a/b"}))
			return err
		}},
		{"Finish empty ID", "BatchID", reasonRequired, func(ctx context.Context, c *bouncer.Client) error {
			return c.Batches().Finish(ctx, bouncer.FinishBatchRequest{})
		}},
		{"Delete ID with backslash", "BatchID", reasonInvalidFormat, func(ctx context.Context, c *bouncer.Client) error {
			return c.Batches().Delete(ctx, bouncer.DeleteBatchRequest{BatchID: `a\b`})
		}},
		{"Wait no MaxWait", "MaxWait", reasonRequired, wait(bouncer.WaitBatchRequest{BatchID: testBatchID})},
		{"Wait MaxWait above 72h", "MaxWait", reasonOutOfRange, wait(bouncer.WaitBatchRequest{
			BatchID: testBatchID, MaxWait: 73 * time.Hour,
		})},
		{"Wait interval below 1s", "Interval", reasonOutOfRange, wait(bouncer.WaitBatchRequest{
			BatchID: testBatchID, Interval: time.Millisecond, MaxWait: time.Hour,
		})},
		{"Wait interval above 10m", "Interval", reasonOutOfRange, wait(bouncer.WaitBatchRequest{
			BatchID: testBatchID, Interval: 11 * time.Minute, MaxWait: time.Hour,
		})},
	}
}

// TestVerifyTimeoutMustLeaveHeadroom checks the rule that the provider's
// budget plus 10 seconds fits the Client's own timeout.
func TestVerifyTimeoutMustLeaveHeadroom(t *testing.T) {
	t.Parallel()
	counter := &testutil.CountingTransport{Next: testutil.StaticTransport(http.StatusOK, verifyOK)}
	c := newClient(t, counter, bouncer.WithTimeout(30*time.Second))
	_, err := c.Verify(t.Context(), bouncer.VerifyRequest{Email: testEmail, Timeout: 21 * time.Second})
	requireValidation(t, err, bouncer.ErrInvalidRequest, "Timeout", "exceeds_client_timeout")
	assert.Zero(t, counter.Attempts())

	_, err = c.Verify(t.Context(), bouncer.VerifyRequest{Email: testEmail, Timeout: 20 * time.Second})
	require.NoError(t, err, "Timeout + 10s == WithTimeout is allowed")
	assert.Equal(t, 1, counter.Attempts())
}
