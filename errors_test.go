package bouncer_test

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/mrz1836/go-bouncer"
	"github.com/mrz1836/go-bouncer/internal/testutil"
)

// errErrorsSynthetic is the static error the synthetic transport failures wrap.
var errErrorsSynthetic = errors.New("synthetic transport failure")

// errorsAllKinds returns every FailureKind the package defines.
func errorsAllKinds() []bouncer.FailureKind {
	return []bouncer.FailureKind{
		bouncer.FailureUnauthorized, bouncer.FailurePaymentRequired, bouncer.FailureForbidden,
		bouncer.FailureNotFound, bouncer.FailureBatchState, bouncer.FailureRateLimited, bouncer.FailureRejected,
		bouncer.FailureUnavailable, bouncer.FailureUpstream, bouncer.FailureUnexpectedResponse,
		bouncer.FailureMalformedResponse, bouncer.FailureResponseTooLarge, bouncer.FailureTransport,
		bouncer.FailureTimeout, bouncer.FailureCanceled, bouncer.FailureDeadlineExceeded,
		bouncer.FailureWriteFailed, bouncer.FailureUnknownBatchState, bouncer.FailureBudgetExhausted,
	}
}

// errorsAllSentinels returns every sentinel the package defines, by name.
func errorsAllSentinels() map[string]error {
	return map[string]error{
		"ErrInvalidConfig":      bouncer.ErrInvalidConfig,
		"ErrInvalidRequest":     bouncer.ErrInvalidRequest,
		"ErrUnauthorized":       bouncer.ErrUnauthorized,
		"ErrPaymentRequired":    bouncer.ErrPaymentRequired,
		"ErrForbidden":          bouncer.ErrForbidden,
		"ErrNotFound":           bouncer.ErrNotFound,
		"ErrBatchState":         bouncer.ErrBatchState,
		"ErrRateLimited":        bouncer.ErrRateLimited,
		"ErrRejected":           bouncer.ErrRejected,
		"ErrUnavailable":        bouncer.ErrUnavailable,
		"ErrUpstream":           bouncer.ErrUpstream,
		"ErrUnexpectedResponse": bouncer.ErrUnexpectedResponse,
		"ErrMalformedResponse":  bouncer.ErrMalformedResponse,
		"ErrResponseTooLarge":   bouncer.ErrResponseTooLarge,
		"ErrTransport":          bouncer.ErrTransport,
		"ErrTimeout":            bouncer.ErrTimeout,
		"ErrWriteFailed":        bouncer.ErrWriteFailed,
		"ErrUnknownBatchState":  bouncer.ErrUnknownBatchState,
		"ErrBudgetExhausted":    bouncer.ErrBudgetExhausted,
	}
}

func TestSentinelsAreDistinctAndPrefixed(t *testing.T) {
	t.Parallel()
	sentinels := errorsAllSentinels()
	messages := map[string]string{}
	for name, err := range sentinels {
		assert.True(t, strings.HasPrefix(err.Error(), "bouncer: "), "%s: %q", name, err.Error())
		other, dup := messages[err.Error()]
		assert.False(t, dup, "%s and %s share the message %q", name, other, err.Error())
		messages[err.Error()] = name
		for otherName, other := range sentinels {
			if otherName != name {
				assert.NotErrorIs(t, err, other, "%s must not match %s", name, otherName)
			}
		}
	}
}

func TestCallErrorIsMatchesItsKindOnly(t *testing.T) {
	t.Parallel()
	sentinels := errorsAllSentinels()
	targets := maps.Clone(sentinels)
	targets["context.Canceled"] = context.Canceled
	targets["context.DeadlineExceeded"] = context.DeadlineExceeded
	want := map[bouncer.FailureKind][]string{
		bouncer.FailureUnauthorized:       {"ErrUnauthorized"},
		bouncer.FailurePaymentRequired:    {"ErrPaymentRequired"},
		bouncer.FailureForbidden:          {"ErrForbidden"},
		bouncer.FailureNotFound:           {"ErrNotFound"},
		bouncer.FailureBatchState:         {"ErrBatchState"},
		bouncer.FailureRateLimited:        {"ErrRateLimited"},
		bouncer.FailureRejected:           {"ErrRejected"},
		bouncer.FailureUnavailable:        {"ErrUnavailable"},
		bouncer.FailureUpstream:           {"ErrUpstream"},
		bouncer.FailureUnexpectedResponse: {"ErrUnexpectedResponse"},
		bouncer.FailureMalformedResponse:  {"ErrMalformedResponse"},
		bouncer.FailureResponseTooLarge:   {"ErrResponseTooLarge"},
		bouncer.FailureTransport:          {"ErrTransport"},
		bouncer.FailureTimeout:            {"ErrTimeout", "context.DeadlineExceeded"},
		bouncer.FailureCanceled:           {"context.Canceled"},
		bouncer.FailureDeadlineExceeded:   {"context.DeadlineExceeded"},
		bouncer.FailureWriteFailed:        {"ErrWriteFailed"},
		bouncer.FailureUnknownBatchState:  {"ErrUnknownBatchState"},
		bouncer.FailureBudgetExhausted:    {"ErrBudgetExhausted"},
		"no_such_kind":                    nil,
		"":                                nil,
	}
	require.Len(t, want, len(errorsAllKinds())+2, "every kind is covered")
	for kind, matches := range want {
		t.Run(string(kind), func(t *testing.T) {
			t.Parallel()
			// A fake built from exported fields matches like an SDK error.
			ce := &bouncer.CallError{Kind: kind, Op: bouncer.OpVerify}
			for name, target := range targets {
				if slices.Contains(matches, name) {
					assert.ErrorIs(t, ce, target, "%s must match %s", kind, name)
				} else {
					assert.NotErrorIs(t, ce, target, "%s must not match %s", kind, name)
				}
			}
			require.NotErrorIs(t, ce, errUnrelated)
			assert.NoError(t, ce.Unwrap(), "a fake has no cause")
		})
	}
}

func TestCallErrorNilReceiver(t *testing.T) {
	t.Parallel()
	var ce *bouncer.CallError
	assert.Equal(t, "bouncer: <nil CallError>", ce.Error())
	assert.Equal(t, "(*bouncer.CallError)(nil)", ce.GoString())
	require.NoError(t, ce.Unwrap())
	assert.False(t, ce.Is(bouncer.ErrTimeout))
	assert.False(t, ce.Timeout())
	assert.Equal(t, bouncer.ProviderDiagnostics{}, ce.Diagnostics())
}

func TestCallErrorErrorFormat(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		ce   *bouncer.CallError
		want string
	}{
		{
			"status only",
			&bouncer.CallError{Kind: bouncer.FailureRateLimited, Op: bouncer.OpVerify, StatusCode: 429},
			"bouncer: verify: rate_limited (HTTP 429)",
		},
		{
			"status and envelope",
			&bouncer.CallError{Kind: bouncer.FailureRejected, Op: bouncer.OpBatchFinish, StatusCode: 200, APIStatus: 400},
			"bouncer: batch_finish: rejected (HTTP 200, API 400)",
		},
		{
			"envelope only",
			&bouncer.CallError{Kind: bouncer.FailureRejected, Op: bouncer.OpVerify, APIStatus: 400},
			"bouncer: verify: rejected (API 400)",
		},
		{
			"field",
			&bouncer.CallError{
				Kind: bouncer.FailureMalformedResponse, Op: bouncer.OpBatchResults, StatusCode: 200, Field: "[17].score",
			},
			"bouncer: batch_results: malformed_response (HTTP 200): [17].score",
		},
		{"no status", &bouncer.CallError{Kind: bouncer.FailureTimeout, Op: bouncer.OpCredits}, "bouncer: credits: timeout"},
		{"empty kind", &bouncer.CallError{Op: bouncer.OpVerify}, "bouncer: verify: call_failed"},
		{"empty op", &bouncer.CallError{Kind: bouncer.FailureTimeout}, "bouncer: timeout"},
		{"empty", &bouncer.CallError{}, "bouncer: call_failed"},
		{
			"other fields stay out",
			&bouncer.CallError{
				Kind: bouncer.FailureWriteFailed, Op: bouncer.OpBatchDownload, StatusCode: 200, BatchID: testBatchID,
				Records: 3, BytesWritten: 99, RetryAfter: time.Minute, HasRetryAfter: true,
			},
			"bouncer: batch_download: write_failed (HTTP 200)",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.want, tt.ce.Error())
			assert.Equal(t, tt.want, fmt.Sprintf("%v", tt.ce))
			assert.Equal(t, tt.want, fmt.Sprintf("%+v", tt.ce))
		})
	}
}

// errorsTransportCase is a failure in transit and the class Error() names.
type errorsTransportCase struct {
	name  string
	err   error
	class string
}

// errorsTransportCases returns a transport error for each fixed class. The
// texts hold markers that must never surface.
func errorsTransportCases() []errorsTransportCase {
	return []errorsTransportCase{
		{"dns", &net.DNSError{Err: "no such host " + testEmail, Name: "leak-marker-host.invalid"}, "dns"},
		{"proxy", &net.OpError{Op: "proxyconnect", Net: "tcp", Err: fmt.Errorf("proxy refused %s: %w", testKey, errErrorsSynthetic)}, "proxy"},
		{"dial", &net.OpError{Op: "dial", Net: "tcp", Err: fmt.Errorf("refused %s: %w", testEmail, errErrorsSynthetic)}, "dial"},
		{"tls record", tls.RecordHeaderError{Msg: "bad record " + testEmail}, "tls"},
		{"tls certificate", &tls.CertificateVerificationError{Err: fmt.Errorf("unknown authority %s: %w", testKey, errErrorsSynthetic)}, "tls"},
		{"tls alert", tls.AlertError(40), "tls"},
		{"reset", fmt.Errorf("read %s: %w", testEmail, syscall.ECONNRESET), "reset"},
		{"aborted", fmt.Errorf("read: %w", syscall.ECONNABORTED), "reset"},
		{"broken pipe", fmt.Errorf("write: %w", syscall.EPIPE), "reset"},
		{"eof", io.EOF, "closed"},
		{"unexpected eof", io.ErrUnexpectedEOF, "closed"},
		{"closed", fmt.Errorf("use of %s: %w", testKey, net.ErrClosed), "closed"},
		{"other", fmt.Errorf("strange %s %s: %w", testEmail, testKey, errErrorsSynthetic), "other"},
	}
}

// TestTransportFailureFormat fails a real call in transit with each error
// class and checks Error(), Unwrap and the error types that must stay
// unreachable.
func TestTransportFailureFormat(t *testing.T) {
	t.Parallel()
	for _, tt := range errorsTransportCases() {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			c, _ := newScriptClient(t, testutil.Step{Err: tt.err})
			_, err := c.Verify(t.Context(), bouncer.VerifyRequest{Email: testEmail})
			ce := requireCallError(t, err, wantCall{Kind: bouncer.FailureTransport, Op: bouncer.OpVerify})
			assert.Equal(t, "bouncer: verify: transport: "+tt.class, err.Error())
			errorsAssertSanitized(t, err)
			cause := ce.Unwrap()
			require.Error(t, cause)
			assert.True(t, strings.HasPrefix(cause.Error(), "bouncer: transport: "), "cause %q", cause.Error())
			assert.NoError(t, errors.Unwrap(cause), "a fixed cause wraps nothing")
		})
	}
}

// errorsAssertSanitized checks that err reaches none of the standard-library
// error types that can quote URLs, hosts or bytes, and prints no marker.
func errorsAssertSanitized(t *testing.T, err error) {
	t.Helper()
	_, isURL := errors.AsType[*url.Error](err)
	assert.False(t, isURL, "*url.Error is unreachable")
	_, isOp := errors.AsType[*net.OpError](err)
	assert.False(t, isOp, "*net.OpError is unreachable")
	_, isDNS := errors.AsType[*net.DNSError](err)
	assert.False(t, isDNS, "*net.DNSError is unreachable")
	_, isNet := errors.AsType[net.Error](err)
	assert.False(t, isNet, "no net.Error is reachable")
	_, isSyntax := errors.AsType[*json.SyntaxError](err)
	assert.False(t, isSyntax, "*json.SyntaxError is unreachable")
	_, isType := errors.AsType[*json.UnmarshalTypeError](err)
	assert.False(t, isType, "*json.UnmarshalTypeError is unreachable")
	_, isCert := errors.AsType[*tls.CertificateVerificationError](err)
	assert.False(t, isCert, "TLS errors are unreachable")
	require.NotErrorIs(t, err, syscall.ECONNRESET)
	require.NotErrorIs(t, err, io.EOF)
	for _, s := range []string{err.Error(), fmt.Sprintf("%+v", err), fmt.Sprintf("%#v", err)} {
		testutil.AssertRedacted(t, s, append(markers(), "leak-marker-host"))
	}
}

// TestStalledAndTruncatedBodiesFormat checks the two transport classes a body
// read produces: a body that stalls, and one shorter than declared.
func TestStalledAndTruncatedBodiesFormat(t *testing.T) {
	t.Parallel()
	stalled := testutil.Step{Respond: func(r *http.Request) (*http.Response, error) {
		testutil.Drain(r)
		body := testutil.NewBody(`{"email":`)
		body.Stall = true
		return testutil.Response(r, http.StatusOK, body, -1), nil
	}}
	c, _ := newScriptClient(t, stalled)
	_, err := c.Verify(t.Context(), bouncer.VerifyRequest{Email: testEmail})
	requireCallError(t, err, wantCall{Kind: bouncer.FailureTransport, Op: bouncer.OpVerify, StatusCode: 200})
	assert.Equal(t, "bouncer: verify: transport (HTTP 200): stalled", err.Error())

	short := testutil.Step{Respond: func(r *http.Request) (*http.Response, error) {
		testutil.Drain(r)
		return testutil.Response(r, http.StatusOK, testutil.NewBody(verifyOK), int64(len(verifyOK)+10)), nil
	}}
	c, _ = newScriptClient(t, short)
	_, err = c.Verify(t.Context(), bouncer.VerifyRequest{Email: testEmail})
	requireCallError(t, err, wantCall{Kind: bouncer.FailureTransport, Op: bouncer.OpVerify, StatusCode: 200})
	assert.Equal(t, "bouncer: verify: transport (HTTP 200): closed", err.Error())
}

// TestDecodeFailureIsSanitized checks that a body encoding/json rejects never
// surfaces the decoder's error.
func TestDecodeFailureIsSanitized(t *testing.T) {
	t.Parallel()
	for _, body := range []string{`{`, `{"email":"` + testEmail + `",}`, `{"email":1,"status":"x","reason":"y"}`} {
		t.Run(body, func(t *testing.T) {
			t.Parallel()
			c, _ := newScriptClient(t, jsonStep(body))
			_, err := c.Verify(t.Context(), bouncer.VerifyRequest{Email: testEmail})
			ce := testutil.RequireErrorAs[*bouncer.CallError](t, err)
			assert.Equal(t, bouncer.FailureMalformedResponse, ce.Kind)
			errorsAssertSanitized(t, err)
			assert.True(t, strings.HasPrefix(ce.Unwrap().Error(), "bouncer: "))
		})
	}
}

// TestContextAndTimeoutCauses checks the causes the context kinds and the
// timeout keep: the context sentinels themselves.
func TestContextAndTimeoutCauses(t *testing.T) {
	t.Parallel()
	t.Run("canceled", func(t *testing.T) {
		t.Parallel()
		ctx, cancel := context.WithCancel(t.Context())
		cancel()
		c, _ := newScriptClient(t, jsonStep(verifyOK))
		_, err := c.Verify(ctx, bouncer.VerifyRequest{Email: testEmail})
		ce := requireCallError(t, err, wantCall{Kind: bouncer.FailureCanceled, Op: bouncer.OpVerify})
		assert.Same(t, context.Canceled, ce.Unwrap())
		assert.False(t, ce.Timeout())
		require.NotErrorIs(t, err, bouncer.ErrTimeout)
		assert.Equal(t, "bouncer: verify: canceled", err.Error())
	})
	t.Run("caller deadline", func(t *testing.T) {
		t.Parallel()
		ctx, cancel := context.WithDeadline(t.Context(), time.Now().Add(-time.Second))
		defer cancel()
		c, _ := newScriptClient(t, jsonStep(verifyOK))
		_, err := c.Verify(ctx, bouncer.VerifyRequest{Email: testEmail})
		ce := requireCallError(t, err, wantCall{Kind: bouncer.FailureDeadlineExceeded, Op: bouncer.OpVerify})
		assert.True(t, ce.Timeout())
		require.ErrorIs(t, err, context.DeadlineExceeded)
		require.NotErrorIs(t, err, bouncer.ErrTimeout, "the caller's own deadline is not the SDK's timeout")
		assert.Equal(t, "bouncer: verify: deadline_exceeded", err.Error())
	})
	t.Run("network timeout", func(t *testing.T) {
		t.Parallel()
		c, _ := newScriptClient(t, testutil.Step{Err: testutil.TimeoutError{Msg: "i/o timeout " + testEmail}})
		_, err := c.Verify(t.Context(), bouncer.VerifyRequest{Email: testEmail})
		ce := requireCallError(t, err, wantCall{Kind: bouncer.FailureTimeout, Op: bouncer.OpVerify})
		assert.True(t, ce.Timeout())
		require.ErrorIs(t, err, bouncer.ErrTimeout)
		require.ErrorIs(t, err, context.DeadlineExceeded)
		assert.Equal(t, "bouncer: verify: timeout", err.Error())
		testutil.AssertRedacted(t, fmt.Sprintf("%+v %#v", err, err), markers())
		_, isURL := errors.AsType[*url.Error](err)
		assert.False(t, isURL)
	})
}

func TestCallErrorTimeout(t *testing.T) {
	t.Parallel()
	for _, kind := range errorsAllKinds() {
		ce := &bouncer.CallError{Kind: kind}
		want := kind == bouncer.FailureTimeout || kind == bouncer.FailureDeadlineExceeded
		assert.Equal(t, want, ce.Timeout(), "%s", kind)
	}
}

func TestCallErrorGoString(t *testing.T) {
	t.Parallel()
	ce := &bouncer.CallError{
		Kind: bouncer.FailureRateLimited, Op: bouncer.OpBatchStatus, StatusCode: 429, APIStatus: 429,
		BatchID: testBatchID, Field: "batchId", Records: 2, BytesWritten: 3, RetryAfter: 2 * time.Second,
		HasRetryAfter: true,
	}
	want := `&bouncer.CallError{Kind:"rate_limited", Op:"batch_status", StatusCode:429, APIStatus:429, ` +
		`BatchID:"5f0c2b9e8d7a6b5c4d3e2f1a", Field:"batchId", Records:2, BytesWritten:3, RetryAfter:2000000000, ` +
		`HasRetryAfter:true}`
	assert.Equal(t, want, ce.GoString())
	assert.Equal(t, want, fmt.Sprintf("%#v", ce), "%#v prints GoString")

	// An SDK error with a cause and diagnostics prints its exported fields only.
	c := envelopeDiagClient(t, true, statusStep(402, `{"status":"402","message":"m-`+testEmail+`"}`))
	_, err := c.Verify(t.Context(), bouncer.VerifyRequest{Email: testEmail})
	sdk := testutil.RequireErrorAs[*bouncer.CallError](t, err)
	require.Contains(t, sdk.Diagnostics().Message, testEmail, "the diagnostics hold the provider text")
	got := fmt.Sprintf("%#v", sdk)
	assert.Equal(t, sdk.GoString(), got)
	assert.NotContains(t, got, testEmail)
	assert.NotContains(t, got, "private")
	assert.NotContains(t, got, "payment required", "the cause is never printed")
	assert.NotContains(t, err.Error(), testEmail)
}

func TestCallErrorDiagnosticsOnFakes(t *testing.T) {
	t.Parallel()
	assert.Equal(t, bouncer.ProviderDiagnostics{}, (&bouncer.CallError{Kind: bouncer.FailureRejected}).Diagnostics())
}

// TestCallErrorJSONHoldsExportedFieldsOnly marshals an SDK error and checks
// that only the exported fields appear, never the cause or the diagnostics.
func TestCallErrorJSONHoldsExportedFieldsOnly(t *testing.T) {
	t.Parallel()
	c := envelopeDiagClient(t, true, testutil.Step{
		Status: 429, Header: http.Header{"Content-Type": {mediaJSON}, "Retry-After": {"9"}},
		Body: `{"status":429,"message":"slow down ` + testEmail + `"}`,
	})
	_, err := c.Verify(t.Context(), bouncer.VerifyRequest{Email: testEmail})
	ce := testutil.RequireErrorAs[*bouncer.CallError](t, err)
	require.NotEmpty(t, ce.Diagnostics().Message)
	data, jerr := json.Marshal(ce) //nolint:musttag // the exported Go field names are what is checked
	require.NoError(t, jerr)
	var fields map[string]any
	require.NoError(t, json.Unmarshal(data, &fields))
	assert.ElementsMatch(t, []string{
		"Kind", "Op", "StatusCode", "APIStatus", "BatchID", "Field", "Records", "BytesWritten", "RetryAfter",
		"HasRetryAfter",
	}, slices.Collect(maps.Keys(fields)))
	assert.Equal(t, "rate_limited", fields["Kind"])
	assert.InDelta(t, float64(9*time.Second), fields["RetryAfter"], 0)
	testutil.AssertRedacted(t, string(data), markers())
	assert.NotContains(t, string(data), "slow down")
}

func TestCallErrorWrapping(t *testing.T) {
	t.Parallel()
	c, _ := newScriptClient(t, statusStep(429, `{}`))
	_, err := c.Verify(t.Context(), bouncer.VerifyRequest{Email: testEmail})
	require.Error(t, err)
	for name, wrapped := range map[string]error{
		"errors.Join":  errors.Join(errUnrelated, err),
		"fmt.Errorf":   fmt.Errorf("signup: %w", err),
		"double":       fmt.Errorf("outer: %w", errors.Join(err, io.EOF)),
		"join of fake": errors.Join(&bouncer.CallError{Kind: bouncer.FailureRateLimited}),
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			require.ErrorIs(t, wrapped, bouncer.ErrRateLimited)
			require.NotErrorIs(t, wrapped, bouncer.ErrTimeout)
			ce := testutil.RequireErrorAs[*bouncer.CallError](t, wrapped)
			assert.Equal(t, bouncer.FailureRateLimited, ce.Kind)
		})
	}
}

func TestValidationErrorFormat(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		ve   *bouncer.ValidationError
		want string
	}{
		{
			"request",
			&bouncer.ValidationError{Err: bouncer.ErrInvalidRequest, Field: "Entries[17].Email", Reason: "invalid_utf8"},
			"bouncer: invalid request: Entries[17].Email: invalid_utf8",
		},
		{
			"config",
			&bouncer.ValidationError{Err: bouncer.ErrInvalidConfig, Field: "Timeout", Reason: "out_of_range"},
			"bouncer: invalid configuration: Timeout: out_of_range",
		},
		{
			"no field", &bouncer.ValidationError{Err: bouncer.ErrInvalidRequest, Reason: "required"},
			"bouncer: invalid request: required",
		},
		{
			"no reason", &bouncer.ValidationError{Err: bouncer.ErrInvalidRequest, Field: "ctx"},
			"bouncer: invalid request: ctx",
		},
		{
			"nil Err", &bouncer.ValidationError{Field: "Email", Reason: "required"},
			"bouncer: validation failed: Email: required",
		},
		{"empty", &bouncer.ValidationError{}, "bouncer: validation failed"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.want, tt.ve.Error())
			assert.Equal(t, tt.ve.Err, tt.ve.Unwrap())
		})
	}

	var nilVE *bouncer.ValidationError
	assert.Equal(t, "bouncer: <nil ValidationError>", nilVE.Error())
	assert.NoError(t, nilVE.Unwrap())
}

// TestValidationErrorsFromTheSDK checks a real validation error: it matches
// its sentinel and nothing a call could produce, and never quotes the value.
func TestValidationErrorsFromTheSDK(t *testing.T) {
	t.Parallel()
	_, err := bouncer.NewClient("")
	ve := requireValidation(t, err, bouncer.ErrInvalidConfig, "apiKey", reasonRequired)
	assert.Equal(t, "bouncer: invalid configuration: apiKey: required", ve.Error())

	_, err = bouncer.NewClient(testKey + " ")
	requireValidation(t, err, bouncer.ErrInvalidConfig, "apiKey", reasonInvalidFormat)
	assert.NotContains(t, err.Error(), testKey)

	c, _ := newScriptClient(t)
	_, err = c.Verify(t.Context(), bouncer.VerifyRequest{Email: testEmail + "\xff"})
	requireValidation(t, err, bouncer.ErrInvalidRequest, "Email", reasonInvalidUTF8)
	assert.NotContains(t, err.Error(), testEmail)
	require.NotErrorIs(t, err, bouncer.ErrInvalidConfig)
	_, isCall := errors.AsType[*bouncer.CallError](err)
	assert.False(t, isCall, "a validation error is never a CallError")
	for _, target := range errorsAllSentinels() {
		if !errors.Is(target, bouncer.ErrInvalidRequest) {
			assert.NotErrorIs(t, err, target)
		}
	}
}
