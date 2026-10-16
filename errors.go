package bouncer

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// Sentinel errors. Match them with errors.Is.
//
// ErrInvalidConfig and ErrInvalidRequest are local: an error matching either
// means no request was sent. Every other sentinel describes a call that was
// attempted, or a Wait that stopped short; after an attempted call the
// provider may already have processed it, billed it or created a batch.
var (
	// ErrInvalidConfig reports an invalid NewClient argument or option, or a
	// Client or BatchService that was not created by NewClient. No request was
	// sent.
	ErrInvalidConfig = errors.New("bouncer: invalid configuration")

	// ErrInvalidRequest reports a request that fails local validation, a nil
	// context or a nil writer. No request was sent.
	ErrInvalidRequest = errors.New("bouncer: invalid request")

	// ErrUnauthorized reports HTTP 401: the API key was refused.
	ErrUnauthorized = errors.New("bouncer: unauthorized")

	// ErrPaymentRequired reports HTTP 402: the account has no credits left for
	// the call.
	ErrPaymentRequired = errors.New("bouncer: payment required")

	// ErrForbidden reports HTTP 403. The provider does not document what it
	// means.
	ErrForbidden = errors.New("bouncer: forbidden")

	// ErrNotFound reports HTTP 404, such as a batch ID the provider does not
	// know.
	ErrNotFound = errors.New("bouncer: not found")

	// ErrBatchState reports HTTP 405 on a call that names a batch: the batch is
	// not completed yet, its results were removed, or it cannot be deleted in
	// its current state.
	ErrBatchState = errors.New("bouncer: batch state does not allow the call")

	// ErrRateLimited reports HTTP 429. The SDK never retries; CallError's
	// RetryAfter carries the standard Retry-After header when one was sent.
	ErrRateLimited = errors.New("bouncer: rate limited")

	// ErrRejected reports HTTP 400 or another 4xx status this package does not
	// name, or HTTP 405 on a call that names no batch.
	ErrRejected = errors.New("bouncer: rejected by provider")

	// ErrUnavailable reports HTTP 503. The provider suggests retrying later;
	// the SDK never does.
	ErrUnavailable = errors.New("bouncer: temporarily unavailable")

	// ErrUpstream reports an HTTP 5xx status other than 503.
	ErrUpstream = errors.New("bouncer: provider server error")

	// ErrUnexpectedResponse reports a response this SDK cannot interpret: an
	// HTTP status outside the call's accepted set (a redirect, which is never
	// followed, included), an undecoded Content-Encoding, a content type that
	// does not match the call, a JSON object (other than an error envelope)
	// where an array or a file was expected, a batch other than the one
	// requested. The provider may already have processed the request.
	ErrUnexpectedResponse = errors.New("bouncer: unexpected response")

	// ErrMalformedResponse reports a success body that is not valid UTF-8 or
	// valid JSON (a \u escape of a lone UTF-16 surrogate included), is
	// truncated or has data after the top-level value, is another kind of JSON
	// value than documented (an array or a scalar where an object was
	// expected), lacks a required field, or holds a field of the wrong JSON
	// type. The provider may already have processed the request.
	ErrMalformedResponse = errors.New("bouncer: malformed response")

	// ErrResponseTooLarge reports a response larger than a configured limit
	// (WithMaxResponseBytes, WithMaxDownloadBytes), than the fixed 1 MiB cap on
	// every buffered call except VerifyBatchSync, or than an SDK bound: 4 KiB
	// for a Finish or Delete acknowledgement, 64 KiB per verification record
	// or 4 KiB per text field. The provider may already have processed the
	// request.
	ErrResponseTooLarge = errors.New("bouncer: response too large")

	// ErrTransport reports a failure in transit, such as DNS, connection, TLS
	// or proxy errors, a reset, a truncated body, or a stalled body (100 reads
	// in a row that return nothing). The request may or may not have reached
	// the provider.
	ErrTransport = errors.New("bouncer: transport failure")

	// ErrTimeout reports that the SDK's own deadline (WithTimeout,
	// WithDownloadTimeout) or an injected http.Client's Timeout expired, or
	// that the network reported a timeout. It also matches
	// context.DeadlineExceeded, so check it first to tell it apart from the
	// caller's own deadline. The provider may already have processed the
	// request.
	ErrTimeout = errors.New("bouncer: timeout")

	// ErrWriteFailed reports that Download's writer returned an error or wrote
	// fewer bytes than it was given. The writer's own error is not kept: wrap
	// the writer to capture it.
	ErrWriteFailed = errors.New("bouncer: download write failed")

	// ErrUnknownBatchState reports that Wait observed a batch state this
	// package does not document. Wait surfaces it rather than polling through
	// it.
	ErrUnknownBatchState = errors.New("bouncer: unknown batch state")

	// ErrBudgetExhausted reports that Wait used up its MaxWait before the
	// batch completed.
	ErrBudgetExhausted = errors.New("bouncer: budget exhausted")
)

// Static causes kept inside a CallError. They replace standard-library
// errors, whose messages can quote URLs, header bytes or response content.
var (
	errBuildRequest     = errors.New("bouncer: cannot build the HTTP request")
	errStatus           = errors.New("bouncer: unexpected HTTP status")
	errResponseTooLarge = errors.New("bouncer: response body exceeds the size limit")
	errContentEncoding  = errors.New("bouncer: response has an undecoded content encoding")
	errContentType      = errors.New("bouncer: response content type does not match the call")
	errInvalidUTF8      = errors.New("bouncer: response is not valid UTF-8")
	errInvalidJSON      = errors.New("bouncer: response is not valid JSON")
	errTruncated        = errors.New("bouncer: response ends before its JSON value does")
	errTrailingData     = errors.New("bouncer: response has data after the top-level value")
	errWrongKind        = errors.New("bouncer: response is not the documented kind of JSON value")
	errMissingField     = errors.New("bouncer: response lacks a required field")
	errWrongType        = errors.New("bouncer: response field has the wrong JSON type")
	errFieldTooLarge    = errors.New("bouncer: response field exceeds its size bound")
	errInvalidBatchID   = errors.New("bouncer: response batchId is not a valid batch ID")
	errEnvelope         = errors.New("bouncer: response is an error envelope")
	errIDMismatch       = errors.New("bouncer: response is for another batch")
	errWriter           = errors.New("bouncer: download writer failed or wrote short")
	errUnknownState     = errors.New("bouncer: batch status is undocumented")
	errWaitBudget       = errors.New("bouncer: MaxWait used up before the batch completed")

	// Transport classes. The original error is discarded, because standard
	// library errors can quote URLs, proxy credentials or server bytes.
	errTransportDNS     = errors.New("bouncer: transport: DNS lookup failed")
	errTransportProxy   = errors.New("bouncer: transport: proxy connection failed")
	errTransportDial    = errors.New("bouncer: transport: connection failed")
	errTransportTLS     = errors.New("bouncer: transport: TLS failed")
	errTransportReset   = errors.New("bouncer: transport: connection reset")
	errTransportClosed  = errors.New("bouncer: transport: connection closed early")
	errTransportStalled = errors.New("bouncer: transport: body read made no progress")
	errTransportOther   = errors.New("bouncer: transport: request failed")
)

// FailureKind classifies a failed call. Each kind matches one target with
// errors.Is (a sentinel of this package, context.Canceled or
// context.DeadlineExceeded), except FailureTimeout, which matches both
// ErrTimeout and context.DeadlineExceeded. The values are short, fixed and
// free of personal data, so they are safe to use as metric labels.
type FailureKind string

// Failure kinds.
const (
	// FailureUnauthorized matches ErrUnauthorized.
	FailureUnauthorized FailureKind = "unauthorized"

	// FailurePaymentRequired matches ErrPaymentRequired.
	FailurePaymentRequired FailureKind = "payment_required"

	// FailureForbidden matches ErrForbidden.
	FailureForbidden FailureKind = "forbidden"

	// FailureNotFound matches ErrNotFound.
	FailureNotFound FailureKind = "not_found"

	// FailureBatchState matches ErrBatchState.
	FailureBatchState FailureKind = "batch_state"

	// FailureRateLimited matches ErrRateLimited.
	FailureRateLimited FailureKind = "rate_limited"

	// FailureRejected matches ErrRejected.
	FailureRejected FailureKind = "rejected"

	// FailureUnavailable matches ErrUnavailable.
	FailureUnavailable FailureKind = "unavailable"

	// FailureUpstream matches ErrUpstream.
	FailureUpstream FailureKind = "upstream"

	// FailureUnexpectedResponse matches ErrUnexpectedResponse.
	FailureUnexpectedResponse FailureKind = "unexpected_response"

	// FailureMalformedResponse matches ErrMalformedResponse.
	FailureMalformedResponse FailureKind = "malformed_response"

	// FailureResponseTooLarge matches ErrResponseTooLarge.
	FailureResponseTooLarge FailureKind = "response_too_large"

	// FailureTransport matches ErrTransport.
	FailureTransport FailureKind = "transport"

	// FailureTimeout matches ErrTimeout, and also context.DeadlineExceeded.
	FailureTimeout FailureKind = "timeout"

	// FailureCanceled means the caller's context was canceled. It matches
	// context.Canceled.
	FailureCanceled FailureKind = "canceled"

	// FailureDeadlineExceeded means the caller's context deadline expired. It
	// matches context.DeadlineExceeded, but not ErrTimeout.
	FailureDeadlineExceeded FailureKind = "deadline_exceeded"

	// FailureWriteFailed matches ErrWriteFailed.
	FailureWriteFailed FailureKind = "write_failed"

	// FailureUnknownBatchState matches ErrUnknownBatchState.
	FailureUnknownBatchState FailureKind = "unknown_batch_state"

	// FailureBudgetExhausted matches ErrBudgetExhausted.
	FailureBudgetExhausted FailureKind = "budget_exhausted"
)

// Operation names the call a CallError concerns.
type Operation string

// Operations.
const (
	// OpVerify is GET /v1.1/email/verify (Verify).
	OpVerify Operation = "verify"

	// OpBatchSync is POST /v1.1/email/verify/batch/sync (VerifyBatchSync).
	OpBatchSync Operation = "batch_sync"

	// OpCredits is GET /v1.1/credits (Credits).
	OpCredits Operation = "credits"

	// OpBatchCreate is POST /v1.1/email/verify/batch (BatchService.Create).
	OpBatchCreate Operation = "batch_create"

	// OpBatchStatus is GET /v1.1/email/verify/batch/{batchId}
	// (BatchService.Status and BatchService.Wait).
	OpBatchStatus Operation = "batch_status"

	// OpBatchResults is GET /v1.1/email/verify/batch/{batchId}/download as
	// JSON (BatchService.Results).
	OpBatchResults Operation = "batch_results"

	// OpBatchDownload is GET /v1.1/email/verify/batch/{batchId}/download
	// (BatchService.Download).
	OpBatchDownload Operation = "batch_download"

	// OpBatchFinish is POST /v1.1/email/verify/batch/{batchId}/finish
	// (BatchService.Finish).
	OpBatchFinish Operation = "batch_finish"

	// OpBatchDelete is DELETE /v1.1/email/verify/batch/{batchId}
	// (BatchService.Delete).
	OpBatchDelete Operation = "batch_delete"
)

// ValidationError describes a local validation failure: nothing was sent. Err
// is ErrInvalidConfig or ErrInvalidRequest. Field names the argument, option or
// request field as a Go path, such as "Entries[17].Email" or "Timeout", and
// Reason is a short fixed code, such as "invalid_utf8". Neither ever contains
// the rejected value.
type ValidationError struct {
	Err    error
	Field  string
	Reason string
}

// Error returns the sentinel's message followed by the field and the reason,
// such as "bouncer: invalid request: Entries[17].Email: invalid_utf8".
func (e *ValidationError) Error() string {
	if e == nil {
		return "bouncer: <nil ValidationError>"
	}
	var b strings.Builder
	if e.Err != nil {
		b.WriteString(e.Err.Error())
	} else {
		b.WriteString("bouncer: validation failed")
	}
	for _, part := range [...]string{e.Field, e.Reason} {
		if part != "" {
			b.WriteString(": ")
			b.WriteString(part)
		}
	}
	return b.String()
}

// Unwrap returns the sentinel, ErrInvalidConfig or ErrInvalidRequest.
func (e *ValidationError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Err
}

// CallError describes a call that was attempted, a call that a canceled or
// expired context stopped before it was sent, or a Wait that stopped short.
//
// Its Error text is built only from Op, Kind, StatusCode, APIStatus, Field and
// a fixed transport class: it never holds the API key, email addresses, names,
// URLs, header values, response bodies or provider messages, so it is safe to
// log. GoString and every fmt verb add only the other exported fields. The
// cause and the provider diagnostics sit behind a function value that fmt and
// reflection-based dumpers print only as an address.
//
// Tests and fakes may build a CallError from its exported fields alone; it
// then matches errors.Is like one the SDK returns.
type CallError struct {
	// Kind classifies the failure.
	Kind FailureKind

	// Op is the call concerned.
	Op Operation

	// StatusCode is the HTTP status, or 0 when no response was received (and
	// for the Wait kinds unknown_batch_state and budget_exhausted).
	StatusCode int

	// APIStatus is the "status" of the provider's error envelope, sent as a
	// JSON number or a string of three digits, when it is from 100 to 599, and
	// 0 otherwise. It may disagree with StatusCode: StatusCode decides the
	// kind of a non-2xx response, and APIStatus that of an envelope inside a
	// 2xx.
	APIStatus int

	// BatchID is the batch concerned when it is known: the requested batch on
	// every batch call, and on BatchService.Create the batchId of a reply that
	// carried a valid one but was otherwise unusable. The batch then exists
	// and is processing: save the ID rather than create it again.
	BatchID BatchID

	// Field is a JSON path, such as "[17].score", for decode and size
	// failures. It names a location, never a value.
	Field string

	// Records is the number of records BatchService.Results yielded before
	// failing. It is 0 for every other call.
	Records int64

	// BytesWritten is the number of bytes BatchService.Download wrote to its
	// writer before failing, the count it returns. It is 0 for every other
	// call.
	BytesWritten int64

	// RetryAfter is the standard Retry-After header of an HTTP 429 or 503,
	// clamped to 0 through 24 hours, when HasRetryAfter is true. It is data
	// only: the SDK never waits or retries.
	RetryAfter time.Duration

	// HasRetryAfter reports whether RetryAfter was read from the response.
	HasRetryAfter bool

	// private holds the sanitized cause and the provider diagnostics.
	private func() callDetail
}

// callDetail is the part of a CallError that is never printed.
type callDetail struct {
	cause       error
	class       string
	diagnostics ProviderDiagnostics
}

// ProviderDiagnostics holds provider text about a failed call. It is empty
// unless the Client was created with WithProviderDiagnostics.
type ProviderDiagnostics struct {
	// Message is the error envelope's "message", cut to at most 1 KiB on a
	// UTF-8 boundary, with every occurrence of the API key replaced by
	// "[redacted]". It may echo request data, such as an email address.
	Message string
}

// newCallError returns a CallError without diagnostics whose cause is
// reachable only through Unwrap.
func newCallError(op Operation, kind FailureKind, status int, cause error) *CallError {
	return newCallErrorWithDiagnostics(op, kind, status, cause, ProviderDiagnostics{})
}

// newCallErrorWithDiagnostics returns a CallError whose cause and diagnostics
// are reachable only through Unwrap and Diagnostics.
func newCallErrorWithDiagnostics(op Operation, kind FailureKind, status int, cause error,
	diag ProviderDiagnostics,
) *CallError {
	d := callDetail{cause: cause, class: transportClassName(cause), diagnostics: diag}
	return &CallError{Kind: kind, Op: op, StatusCode: status, private: func() callDetail { return d }}
}

// Error returns "bouncer: <op>: <kind>", followed by " (HTTP <status>, API
// <api status>)" with whichever of the two is known, and ": <field>" when a
// field is named, or ": <class>" for a transport failure, such as
// "bouncer: batch_finish: rejected (HTTP 200, API 400)" or
// "bouncer: verify: transport: dns".
func (e *CallError) Error() string {
	if e == nil {
		return "bouncer: <nil CallError>"
	}
	var b strings.Builder
	b.WriteString("bouncer: ")
	if e.Op != "" {
		b.WriteString(string(e.Op))
		b.WriteString(": ")
	}
	if e.Kind != "" {
		b.WriteString(string(e.Kind))
	} else {
		b.WriteString("call_failed")
	}
	var meta []string
	if e.StatusCode != 0 {
		meta = append(meta, "HTTP "+strconv.Itoa(e.StatusCode))
	}
	if e.APIStatus != 0 {
		meta = append(meta, "API "+strconv.Itoa(e.APIStatus))
	}
	if len(meta) > 0 {
		b.WriteString(" (")
		b.WriteString(strings.Join(meta, ", "))
		b.WriteString(")")
	}
	switch {
	case e.Field != "":
		b.WriteString(": ")
		b.WriteString(e.Field)
	case e.detail().class != "":
		b.WriteString(": ")
		b.WriteString(e.detail().class)
	}
	return b.String()
}

// Unwrap returns the sanitized cause: a context error or a fixed error of this
// package. It is never a *url.Error, a net error, a JSON decoding error, the
// writer's error or anything else that could quote a URL, a header or
// response content. It is nil for a CallError built from its exported fields.
func (e *CallError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.detail().cause
}

// Is reports whether target is the sentinel for e.Kind. A timeout also matches
// context.DeadlineExceeded, a caller deadline matches context.DeadlineExceeded
// and a cancellation matches context.Canceled.
func (e *CallError) Is(target error) bool {
	if e == nil {
		return false
	}
	if target == context.Canceled {
		return e.Kind == FailureCanceled
	}
	if target == context.DeadlineExceeded {
		return e.Kind == FailureDeadlineExceeded || e.Kind == FailureTimeout
	}
	sentinel := kindSentinel(e.Kind)
	return sentinel != nil && target == sentinel
}

// Timeout reports whether the call ran out of time: the SDK's deadline, an
// injected client's Timeout or a network timeout (FailureTimeout), or the
// caller's own deadline (FailureDeadlineExceeded).
func (e *CallError) Timeout() bool {
	return e != nil && (e.Kind == FailureTimeout || e.Kind == FailureDeadlineExceeded)
}

// GoString prints the exported fields only, so that %#v cannot reach the cause
// or the provider diagnostics.
func (e *CallError) GoString() string {
	if e == nil {
		return "(*bouncer.CallError)(nil)"
	}
	return fmt.Sprintf("&bouncer.CallError{Kind:%q, Op:%q, StatusCode:%d, APIStatus:%d, BatchID:%q, "+
		"Field:%q, Records:%d, BytesWritten:%d, RetryAfter:%d, HasRetryAfter:%t}",
		string(e.Kind), string(e.Op), e.StatusCode, e.APIStatus, string(e.BatchID),
		e.Field, e.Records, e.BytesWritten, int64(e.RetryAfter), e.HasRetryAfter)
}

// Diagnostics returns the provider's message for this failure. It is empty
// unless the Client was created with WithProviderDiagnostics. Provider text
// may echo request data, such as an email address: inspect it, but think
// before logging or storing it.
func (e *CallError) Diagnostics() ProviderDiagnostics {
	if e == nil {
		return ProviderDiagnostics{}
	}
	return e.detail().diagnostics
}

// forBatch sets the batch e concerns and returns e.
func (e *CallError) forBatch(id BatchID) *CallError {
	e.BatchID = id
	return e
}

func (e *CallError) detail() callDetail {
	if e.private == nil {
		return callDetail{}
	}
	return e.private()
}

// kindSentinel returns the sentinel a kind matches, or nil for the context
// kinds and any kind this package does not define.
func kindSentinel(kind FailureKind) error {
	switch kind {
	case FailureUnauthorized:
		return ErrUnauthorized
	case FailurePaymentRequired:
		return ErrPaymentRequired
	case FailureForbidden:
		return ErrForbidden
	case FailureNotFound:
		return ErrNotFound
	case FailureBatchState:
		return ErrBatchState
	case FailureRateLimited:
		return ErrRateLimited
	case FailureRejected:
		return ErrRejected
	case FailureUnavailable:
		return ErrUnavailable
	case FailureUpstream:
		return ErrUpstream
	case FailureUnexpectedResponse:
		return ErrUnexpectedResponse
	case FailureMalformedResponse:
		return ErrMalformedResponse
	case FailureResponseTooLarge:
		return ErrResponseTooLarge
	case FailureTransport:
		return ErrTransport
	case FailureTimeout:
		return ErrTimeout
	case FailureWriteFailed:
		return ErrWriteFailed
	case FailureUnknownBatchState:
		return ErrUnknownBatchState
	case FailureBudgetExhausted:
		return ErrBudgetExhausted
	case FailureCanceled, FailureDeadlineExceeded:
		return nil
	}
	return nil
}

// transportClassName returns the fixed token Error() appends for a transport
// cause, and "" for any other cause.
func transportClassName(cause error) string {
	switch {
	case errors.Is(cause, errTransportDNS):
		return "dns"
	case errors.Is(cause, errTransportProxy):
		return "proxy"
	case errors.Is(cause, errTransportTLS):
		return "tls"
	case errors.Is(cause, errTransportReset):
		return "reset"
	case errors.Is(cause, errTransportDial):
		return "dial"
	case errors.Is(cause, errTransportClosed):
		return "closed"
	case errors.Is(cause, errTransportStalled):
		return "stalled"
	case errors.Is(cause, errTransportOther):
		return "other"
	}
	return ""
}

// contextFailure returns the CallError for a caller context that is done, with
// the context's error as its cause.
func contextFailure(op Operation, err error, status int) *CallError {
	if errors.Is(err, context.DeadlineExceeded) {
		return newCallError(op, FailureDeadlineExceeded, status, context.DeadlineExceeded)
	}
	return newCallError(op, FailureCanceled, status, context.Canceled)
}

// Validation reasons, reported in ValidationError.Reason.
const (
	reasonRequired             = "required"
	reasonNil                  = "nil"
	reasonNotInitialized       = "not_initialized"
	reasonOutOfRange           = "out_of_range"
	reasonInvalidFormat        = "invalid_format"
	reasonInvalidURL           = "invalid_url"
	reasonInvalidUTF8          = "invalid_utf8"
	reasonInvalidValue         = "invalid_value"
	reasonTooLong              = "too_long"
	reasonTooMany              = "too_many"
	reasonTooLarge             = "too_large"
	reasonNotWholeSeconds      = "not_whole_seconds"
	reasonExceedsClientTimeout = "exceeds_client_timeout"
	reasonUnsupportedScheme    = "unsupported_scheme"
)

// invalidConfig returns a *ValidationError matching ErrInvalidConfig.
func invalidConfig(field, reason string) error {
	return &ValidationError{Err: ErrInvalidConfig, Field: field, Reason: reason}
}

// invalidRequest returns a *ValidationError matching ErrInvalidRequest.
func invalidRequest(field, reason string) error {
	return &ValidationError{Err: ErrInvalidRequest, Field: field, Reason: reason}
}
