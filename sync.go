package bouncer

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
)

// BatchSyncRequest is one batch-sync call. It is read only while
// VerifyBatchSync validates and encodes it, before any I/O, and is never kept
// or modified.
type BatchSyncRequest struct {
	// Emails are the addresses to verify: 1 to MaxSyncEmails (10,000), each 1
	// to 1024 bytes of valid UTF-8, sent verbatim, in order, duplicates
	// included. The whole encoded body must be at most 8 MiB.
	Emails []string
}

// BatchSyncResult is the provider's answer to one batch-sync call: only the
// results it already had.
type BatchSyncResult struct {
	// Requested is len(BatchSyncRequest.Emails), as the SDK counted it.
	Requested int `json:"requested"`

	// Available holds the verifications the provider returned, in its order.
	// It may be shorter than Requested, even empty: the provider returns only
	// the results it already has, and verifies the rest in the background.
	// The SDK promises no correlation with the request: match rows by Email
	// yourself if you need to, knowing that it is the provider's echo.
	Available []Verification `json:"available,omitempty"`
}

// VerifyBatchSync submits up to 10,000 addresses and returns the results that
// are already available: POST
// https://api.usebouncer.com/v1.1/email/verify/batch/sync.
//
// PAID, and PARTIAL: the provider charges for the addresses it verifies, and
// answers with only the results it already has; the rest keep verifying in
// the background. It keeps results for about 24 hours: resubmitting the same
// addresses within that window returns those verified since, and
// resubmitting after it verifies and charges them again. The provider asks
// for calls to be sent one at a time, 5 seconds to 10 minutes apart (its
// older reference says 15 seconds); pacing is the caller's. The SDK makes
// exactly one attempt: it never polls, resubmits, works out which addresses
// are still missing, or falls back to Verify or a batch. When the provider
// returns more results than were requested, they are all kept.
//
// Errors are a *ValidationError (nothing sent) or a *CallError.
func (c *Client) VerifyBatchSync(ctx context.Context, req BatchSyncRequest) (*BatchSyncResult, error) {
	if err := c.prepare(ctx); err != nil {
		return nil, err
	}
	out, err := req.outgoing()
	if err != nil {
		return nil, err
	}
	rep, cerr := c.exchange(ctx, out)
	if cerr != nil {
		return nil, cerr
	}
	available, cerr := decodeVerifications(rep, OpBatchSync)
	if cerr != nil {
		return nil, cerr
	}
	return &BatchSyncResult{Requested: len(req.Emails), Available: available}, nil
}

// outgoing validates the request and describes its call, whose body is a JSON
// array of strings.
func (r *BatchSyncRequest) outgoing() (*outgoing, error) {
	switch {
	case len(r.Emails) == 0:
		return nil, invalidRequest("Emails", reasonRequired)
	case len(r.Emails) > MaxSyncEmails:
		return nil, invalidRequest("Emails", reasonTooMany)
	}
	for i, email := range r.Emails {
		if reason := emailProblem(email); reason != "" {
			return nil, invalidRequest(indexed("Emails", i, ""), reason)
		}
	}
	body, err := encodeJSON(r.Emails)
	if err != nil {
		return nil, invalidRequest("Emails", reasonInvalidValue)
	}
	if len(body) > maxSyncBodyBytes {
		return nil, invalidRequest("Emails", reasonTooLarge)
	}
	return &outgoing{op: OpBatchSync, method: http.MethodPost, path: pathSync, accept: mediaJSON, body: body}, nil
}

// decodeVerifications decodes a buffered answer that is a JSON array of
// verification records. An object instead of the array, which exchange has
// already found not to be an error envelope, is unexpected.
func decodeVerifications(rep *reply, op Operation) ([]Verification, *CallError) {
	sc := newArrayScanner(bytes.NewReader(rep.body))
	var out []Verification
	for {
		elem, err := sc.next()
		switch {
		case errors.Is(err, io.EOF):
			return out, nil
		case errors.Is(err, errObjectBody):
			return nil, newCallError(op, FailureUnexpectedResponse, rep.status, errWrongKind)
		case err != nil:
			// The reader is in memory, so every failure is a decodeError;
			// the fallback is defensive.
			if derr, ok := errors.AsType[*decodeError](err); ok {
				return nil, derr.callError(op, rep.status)
			}
			return nil, newCallError(op, FailureMalformedResponse, rep.status, errInvalidJSON)
		}
		v, derr := decodeVerification(elem, elemPath(int64(len(out))))
		if derr != nil {
			return nil, derr.callError(op, rep.status)
		}
		out = append(out, v)
	}
}
