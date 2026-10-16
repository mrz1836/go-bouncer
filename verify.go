package bouncer

import (
	"context"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// VerifyRequest is one real-time verification. It is read only while Verify
// validates it, before any I/O, and is never kept or modified.
type VerifyRequest struct {
	// Email is the address to verify, sent verbatim: never trimmed, lowercased
	// or checked against an RFC. It must be 1 to 1024 bytes of valid UTF-8. A
	// malformed address is a legitimate input: the provider answers it like any
	// other, and its documentation does not promise that rejected input is
	// free.
	Email string

	// Timeout is the provider's verification budget, sent as "timeout" in whole
	// seconds. 0 means not sent: the provider's default of 10 seconds. When it
	// runs out the provider answers with what it has, which may be
	// StatusUnknown. It must be whole seconds from 1s to MaxVerifyTimeout
	// (30s), and at least 10 seconds shorter than the Client's WithTimeout, so
	// that the SDK does not give up on a check the provider will still bill.
	Timeout time.Duration
}

// Verify checks one address in real time: GET
// https://api.usebouncer.com/v1.1/email/verify.
//
// PAID: the provider may bill every call, although it is a GET. It makes
// exactly one attempt and never retries. After a timeout, cancellation,
// transport failure or unreadable response the check may already be billed:
// do not resend it blindly. StatusUnknown is a successful answer, never an
// error.
//
// The address necessarily travels in the URL query, where the provider, its
// CDN and access logs (and any TLS-terminating middleware an injected client
// adds) can see it. The SDK never puts URLs in errors.
//
// Errors are a *ValidationError (nothing sent) or a *CallError.
func (c *Client) Verify(ctx context.Context, req VerifyRequest) (*Verification, error) {
	if err := c.prepare(ctx); err != nil {
		return nil, err
	}
	out, err := req.outgoing(c.timeout)
	if err != nil {
		return nil, err
	}
	rep, cerr := c.exchange(ctx, out)
	if cerr != nil {
		return nil, cerr
	}
	v, derr := decodeVerification(rep.body, "")
	if derr != nil {
		return nil, derr.callError(OpVerify, rep.status)
	}
	return &v, nil
}

// outgoing validates the request and describes its call:
// /email/verify?email=…[&timeout=N].
func (r *VerifyRequest) outgoing(clientTimeout time.Duration) (*outgoing, error) {
	if err := checkEmail("Email", r.Email); err != nil {
		return nil, err
	}
	if err := checkVerifyTimeout(r.Timeout, clientTimeout); err != nil {
		return nil, err
	}
	var q strings.Builder
	q.Grow(len(r.Email)*3 + 20)
	queryParam(&q, "email", r.Email)
	if r.Timeout != 0 {
		queryParam(&q, "timeout", strconv.FormatInt(int64(r.Timeout/time.Second), 10))
	}
	return &outgoing{op: OpVerify, method: http.MethodGet, path: pathVerify, query: q.String(), accept: mediaJSON}, nil
}
