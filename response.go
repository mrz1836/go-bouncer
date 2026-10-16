package bouncer

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

// Response bounds.
const (
	// maxErrorBodyBytes bounds the excerpt read from a response whose status
	// is an error, which only feeds APIStatus and the opt-in diagnostics, and
	// the body of a Finish or Delete acknowledgement.
	maxErrorBodyBytes = 4 << 10

	// maxPrealloc bounds the buffer sized from a declared length before any
	// byte arrives, so that a response that declares a large body and then
	// stalls cannot pin that much memory until the timeout.
	maxPrealloc = 1 << 20

	// maxEmptyReads is how many reads in a row may return nothing before a
	// body counts as stalled.
	maxEmptyReads = 100

	// maxDiagnosticMessageBytes bounds ProviderDiagnostics.Message.
	maxDiagnosticMessageBytes = 1 << 10

	// maxRetryAfter bounds CallError.RetryAfter.
	maxRetryAfter = 24 * time.Hour
)

// reply is an accepted buffered response: a success status and its whole body,
// within the call's size limit, already checked not to be an error envelope.
type reply struct {
	status int
	body   []byte
}

// exchange makes the one attempt of a buffered call and reads its response,
// all within the Client's timeout. Every failure is a *CallError, in this
// order: the caller's context (one already done sends nothing),
// the SDK's timeout and transport failures; then the status (see
// checkResponse); then the content type; then the size limit; then an error
// envelope inside the success status.
//
// A failed Create may still return a reply: the body of a 2xx answer that
// was otherwise unusable, read only so that Create can report the batchId it
// may carry. Every other failure returns a nil reply.
func (c *Client) exchange(ctx context.Context, out *outgoing) (*reply, *CallError) {
	callCtx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	resp, body, cerr := open(ctx, callCtx, c.send, out) //nolint:bodyclose // closed exactly once by release
	if cerr != nil {
		return nil, cerr
	}
	defer body.release()
	// A Finish or Delete acknowledgement may be empty with any content type;
	// one with content must be JSON like every other answer.
	failure := c.checkResponse(out.op, resp)
	jsonType := hasJSONType(resp.Header)
	if failure == nil && !jsonType && !isAck(out.op) {
		failure = newCallError(out.op, FailureUnexpectedResponse, resp.StatusCode, errContentType)
	}
	if failure != nil && !keepsUnusableBody(out.op, resp) {
		return nil, failure
	}
	data, cerr := readAll(ctx, callCtx, out.op, resp, c.responseLimit(out.op))
	switch {
	case failure != nil && cerr != nil:
		return nil, failure
	case failure != nil:
		return &reply{status: resp.StatusCode, body: data}, failure
	case cerr != nil:
		return nil, cerr
	case !jsonType && !blank(data):
		return nil, newCallError(out.op, FailureUnexpectedResponse, resp.StatusCode, errContentType)
	}
	rep := &reply{status: resp.StatusCode, body: data}
	if env, ok := readEnvelope(data); ok && env.failed() {
		return rep, c.envelopeFailure(out.op, resp.StatusCode, env)
	}
	return rep, nil
}

// keepsUnusableBody reports whether a failed answer is still read: a Create
// answer with a 2xx status and no undecoded encoding, whose body may carry
// the batchId of a batch the provider created.
func keepsUnusableBody(op Operation, resp *http.Response) bool {
	return op == OpBatchCreate && resp.StatusCode >= http.StatusOK && resp.StatusCode < http.StatusMultipleChoices &&
		!encoded(resp.Header)
}

// openBody is a response body that is closed exactly once: when the call's
// context ends, so that a read that does not watch the context still stops,
// when another deadline the caller sets ends, or when release runs.
type openBody struct {
	body io.Closer
	once sync.Once
	stop func() bool
}

// close closes the body, the first time only. A close error after a complete
// read changes nothing.
func (b *openBody) close() { b.once.Do(func() { _ = b.body.Close() }) }

// release stops watching the call's context and closes the body. The caller
// must run it before returning.
func (b *openBody) release() {
	b.stop()
	b.close()
}

// open makes the one attempt of a call within callCtx and returns the
// response with its body guard. When the caller's ctx is already done, it
// sends nothing.
func open(ctx, callCtx context.Context, send sender, out *outgoing) (*http.Response, *openBody, *CallError) {
	if err := ctx.Err(); err != nil {
		return nil, nil, contextFailure(out.op, err, 0)
	}
	resp, err := send(callCtx, out)
	if err != nil {
		return nil, nil, classify(ctx, callCtx, out.op, err, 0)
	}
	b := &openBody{body: resp.Body}
	b.stop = context.AfterFunc(callCtx, b.close)
	return resp, b, nil
}

// checkResponse classifies a response by its status and headers, before its
// body is read as a success: a 1xx or a 3xx (whose Location the redirect guard
// removed) is unexpected and never read; a 4xx or 5xx fails by its status
// alone (see statusFailure); a 2xx outside the call's accepted set is
// unexpected; and so is a Content-Encoding that nobody decoded on a body that
// is not empty.
func (c *Client) checkResponse(op Operation, resp *http.Response) *CallError {
	status := resp.StatusCode
	switch {
	case status < http.StatusOK || (status >= http.StatusMultipleChoices && status < http.StatusBadRequest):
		// A 1xx that reaches here, such as 101 Switching Protocols, has the
		// raw connection as its body, which no deadline watches: never read it.
		return newCallError(op, FailureUnexpectedResponse, status, errStatus)
	case status >= http.StatusBadRequest:
		return c.statusFailure(op, resp)
	case !accepted(op, status):
		return newCallError(op, FailureUnexpectedResponse, status, errStatus)
	case resp.ContentLength != 0 && encoded(resp.Header):
		// An empty body (a 204 included) has nothing to decode: the transport
		// leaves its Content-Encoding in place.
		return newCallError(op, FailureUnexpectedResponse, status, errContentEncoding)
	}
	return nil
}

// statusFailure returns the CallError for an HTTP status of 400 or more. The
// status alone decides the kind. A bounded excerpt of the body is parsed
// best-effort for the envelope status and, when enabled, the provider's
// message: a body that cannot be parsed never changes the kind. A 429 or 503
// also reports its Retry-After header.
func (c *Client) statusFailure(op Operation, resp *http.Response) *CallError {
	status := resp.StatusCode
	env, _ := readEnvelope(excerpt(resp.Body, resp.ContentLength))
	ce := newCallErrorWithDiagnostics(op, statusKind(status, op), status, errStatus, c.diagnosticsFrom(env.message))
	ce.APIStatus = env.status
	if status == http.StatusTooManyRequests || status == http.StatusServiceUnavailable {
		ce.RetryAfter, ce.HasRetryAfter = retryAfter(resp.Header, time.Now())
	}
	return ce
}

// envelopeFailure returns the CallError for an error envelope in a 2xx body:
// the envelope's status decides the kind, while StatusCode stays the real
// status.
func (c *Client) envelopeFailure(op Operation, status int, env envelope) *CallError {
	ce := newCallErrorWithDiagnostics(op, statusKind(env.status, op), status, errEnvelope, c.diagnosticsFrom(env.message))
	ce.APIStatus = env.status
	return ce
}

// statusKind classifies an HTTP status, or an envelope status, of 400 or more.
// HTTP 405 means a batch state on a call that names a batch, and a refused
// request on any other. Anything below 400 is unexpected here.
func statusKind(code int, op Operation) FailureKind {
	switch {
	case code == http.StatusUnauthorized:
		return FailureUnauthorized
	case code == http.StatusPaymentRequired:
		return FailurePaymentRequired
	case code == http.StatusForbidden:
		return FailureForbidden
	case code == http.StatusNotFound:
		return FailureNotFound
	case code == http.StatusMethodNotAllowed && namesBatch(op):
		return FailureBatchState
	case code == http.StatusTooManyRequests:
		return FailureRateLimited
	case code == http.StatusServiceUnavailable:
		return FailureUnavailable
	case code >= 400 && code < 500:
		return FailureRejected
	case code >= 500 && code < 600:
		return FailureUpstream
	}
	return FailureUnexpectedResponse
}

// namesBatch reports whether op is a call on an existing batch.
func namesBatch(op Operation) bool {
	switch op {
	case OpBatchStatus, OpBatchResults, OpBatchDownload, OpBatchFinish, OpBatchDelete:
		return true
	case OpVerify, OpBatchSync, OpCredits, OpBatchCreate:
	}
	return false
}

// isAck reports whether op answers with an acknowledgement rather than data.
func isAck(op Operation) bool { return op == OpBatchFinish || op == OpBatchDelete }

// accepted reports whether a 2xx status is a success for op: 200, 201 or 202
// for Create; 200, 202 or 204 for Finish and Delete; 200 for every other call.
func accepted(op Operation, status int) bool {
	switch op {
	case OpBatchCreate:
		return status == http.StatusOK || status == http.StatusCreated || status == http.StatusAccepted
	case OpBatchFinish, OpBatchDelete:
		return status == http.StatusOK || status == http.StatusAccepted || status == http.StatusNoContent
	case OpVerify, OpBatchSync, OpCredits, OpBatchStatus, OpBatchResults, OpBatchDownload:
	}
	return status == http.StatusOK
}

// readAll reads a whole response body within limit bytes: a declared length
// over the limit fails before any read, and a body that ends short of its
// declared length is truncated.
func readAll(ctx, callCtx context.Context, op Operation, resp *http.Response, limit int64) ([]byte, *CallError) {
	if resp.ContentLength > limit {
		return nil, newCallError(op, FailureResponseTooLarge, resp.StatusCode, errResponseTooLarge)
	}
	data, err := readBody(resp.Body, resp.ContentLength, limit)
	switch {
	case err != nil:
		return nil, classify(ctx, callCtx, op, err, resp.StatusCode)
	case truncated(int64(len(data)), resp.ContentLength):
		// The standard transport reports a short body as io.ErrUnexpectedEOF;
		// an injected one might end it cleanly instead. Either way it is
		// incomplete.
		return nil, newCallError(op, FailureTransport, resp.StatusCode, errTransportClosed)
	}
	return data, nil
}

// readBody reads r to EOF, but never more than limit bytes: one more fails
// with errResponseTooLarge. A declared length, already known to be within the
// limit, sizes the buffer exactly when it is small, with one spare byte to see
// EOF without growing. A body of unknown or large declared length is read by
// io.ReadAll, which grows as bytes arrive.
func readBody(r io.Reader, contentLength, limit int64) ([]byte, error) {
	capped := &capReader{r: &progressReader{r: r}, limit: limit}
	if contentLength < 0 || contentLength > maxPrealloc {
		return io.ReadAll(capped)
	}
	buf := make([]byte, 0, contentLength+1)
	for len(buf) < cap(buf) {
		n, err := capped.Read(buf[len(buf):cap(buf)])
		buf = buf[:len(buf)+n]
		if errors.Is(err, io.EOF) {
			return buf, nil
		}
		if err != nil {
			return buf, err
		}
	}
	// The body is longer than declared: read on, still within the limit.
	rest, err := io.ReadAll(capped)
	return append(buf, rest...), err
}

// truncated reports whether a body of n bytes falls short of, or runs past,
// its declared length (-1 for unknown).
func truncated(n, declared int64) bool { return declared >= 0 && n != declared }

// capReader passes on at most limit bytes of r. The read that finds a byte
// beyond the limit returns the bytes within it together with
// errResponseTooLarge, and so does every read after it. Unlike io.LimitReader,
// it never reports a body cut at the limit as a clean end.
type capReader struct {
	r        io.Reader
	limit    int64
	read     int64
	exceeded bool
}

// Read reads from the wrapped reader within the limit, plus one byte to
// detect a longer body.
func (c *capReader) Read(p []byte) (int, error) {
	if c.exceeded {
		return 0, errResponseTooLarge
	}
	if room := c.limit - c.read + 1; int64(len(p)) > room {
		p = p[:room]
	}
	n, err := c.r.Read(p)
	if c.read+int64(n) > c.limit {
		n = int(c.limit - c.read)
		c.read = c.limit
		c.exceeded = true
		return n, errResponseTooLarge
	}
	c.read += int64(n)
	return n, err
}

// progressReader fails a body that makes no progress: maxEmptyReads reads in
// a row that return neither bytes nor an error. Without it, a body from an
// injected transport that keeps answering (0, nil) would spin a CPU until the
// call's deadline.
type progressReader struct {
	r     io.Reader
	empty int
}

// Read reads from the wrapped reader, counting reads that make no progress.
func (p *progressReader) Read(b []byte) (int, error) {
	n, err := p.r.Read(b)
	if n > 0 || err != nil || len(b) == 0 {
		p.empty = 0
		return n, err
	}
	if p.empty++; p.empty >= maxEmptyReads {
		return 0, errTransportStalled
	}
	return 0, nil
}

// excerpt returns a body when it reads completely within maxErrorBodyBytes,
// and nil when it is declared or found longer, or its read fails. A stalled
// read ends with the call's context, which closes the body.
func excerpt(body io.Reader, contentLength int64) []byte {
	if contentLength > maxErrorBodyBytes {
		return nil
	}
	b, err := readBody(body, contentLength, maxErrorBodyBytes)
	if err != nil {
		return nil
	}
	return b
}

// encoded reports whether h carries a Content-Encoding other than identity.
// The transport removes the header when it decodes gzip itself, so one that
// remains names an encoding nobody decoded. Every value counts, as a list of
// codings; empty list elements are ignored.
func encoded(h http.Header) bool {
	for _, v := range h.Values("Content-Encoding") {
		for coding := range strings.SplitSeq(v, ",") {
			coding = strings.Trim(coding, " \t")
			if coding != "" && !strings.EqualFold(coding, "identity") {
				return true
			}
		}
	}
	return false
}

// contentType returns the lowercased media type of the one Content-Type
// header, and whether it is usable: no header at all is ("", true), while more
// than one, or one that does not parse, is ("", false).
func contentType(h http.Header) (string, bool) {
	values := h.Values("Content-Type")
	switch len(values) {
	case 0:
		return "", true
	case 1:
	default:
		return "", false
	}
	media, _, err := mime.ParseMediaType(values[0])
	if err != nil {
		return "", false
	}
	return media, true
}

// hasJSONType reports whether h declares JSON (application/json or a +json
// type) or no content type at all.
func hasJSONType(h http.Header) bool {
	media, ok := contentType(h)
	return ok && (media == "" || isJSONMedia(media))
}

// isJSONMedia reports whether media is application/json or a +json type.
func isJSONMedia(media string) bool {
	return media == mediaJSON || strings.HasSuffix(media, "+json")
}

// blank reports whether b holds only JSON whitespace.
func blank(b []byte) bool { return skipSpace(b) == len(b) }

// skipSpace returns the index of the first byte of b that is not JSON
// whitespace, or len(b).
func skipSpace(b []byte) int {
	i := 0
	for i < len(b) && isSpace(b[i]) {
		i++
	}
	return i
}

// isSpace reports whether c is JSON whitespace.
func isSpace(c byte) bool { return c == ' ' || c == '\t' || c == '\n' || c == '\r' }

// envelope is what the SDK reads from a JSON object that may be the
// provider's error envelope, {"status": …, "error": …, "message": …}.
type envelope struct {
	// status is the "status" member when it is a JSON integer or a string of
	// three digits from 100 to 599, else 0. No success answer has one: their
	// "status" members are words. Only a status of 400 or more makes the
	// object an error envelope (see failed); any status is kept as APIStatus
	// of an error response.
	status int

	// hasError reports an "error" member that is present and not null.
	hasError bool

	// message is the raw "message" member.
	message json.RawMessage
}

// failed reports whether e is an error envelope: its status is from 400 to
// 599. Inside a 2xx answer such an envelope fails the call by that status; an
// object whose status is lower is an ordinary answer, judged by its call.
func (e envelope) failed() bool { return e.status >= http.StatusBadRequest }

// envelopeWire is the decoding shape of an envelope.
type envelopeWire struct {
	Status  json.RawMessage `json:"status"`
	Error   json.RawMessage `json:"error"`
	Message json.RawMessage `json:"message"`
}

// readEnvelope reads b as an envelope. ok reports that b is one valid JSON
// object in valid UTF-8; it is an error envelope when env.failed().
func readEnvelope(b []byte) (envelope, bool) {
	if i := skipSpace(b); i >= len(b) || b[i] != '{' || !utf8.Valid(b) {
		return envelope{}, false
	}
	var w envelopeWire
	if err := json.Unmarshal(b, &w); err != nil {
		return envelope{}, false
	}
	return envelope{status: envelopeStatus(w.Status), hasError: present(w.Error), message: w.Message}, true
}

// envelopeStatus returns an envelope status member as a number from 100 to
// 599: a JSON integer, or a string of exactly three digits. It returns 0 for
// anything else.
func envelopeStatus(raw json.RawMessage) int {
	digits := string(raw)
	if len(raw) == 5 && raw[0] == '"' && raw[4] == '"' {
		digits = string(raw[1:4])
	}
	if len(digits) != 3 || !asciiRange(digits, '0', '9') {
		return 0
	}
	n, _ := strconv.Atoi(digits)
	if n < 100 || n > 599 {
		return 0
	}
	return n
}

// present reports whether a raw member was sent with a value other than null.
func present(raw json.RawMessage) bool { return raw != nil && string(raw) != "null" }

// diagnosticsFrom returns the provider's message when diagnostics are enabled
// and the member is a JSON string, with the API key scrubbed, cut to 1 KiB.
func (c *Client) diagnosticsFrom(raw json.RawMessage) ProviderDiagnostics {
	if !c.diagnostics || len(raw) == 0 || raw[0] != '"' {
		return ProviderDiagnostics{}
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return ProviderDiagnostics{}
	}
	return ProviderDiagnostics{Message: truncateUTF8(c.scrub(s), maxDiagnosticMessageBytes)}
}

// truncateUTF8 cuts s to at most n bytes without splitting a UTF-8 sequence.
func truncateUTF8(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n]
}

// retryAfter reads the standard Retry-After header: exactly one value, either
// delta-seconds or an HTTP-date, clamped to 0 through 24 hours. ok is false
// when there is none or it does not parse.
func retryAfter(h http.Header, now time.Time) (time.Duration, bool) {
	values := h.Values("Retry-After")
	if len(values) != 1 {
		return 0, false
	}
	v := strings.Trim(values[0], " \t")
	if v != "" && asciiRange(v, '0', '9') {
		const maxSeconds = int64(maxRetryAfter / time.Second)
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil {
			// Digits only, so the one possible failure is a value too large
			// for int64: it is past the clamp either way.
			return maxRetryAfter, true
		}
		return time.Duration(min(n, maxSeconds)) * time.Second, true
	}
	t, err := http.ParseTime(v)
	if err != nil {
		return 0, false
	}
	return min(max(t.Sub(now), 0), maxRetryAfter), true
}
