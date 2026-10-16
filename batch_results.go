package bouncer

import (
	"context"
	"errors"
	"io"
	"iter"
	"net/http"
	"strings"
)

// ResultFilter selects which of a batch's results Results and Download read.
// It is a closed set: "" means FilterAll, and any other value outside the
// constants fails validation. The SDK always sends it, because the provider
// documents no default.
type ResultFilter string

// Result filters.
const (
	FilterAll           ResultFilter = "all"
	FilterDeliverable   ResultFilter = "deliverable"
	FilterRisky         ResultFilter = "risky"
	FilterUndeliverable ResultFilter = "undeliverable"
	FilterUnknown       ResultFilter = "unknown"
)

// param returns the filter as it is sent, and false when it is invalid.
func (f ResultFilter) param() (string, bool) {
	switch f {
	case "":
		return string(FilterAll), true
	case FilterAll, FilterDeliverable, FilterRisky, FilterUndeliverable, FilterUnknown:
		return string(f), true
	}
	return "", false
}

// BatchResultsRequest is one Results call.
type BatchResultsRequest struct {
	// BatchID is the completed batch to read.
	BatchID BatchID

	// Filter selects results by verdict. "" means FilterAll.
	Filter ResultFilter
}

// Results streams a completed batch's results: GET
// https://api.usebouncer.com/v1.1/email/verify/batch/{batchId}/download as
// JSON.
//
// Free and read-only. Calling Results does nothing: each range over the
// returned sequence validates the request and makes exactly one GET, and a
// second range makes a new one (nothing is cached). Records arrive in the
// provider's order, which it does not document, with memory bounded by one
// record: the SDK promises no correlation with the batch's entries, and
// duplicates pass through as the provider sends them. Breaking out of the
// loop closes the response at once.
//
// The sequence yields at most one error, last, with a zero Verification. A
// failure after some records, such as a truncated or oversized stream or data
// after the array, still yields those records first: an error always ends
// the sequence, so a stream that ends early never looks complete. HTTP 405
// (ErrBatchState) means the batch is not completed or its results were
// removed. WithDownloadTimeout bounds the whole range, the loop body's time
// included, and WithMaxDownloadBytes its bytes. An empty array yields
// nothing and no error.
//
// Errors are a *ValidationError (nothing sent) or a *CallError whose BatchID
// is req.BatchID and whose Records is the number of records yielded.
func (s BatchService) Results(ctx context.Context, req BatchResultsRequest) iter.Seq2[Verification, error] {
	return func(yield func(Verification, error) bool) {
		s.results(ctx, req, yield)
	}
}

// results runs one range of Results.
func (s BatchService) results(ctx context.Context, req BatchResultsRequest, yield func(Verification, error) bool) {
	c := s.c
	if err := c.prepare(ctx); err != nil {
		yield(Verification{}, err)
		return
	}
	out, err := req.outgoing()
	if err != nil {
		yield(Verification{}, err)
		return
	}
	callCtx, cancel := context.WithTimeout(ctx, c.downloadTimeout)
	defer cancel()
	resp, release, cerr := c.openStream(ctx, callCtx, out) //nolint:bodyclose // closed exactly once by release
	if cerr != nil {
		yield(Verification{}, cerr.forBatch(req.BatchID))
		return
	}
	defer release()
	if !hasJSONType(resp.Header) {
		yield(Verification{}, newCallError(OpBatchResults, FailureUnexpectedResponse, resp.StatusCode, errContentType).
			forBatch(req.BatchID))
		return
	}
	if cerr := c.tooLong(OpBatchResults, resp); cerr != nil {
		yield(Verification{}, cerr.forBatch(req.BatchID))
		return
	}
	rs := newResultStream(ctx, callCtx, c, resp)
	for {
		v, done, cerr := rs.next()
		switch {
		case cerr != nil:
			cerr.Records = rs.records
			yield(Verification{}, cerr.forBatch(req.BatchID))
			return
		case done:
			return
		}
		rs.records++
		if !yield(v, nil) {
			return
		}
	}
}

// outgoing validates the request and describes its call.
func (r *BatchResultsRequest) outgoing() (*outgoing, error) {
	filter, err := checkResultsTarget(r.BatchID, r.Filter)
	if err != nil {
		return nil, err
	}
	return downloadCall(OpBatchResults, r.BatchID, filter, mediaJSON), nil
}

// checkResultsTarget validates the batch and the filter of a Results or
// Download call, and returns the filter as it is sent.
func checkResultsTarget(id BatchID, f ResultFilter) (string, error) {
	if err := checkBatchID(id); err != nil {
		return "", err
	}
	filter, ok := f.param()
	if !ok {
		return "", invalidRequest("Filter", reasonInvalidValue)
	}
	return filter, nil
}

// downloadCall describes a GET of a batch's results.
func downloadCall(op Operation, id BatchID, filter, accept string) *outgoing {
	path, rawPath := batchPath(id, "/download")
	var q strings.Builder
	queryParam(&q, "download", filter)
	return &outgoing{op: op, method: http.MethodGet, path: path, rawPath: rawPath, query: q.String(), accept: accept}
}

// openStream makes the one attempt of a streaming call within callCtx and
// checks the response's status and encoding before any of its body is read.
// On success the caller must run release.
//
// An error status is read only for its excerpt, which feeds APIStatus and the
// diagnostics: that read is bounded by the buffered-call timeout as well, so
// that an error answer whose body stalls fails as soon as a buffered call
// would, not when the download timeout ends.
func (c *Client) openStream(ctx, callCtx context.Context, out *outgoing) (*http.Response, func(), *CallError) {
	resp, body, cerr := open(ctx, callCtx, c.send, out)
	if cerr != nil {
		return nil, nil, cerr
	}
	if resp.StatusCode >= http.StatusBadRequest {
		excerptCtx, cancel := context.WithTimeout(callCtx, c.timeout)
		stop := context.AfterFunc(excerptCtx, body.close)
		failure := c.checkResponse(out.op, resp)
		stop()
		cancel()
		body.release()
		return nil, nil, failure
	}
	if failure := c.checkResponse(out.op, resp); failure != nil {
		body.release()
		return nil, nil, failure
	}
	return resp, body.release, nil
}

// tooLong returns the failure for a streamed answer whose declared length is
// over the download byte limit, or nil. Callers check it after the content
// type, before reading.
func (c *Client) tooLong(op Operation, resp *http.Response) *CallError {
	if resp.ContentLength > c.maxDownloadBytes {
		return newCallError(op, FailureResponseTooLarge, resp.StatusCode, errResponseTooLarge)
	}
	return nil
}

// resultStream reads one Results response record by record.
type resultStream struct {
	c       *Client
	ctx     context.Context //nolint:containedctx // lives for one range of Results only
	callCtx context.Context //nolint:containedctx // lives for one range of Results only
	resp    *http.Response
	body    *capReader
	sc      *arrayScanner
	records int64
}

// newResultStream returns the stream over resp's body, within the Client's
// download byte limit.
func newResultStream(ctx, callCtx context.Context, c *Client, resp *http.Response) *resultStream {
	body := &capReader{r: &progressReader{r: resp.Body}, limit: c.maxDownloadBytes}
	return &resultStream{c: c, ctx: ctx, callCtx: callCtx, resp: resp, body: body, sc: newArrayScanner(body)}
}

// next returns the next record, done at the clean end of the array, or the
// failure that ends the stream. The call's context is checked before each
// record, so that nothing more is yielded once it is done.
func (r *resultStream) next() (Verification, bool, *CallError) {
	const op = OpBatchResults
	status := r.resp.StatusCode
	elem, err := r.sc.next()
	switch {
	case errors.Is(err, io.EOF):
		if truncated(r.body.read, r.resp.ContentLength) {
			return Verification{}, false, newCallError(op, FailureTransport, status, errTransportClosed)
		}
		return Verification{}, true, nil
	case errors.Is(err, errObjectBody):
		return Verification{}, false, r.objectBody()
	case err != nil:
		return Verification{}, false, r.fail(err)
	}
	if err := r.callCtx.Err(); err != nil {
		return Verification{}, false, classify(r.ctx, r.callCtx, op, err, status)
	}
	v, derr := decodeVerification(elem, elemPath(r.records))
	if derr != nil {
		return Verification{}, false, derr.callError(op, status)
	}
	return v, false, nil
}

// objectBody reads an answer that is an object instead of the array: an
// error envelope fails by its status, and any other object is unexpected.
func (r *resultStream) objectBody() *CallError {
	obj, err := r.sc.object()
	if err != nil {
		return r.fail(err)
	}
	if env, ok := readEnvelope(obj); ok && env.failed() {
		return r.c.envelopeFailure(OpBatchResults, r.resp.StatusCode, env)
	}
	return newCallError(OpBatchResults, FailureUnexpectedResponse, r.resp.StatusCode, errWrongKind)
}

// fail maps a scanner failure: its own decode and size failures as they are,
// and a read error as a transport failure, a timeout or the caller's context.
func (r *resultStream) fail(err error) *CallError {
	if derr, ok := errors.AsType[*decodeError](err); ok {
		return derr.callError(OpBatchResults, r.resp.StatusCode)
	}
	return classify(r.ctx, r.callCtx, OpBatchResults, err, r.resp.StatusCode)
}
