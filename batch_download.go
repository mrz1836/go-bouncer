package bouncer

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net/http"
	"slices"
)

// Download bounds.
const (
	// downloadSniffBytes is how much of a download is buffered before the
	// first byte is written: a body that ends within it and is a JSON object
	// is an error envelope or unexpected, not a file.
	downloadSniffBytes = 64 << 10

	// downloadCopyBuffer is the copy loop's read size.
	downloadCopyBuffer = 32 << 10
)

// DownloadFormat is the format Download asks for. It is a closed set, and
// required.
type DownloadFormat string

// Download formats.
const (
	// FormatJSON asks for a JSON array of verification records, the shape
	// Results decodes.
	FormatJSON DownloadFormat = "json"

	// FormatCSV asks for CSV ("Accept: text/csv"). Its columns are
	// undocumented: the SDK copies the bytes and never parses them.
	FormatCSV DownloadFormat = "csv"
)

// accept returns the Accept header for f, and false when f is invalid.
func (f DownloadFormat) accept() (string, bool) {
	switch f {
	case FormatJSON:
		return mediaJSON, true
	case FormatCSV:
		return mediaCSV, true
	}
	return "", false
}

// DownloadBatchRequest is one Download call.
type DownloadBatchRequest struct {
	// BatchID is the completed batch to download.
	BatchID BatchID

	// Filter selects results by verdict. "" means FilterAll.
	Filter ResultFilter

	// Format is the format to ask for. It is required.
	Format DownloadFormat
}

// Download streams a completed batch's results, unchanged, to w: GET
// https://api.usebouncer.com/v1.1/email/verify/batch/{batchId}/download. It
// returns the number of bytes written to w, on error too.
//
// Free and read-only. It makes exactly one attempt and never retries or
// resumes. The response is classified before any byte reaches w: a status
// other than 200, an undecoded Content-Encoding, a declared length over
// WithMaxDownloadBytes, a content type that does not match Format, a JSON body
// that does not start with "[", and a CSV body that is wholly a JSON object
// (an error envelope, such as for a batch that is not completed) all write
// nothing. The bytes are then copied as they are: quoting, line endings and
// any byte order mark included.
//
// w belongs to the caller: the SDK never closes, flushes or inspects it, and
// never writes to it again after a failure. On any error after streaming
// began, w holds a partial file of BytesWritten bytes: discard it. A JSON
// download whose last byte other than whitespace is not "]" fails as
// malformed; a CSV body the server ends by closing the connection cannot be
// checked for truncation. WithDownloadTimeout bounds the whole call, and
// WithMaxDownloadBytes the bytes written: a longer download fails with
// ErrResponseTooLarge after exactly that many. Canceling ctx stops the
// download at its next read, but cannot interrupt a Write to w that blocks.
//
// Errors are a *ValidationError (nothing sent) or a *CallError whose BatchID
// is req.BatchID and whose BytesWritten is the count returned.
func (s BatchService) Download(ctx context.Context, req DownloadBatchRequest, w io.Writer) (int64, error) {
	c := s.c
	if err := c.prepare(ctx); err != nil {
		return 0, err
	}
	out, err := req.outgoing()
	if err != nil {
		return 0, err
	}
	if w == nil {
		return 0, invalidRequest("w", reasonNil)
	}
	n, cerr := c.download(ctx, out, req.Format, w)
	if cerr != nil {
		cerr.BytesWritten = n
		return n, cerr.forBatch(req.BatchID)
	}
	return n, nil
}

// outgoing validates the request and describes its call.
func (r *DownloadBatchRequest) outgoing() (*outgoing, error) {
	filter, err := checkResultsTarget(r.BatchID, r.Filter)
	if err != nil {
		return nil, err
	}
	if r.Format == "" {
		return nil, invalidRequest("Format", reasonRequired)
	}
	accept, ok := r.Format.accept()
	if !ok {
		return nil, invalidRequest("Format", reasonInvalidValue)
	}
	return downloadCall(OpBatchDownload, r.BatchID, filter, accept), nil
}

// download makes the one attempt of a download within the download timeout
// and streams an accepted response to w.
func (c *Client) download(ctx context.Context, out *outgoing, format DownloadFormat, w io.Writer) (int64, *CallError) {
	callCtx, cancel := context.WithTimeout(ctx, c.downloadTimeout)
	defer cancel()
	resp, release, cerr := c.openStream(ctx, callCtx, out) //nolint:bodyclose // closed exactly once by release
	if cerr != nil {
		return 0, cerr
	}
	defer release()
	r, cerr := c.acceptDownload(ctx, callCtx, resp, format)
	if cerr != nil {
		return 0, cerr
	}
	cp := copier{ctx: ctx, callCtx: callCtx, contentLength: resp.ContentLength, limit: c.maxDownloadBytes}
	return cp.copy(w, r, format == FormatJSON)
}

// acceptDownload classifies a download response by its content type and its
// first bytes, before anything is written, and returns the reader to stream
// from when it is a file in the requested format.
func (c *Client) acceptDownload(ctx, callCtx context.Context, resp *http.Response, format DownloadFormat) (
	io.Reader, *CallError,
) {
	const op = OpBatchDownload
	status := resp.StatusCode
	media, ok := contentType(resp.Header)
	switch {
	case !ok:
		return nil, newCallError(op, FailureUnexpectedResponse, status, errContentType)
	case format == FormatCSV && isJSONMedia(media):
		return nil, c.jsonInsteadOfCSV(ctx, callCtx, resp)
	case format == FormatCSV && media != "" && !isCSVMedia(media):
		return nil, newCallError(op, FailureUnexpectedResponse, status, errContentType)
	case format == FormatJSON && media != "" && !isJSONMedia(media):
		return nil, newCallError(op, FailureUnexpectedResponse, status, errContentType)
	}
	if cerr := c.tooLong(op, resp); cerr != nil {
		return nil, cerr
	}
	// The progress check sits under the buffer, so a body that stalls is
	// reported the same way whether it stalls while sniffing or streaming.
	br := bufio.NewReaderSize(&progressReader{r: resp.Body}, downloadSniffBytes+1)
	head, err := br.Peek(downloadSniffBytes + 1)
	whole := errors.Is(err, io.EOF)
	switch {
	case err != nil && !whole:
		return nil, classify(ctx, callCtx, op, err, status)
	case whole && truncated(int64(len(head)), resp.ContentLength):
		return nil, newCallError(op, FailureTransport, status, errTransportClosed)
	}
	if cerr := c.sniff(head, whole, format, status); cerr != nil {
		return nil, cerr
	}
	return br, nil
}

// sniff checks a download's first bytes, the whole body when whole is set. A
// JSON download must start with "[": an object that is the whole body fails
// as its envelope, or as unexpected. A CSV download that is wholly a JSON
// object fails the same way; any other CSV body is accepted.
func (c *Client) sniff(head []byte, whole bool, format DownloadFormat, status int) *CallError {
	const op = OpBatchDownload
	i := skipSpace(head)
	if format == FormatJSON && i < len(head) && head[i] == '[' {
		return nil
	}
	if whole {
		if env, ok := readEnvelope(head); ok {
			if env.failed() {
				return c.envelopeFailure(op, status, env)
			}
			return newCallError(op, FailureUnexpectedResponse, status, errWrongKind)
		}
	}
	switch {
	case format == FormatCSV:
		return nil
	case i < len(head) && head[i] == '{':
		return newCallError(op, FailureUnexpectedResponse, status, errWrongKind)
	}
	return newCallError(op, FailureMalformedResponse, status, errWrongKind)
}

// jsonInsteadOfCSV reads a CSV download answered as JSON, at most
// downloadSniffBytes of it, and returns the failure it reports: its error
// envelope, or unexpected.
func (c *Client) jsonInsteadOfCSV(ctx, callCtx context.Context, resp *http.Response) *CallError {
	const op = OpBatchDownload
	status := resp.StatusCode
	if resp.ContentLength > downloadSniffBytes {
		return newCallError(op, FailureUnexpectedResponse, status, errContentType)
	}
	data, err := readBody(resp.Body, resp.ContentLength, downloadSniffBytes)
	switch {
	case errors.Is(err, errResponseTooLarge):
		return newCallError(op, FailureUnexpectedResponse, status, errContentType)
	case err != nil:
		return classify(ctx, callCtx, op, err, status)
	case truncated(int64(len(data)), resp.ContentLength):
		return newCallError(op, FailureTransport, status, errTransportClosed)
	}
	if env, ok := readEnvelope(data); ok && env.failed() {
		return c.envelopeFailure(op, status, env)
	}
	return newCallError(op, FailureUnexpectedResponse, status, errContentType)
}

// isCSVMedia reports whether media is a type a CSV download may carry.
func isCSVMedia(media string) bool {
	switch media {
	case "text/csv", "application/csv", "text/plain", "application/octet-stream":
		return true
	}
	return false
}

// copier copies an accepted download to the caller's writer.
type copier struct {
	ctx           context.Context //nolint:containedctx // lives for one Download call only
	callCtx       context.Context //nolint:containedctx // lives for one Download call only
	contentLength int64
	limit         int64
}

// copy copies r to w, at most limit bytes, and returns the bytes written. It
// is its own loop rather than io.Copy so that a failed read and a failed write
// stay apart: a writer that fails, or writes short or reports an impossible
// count, is write_failed; a read error, a stall included, is classified like
// any transport failure; a body that ends before its declared length is a
// truncated transport failure; and a body longer than limit is
// response_too_large after exactly limit bytes, found by a 1-byte probe read.
// For a JSON download, the last byte other than whitespace must be "]".
func (cp *copier) copy(w io.Writer, r io.Reader, jsonArray bool) (int64, *CallError) {
	const op = OpBatchDownload
	buf := make([]byte, min(downloadCopyBuffer, cp.limit))
	var (
		written int64
		last    byte
	)
	for {
		probing := written == cp.limit
		want := min(int64(len(buf)), cp.limit-written)
		if probing {
			want = 1
		}
		n, rerr := cp.read(r, buf[:want])
		if n > 0 {
			if probing {
				return written, newCallError(op, FailureResponseTooLarge, http.StatusOK, errResponseTooLarge)
			}
			if i := lastNonSpace(buf[:n]); i >= 0 {
				last = buf[i]
			}
			wn, ok := writeChunk(w, buf[:n])
			written += int64(wn)
			if !ok {
				return written, newCallError(op, FailureWriteFailed, http.StatusOK, errWriter)
			}
		}
		if rerr != nil {
			return written, cp.end(rerr, written, jsonArray && last != ']')
		}
	}
}

// end returns the outcome of a copy that read rerr after written bytes: none
// at a clean end, a truncated transport failure short of the declared length,
// a malformed JSON download whose last byte other than whitespace is not "]"
// (unclosed), or the read error classified.
func (cp *copier) end(rerr error, written int64, unclosed bool) *CallError {
	const op = OpBatchDownload
	switch {
	case !errors.Is(rerr, io.EOF):
		return classify(cp.ctx, cp.callCtx, op, rerr, http.StatusOK)
	case truncated(written, cp.contentLength):
		return newCallError(op, FailureTransport, http.StatusOK, errTransportClosed)
	case unclosed:
		return newCallError(op, FailureMalformedResponse, http.StatusOK, errTruncated)
	}
	return nil
}

// read reads from r unless the call's context is done: once the call is over,
// nothing more reaches w, neither bytes already buffered nor those of a body
// that keeps answering after the context closed it.
func (cp *copier) read(r io.Reader, p []byte) (int, error) {
	if err := cp.callCtx.Err(); err != nil {
		return 0, err
	}
	return r.Read(p)
}

// lastNonSpace returns the index of the last byte of p that is not JSON
// whitespace, or -1.
func lastNonSpace(p []byte) int {
	for i, c := range slices.Backward(p) {
		if !isSpace(c) {
			return i
		}
	}
	return -1
}

// writeChunk writes p to w and returns the bytes it counts as written, and
// whether the write succeeded in full. A count outside 0..len(p) counts as
// nothing written.
func writeChunk(w io.Writer, p []byte) (int, bool) {
	n, err := w.Write(p)
	if n < 0 || n > len(p) {
		return 0, false
	}
	return n, err == nil && n == len(p)
}
