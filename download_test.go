package bouncer_test

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"testing/synctest"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/mrz1836/go-bouncer"
	"github.com/mrz1836/go-bouncer/internal/testutil"
)

// downloadCSVHeader is the header of a CSV answer.
func downloadCSVHeader() http.Header { return http.Header{"Content-Type": {mediaCSV}} }

// downloadCSVBody returns n bytes of CSV-like text that does not start with a
// brace.
func downloadCSVBody(n int) string {
	const row = "email,status\r\n"
	var b strings.Builder
	for b.Len() < n {
		b.WriteString(row)
	}
	return b.String()[:n]
}

// downloadJSONBody returns a JSON-looking body of exactly n bytes (n >= 2)
// that starts with "[" and ends with "]".
func downloadJSONBody(n int) string { return "[" + strings.Repeat(" ", n-2) + "]" }

// downloadOf runs one Download of testBatchID in format to w.
func downloadOf(ctx context.Context, c *bouncer.Client, format bouncer.DownloadFormat, w io.Writer) (int64, error) {
	return c.Batches().Download(ctx, bouncer.DownloadBatchRequest{BatchID: testBatchID, Format: format}, w)
}

// downloadFailure is the CallError a failed Download must carry.
func downloadFailure(kind bouncer.FailureKind, written int64) wantCall {
	return wantCall{
		Kind: kind, Op: bouncer.OpBatchDownload, StatusCode: http.StatusOK, BatchID: testBatchID,
		BytesWritten: written, checkCounts: true,
	}
}

// downloadBody answers every request with status 200, header and content,
// declared with contentLength (-1 for unknown).
func downloadBody(header http.Header, contentLength int64, content string) http.RoundTripper {
	return testutil.TransportWith(http.StatusOK, header, contentLength, io.NopCloser(strings.NewReader(content)))
}

// TestDownloadByteCap checks WithMaxDownloadBytes around the sniff window and
// the copy buffer: a body of exactly the cap is written whole; one byte more
// fails as ErrResponseTooLarge after exactly the cap, which the writer holds;
// and a declared length over the cap fails before any write.
func TestDownloadByteCap(t *testing.T) {
	t.Parallel()
	limits := []int{1, 7, 32<<10 - 1, 32 << 10, 32<<10 + 1, 64<<10 - 1, 64 << 10, 64<<10 + 1, 64<<10 + 2, 200 << 10}
	for _, limit := range limits {
		name := strconv.Itoa(limit)
		body := downloadCSVBody(limit + 1)

		t.Run(name+"/exact", func(t *testing.T) {
			t.Parallel()
			for _, declared := range []int64{-1, int64(limit)} {
				c := newClient(t, downloadBody(downloadCSVHeader(), declared, body[:limit]),
					bouncer.WithMaxDownloadBytes(int64(limit)))
				var w testutil.CountingWriter
				n, err := downloadOf(t.Context(), c, bouncer.FormatCSV, &w)
				require.NoError(t, err)
				assert.Equal(t, int64(limit), n)
				assert.Equal(t, body[:limit], string(w.Bytes()))
			}
		})

		t.Run(name+"/one byte over", func(t *testing.T) {
			t.Parallel()
			c := newClient(t, downloadBody(downloadCSVHeader(), -1, body), bouncer.WithMaxDownloadBytes(int64(limit)))
			var w testutil.CountingWriter
			n, err := downloadOf(t.Context(), c, bouncer.FormatCSV, &w)
			requireCallError(t, err, downloadFailure(bouncer.FailureResponseTooLarge, int64(limit)))
			assert.Equal(t, int64(limit), n)
			assert.Equal(t, body[:limit], string(w.Bytes()), "exactly the cap reaches the writer")
		})

		t.Run(name+"/endless", func(t *testing.T) {
			t.Parallel()
			endless := &testutil.EndlessBody{}
			c := newClient(t, testutil.TransportWith(http.StatusOK, downloadCSVHeader(), -1, endless),
				bouncer.WithMaxDownloadBytes(int64(limit)))
			var w testutil.CountingWriter
			n, err := downloadOf(t.Context(), c, bouncer.FormatCSV, &w)
			requireCallError(t, err, downloadFailure(bouncer.FailureResponseTooLarge, int64(limit)))
			assert.Equal(t, int64(limit), n)
			assert.Equal(t, limit, w.Len())
			assert.Equal(t, 1, endless.Closes())
		})

		t.Run(name+"/declared over", func(t *testing.T) {
			t.Parallel()
			lazy := testutil.NewBody(body)
			c := newClient(t, testutil.TransportWith(http.StatusOK, downloadCSVHeader(), int64(len(body)), lazy),
				bouncer.WithMaxDownloadBytes(int64(limit)))
			var w testutil.CountingWriter
			n, err := downloadOf(t.Context(), c, bouncer.FormatCSV, &w)
			requireCallError(t, err, downloadFailure(bouncer.FailureResponseTooLarge, 0))
			assert.Zero(t, n)
			assert.Zero(t, w.Writes())
			assert.Zero(t, lazy.Reads(), "refused before any read")
		})

		if limit >= 2 {
			t.Run(name+"/json exact", func(t *testing.T) {
				t.Parallel()
				arrayBody := downloadJSONBody(limit)
				c := newClient(t, downloadBody(http.Header{"Content-Type": {mediaJSON}}, -1, arrayBody),
					bouncer.WithMaxDownloadBytes(int64(limit)))
				var w testutil.CountingWriter
				n, err := downloadOf(t.Context(), c, bouncer.FormatJSON, &w)
				require.NoError(t, err)
				assert.Equal(t, int64(limit), n)
				assert.Equal(t, arrayBody, string(w.Bytes()))
			})
		}
	}
}

// TestDownloadWriterFailures checks writers that fail, write short or report
// an impossible count: ErrWriteFailed, BytesWritten equal to what the writer
// accepted (never over-counted), and no write after the failure.
func TestDownloadWriterFailures(t *testing.T) {
	t.Parallel()
	body := downloadCSVBody(100 << 10)
	tests := []struct {
		name    string
		w       interface{ Writes() int }
		written int64
		writes  int
	}{
		{"fails at once", &testutil.FailAfterWriter{N: 0}, 0, 1},
		{"fails after 5 bytes", &testutil.FailAfterWriter{N: 5}, 5, 1},
		{"fails inside the second chunk", &testutil.FailAfterWriter{N: 40_000}, 40_000, 2},
		{"fails at a chunk boundary", &testutil.FailAfterWriter{N: 32 << 10}, 32 << 10, 2},
		{"short write", &testutil.ShortWriter{Max: 3}, 3, 1},
		{"negative count", &testutil.InvalidCountWriter{N: -1}, 0, 1},
		{"count over the chunk", &testutil.InvalidCountWriter{N: 1 << 30}, 0, 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			c := newClient(t, downloadBody(downloadCSVHeader(), int64(len(body)), body))
			n, err := downloadOf(t.Context(), c, bouncer.FormatCSV, tt.w.(io.Writer))
			requireCallError(t, err, downloadFailure(bouncer.FailureWriteFailed, tt.written))
			assert.Equal(t, tt.written, n)
			assert.Equal(t, tt.writes, tt.w.Writes(), "nothing is written after the failure")
		})
	}
}

// TestDownloadCopiesBytesExactly checks that CSV bodies reach the writer
// unchanged: quoted newlines, CRLF and lone CR line endings, a byte order mark,
// bytes that are not UTF-8 and NUL bytes, in one read or many small ones.
func TestDownloadCopiesBytesExactly(t *testing.T) {
	t.Parallel()
	bodies := map[string]string{
		"quoted newlines": "email,note\r\n" + testEmail + ",\"line one\nline two\r\nline three\"\r\n",
		"crlf":            "email,status\r\n" + testEmail + ",deliverable\r\n",
		"lone cr":         "email,status\r" + testEmail + ",deliverable\r",
		"lf":              "email,status\n" + testEmail + ",deliverable\n",
		"bom":             "\xef\xbb\xbfemail,status\r\n" + testEmail + ",risky\r\n",
		"not utf-8":       "email,name\r\n" + testEmail + ",\xff\xfe\xc3\x28\r\n",
		"nul bytes":       "email\x00status\r\n",
		"large mixed":     strings.Repeat("\xef\xbb\xbf\"a\r\nb\",\xff\r", 30<<10),
	}
	for name, body := range bodies {
		for _, step := range []int{0, 1, 7, 4096} {
			t.Run(name+"/step "+strconv.Itoa(step), func(t *testing.T) {
				t.Parallel()
				b := testutil.NewBody(body)
				b.Step = step
				c := newClient(t, testutil.TransportWith(http.StatusOK, downloadCSVHeader(), int64(len(body)), b))
				var w bytes.Buffer
				n, err := downloadOf(t.Context(), c, bouncer.FormatCSV, &w)
				require.NoError(t, err)
				assert.Equal(t, int64(len(body)), n)
				assert.Equal(t, []byte(body), w.Bytes(), "byte for byte")
				assert.Equal(t, 1, b.Closes())
			})
		}
	}
}

// TestDownloadCSVStartingWithABrace checks that a CSV answer over the 64 KiB
// sniff window is the file even when it starts with a brace: only a body
// wholly inside the window can be an envelope.
func TestDownloadCSVStartingWithABrace(t *testing.T) {
	t.Parallel()
	body := `{"status":402}` + downloadCSVBody(64<<10)
	c := newClient(t, downloadBody(downloadCSVHeader(), int64(len(body)), body))
	var w bytes.Buffer
	n, err := downloadOf(t.Context(), c, bouncer.FormatCSV, &w)
	require.NoError(t, err)
	assert.Equal(t, int64(len(body)), n)
	assert.Equal(t, body, w.String())
}

// TestDownloadJSONFraming checks the JSON format's framing: the body must
// start with "[" after whitespace (otherwise nothing is written), and its last
// byte other than whitespace must be "]" (otherwise the call fails after the
// copy, with every byte counted).
func TestDownloadJSONFraming(t *testing.T) {
	t.Parallel()
	large := "[" + resultsRecord("one") + strings.Repeat(","+verifyOK, 1000)
	tests := []struct {
		name    string
		body    string
		kind    bouncer.FailureKind
		written int64
	}{
		{"array", resultsOK, "", int64(len(resultsOK))},
		{"empty array", `[]`, "", 2},
		{"leading and trailing whitespace", " \r\n\t" + resultsOK + " \n", "", int64(len(resultsOK)) + 6},
		{"large array", large + "]", "", int64(len(large)) + 1},
		{"missing final bracket", `[` + verifyOK, bouncer.FailureMalformedResponse, int64(len(verifyOK)) + 1},
		{"large, missing final bracket", large, bouncer.FailureMalformedResponse, int64(len(large))},
		{"data after the bracket", resultsOK + ` x`, bouncer.FailureMalformedResponse, int64(len(resultsOK)) + 2},
		{"empty body", ``, bouncer.FailureMalformedResponse, 0},
		{"only whitespace", " \n ", bouncer.FailureMalformedResponse, 0},
		{"a string", `"` + testEmail + `"`, bouncer.FailureMalformedResponse, 0},
		{"null", `null`, bouncer.FailureMalformedResponse, 0},
		{"csv", csvFile, bouncer.FailureMalformedResponse, 0},
		{"large object", `{"pad":"` + strings.Repeat("p", 64<<10) + `"}`, bouncer.FailureUnexpectedResponse, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			c := newClient(t, downloadBody(http.Header{"Content-Type": {mediaJSON}}, int64(len(tt.body)), tt.body))
			var w testutil.CountingWriter
			n, err := downloadOf(t.Context(), c, bouncer.FormatJSON, &w)
			assert.Equal(t, tt.written, n)
			assert.Equal(t, int(tt.written), w.Len(), "n is what the writer received")
			if tt.kind == "" {
				require.NoError(t, err)
				assert.Equal(t, tt.body, string(w.Bytes()))
				return
			}
			requireCallError(t, err, downloadFailure(tt.kind, tt.written))
		})
	}
}

// TestDownloadContentTypes checks the content-type gate of each format,
// before anything is written.
func TestDownloadContentTypes(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		format bouncer.DownloadFormat
		types  []string
		ok     bool
	}{
		{"csv text/csv", bouncer.FormatCSV, []string{mediaCSV}, true},
		{"csv with charset", bouncer.FormatCSV, []string{"text/csv; charset=utf-8"}, true},
		{"csv uppercase", bouncer.FormatCSV, []string{"TEXT/CSV"}, true},
		{"csv application/csv", bouncer.FormatCSV, []string{"application/csv"}, true},
		{"csv text/plain", bouncer.FormatCSV, []string{"text/plain"}, true},
		{"csv octet-stream", bouncer.FormatCSV, []string{mediaOctet}, true},
		{"csv none", bouncer.FormatCSV, nil, true},
		{"csv text/html", bouncer.FormatCSV, []string{mediaHTML}, false},
		{"csv application/xml", bouncer.FormatCSV, []string{"application/xml"}, false},
		{"csv two types", bouncer.FormatCSV, []string{mediaCSV, mediaCSV}, false},
		{"csv unparsable", bouncer.FormatCSV, []string{"text/"}, false},
		{"json application/json", bouncer.FormatJSON, []string{mediaJSON}, true},
		{"json +json", bouncer.FormatJSON, []string{"application/vnd.example+json"}, true},
		{"json none", bouncer.FormatJSON, nil, true},
		{"json text/csv", bouncer.FormatJSON, []string{mediaCSV}, false},
		{"json text/plain", bouncer.FormatJSON, []string{"text/plain"}, false},
		{"json octet-stream", bouncer.FormatJSON, []string{mediaOctet}, false},
		{"json text/html", bouncer.FormatJSON, []string{mediaHTML}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			body := csvFile
			if tt.format == bouncer.FormatJSON {
				body = resultsOK
			}
			header := http.Header{}
			if tt.types != nil {
				header["Content-Type"] = tt.types
			}
			c := newClient(t, downloadBody(header, int64(len(body)), body))
			var w testutil.CountingWriter
			n, err := downloadOf(t.Context(), c, tt.format, &w)
			if tt.ok {
				require.NoError(t, err)
				assert.Equal(t, body, string(w.Bytes()))
				return
			}
			requireCallError(t, err, downloadFailure(bouncer.FailureUnexpectedResponse, 0))
			assert.Zero(t, n)
			assert.Zero(t, w.Writes())
		})
	}
}

// TestDownloadCSVAnsweredAsUnreadableJSON checks a CSV download answered as
// JSON whose body cannot be read whole within the 64 KiB sniff: one of
// unknown length that runs past it is unexpected, like one that declares
// more, and one whose read fails is a transport failure. Neither writes a
// byte.
func TestDownloadCSVAnsweredAsUnreadableJSON(t *testing.T) {
	t.Parallel()
	header := http.Header{"Content-Type": {mediaJSON}}
	broken := testutil.NewBody(`{"status":402`)
	broken.End = io.ErrUnexpectedEOF
	tests := []struct {
		name string
		rt   http.RoundTripper
		kind bouncer.FailureKind
	}{
		{
			"over 64 KiB, length unknown",
			downloadBody(header, -1, `{"status":402,"pad":"`+strings.Repeat("x", 64<<10)+`"}`),
			bouncer.FailureUnexpectedResponse,
		},
		{"read error", testutil.TransportWith(http.StatusOK, header, -1, broken), bouncer.FailureTransport},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var w testutil.CountingWriter
			n, err := downloadOf(t.Context(), newClient(t, tt.rt), bouncer.FormatCSV, &w)
			requireCallError(t, err, downloadFailure(tt.kind, 0))
			assert.Zero(t, n)
			assert.Zero(t, w.Writes())
		})
	}
}

// TestDownloadNeverClosesTheWriter checks that the caller's writer is never
// closed, flushed or synced, whether the download succeeds or fails.
func TestDownloadNeverClosesTheWriter(t *testing.T) {
	t.Parallel()
	big := downloadCSVBody(100 << 10)
	tests := []struct {
		name string
		rt   http.RoundTripper
		opts []bouncer.Option
		ok   bool
	}{
		{"success", downloadBody(downloadCSVHeader(), int64(len(big)), big), nil, true},
		{"too large", downloadBody(downloadCSVHeader(), -1, big), []bouncer.Option{bouncer.WithMaxDownloadBytes(50 << 10)}, false},
		{"truncated", downloadBody(downloadCSVHeader(), int64(len(big))+1, big), nil, false},
		{"refused", statusRoundTripper(http.StatusMethodNotAllowed), nil, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			c := newClient(t, tt.rt, tt.opts...)
			spy := &testutil.CloseFlushSpy{}
			n, err := downloadOf(t.Context(), c, bouncer.FormatCSV, spy)
			assert.Equal(t, int64(spy.Len()), n)
			if tt.ok {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
			}
			assert.False(t, spy.Touched(), "never closed, flushed or synced")
		})
	}
}

// statusRoundTripper answers every request with status and an empty JSON
// object.
func statusRoundTripper(status int) http.RoundTripper { return testutil.StaticTransport(status, `{}`) }

// TestDownloadBlockedWriteIsNotInterrupted checks the documented limit: a
// Write that blocks cannot be interrupted, so canceling the context during
// it returns only once the write is released. The bytes it wrote are
// counted, and nothing is read or written after it.
func TestDownloadBlockedWriteIsNotInterrupted(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		body := downloadCSVBody(100 << 10)
		c := newClient(t, downloadBody(downloadCSVHeader(), int64(len(body)), body))
		w := testutil.NewBlockingWriter()
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		type result struct {
			n   int64
			err error
		}
		done := make(chan result, 1)
		go func() {
			n, err := downloadOf(ctx, c, bouncer.FormatCSV, w)
			done <- result{n, err}
		}()
		<-w.Entered()
		cancel()
		synctest.Wait()
		select {
		case <-done:
			t.Fatal("Download returned while its writer was blocked")
		default:
		}
		w.Release()
		res := <-done
		requireCallError(t, res.err, downloadFailure(bouncer.FailureCanceled, 32<<10))
		assert.Equal(t, int64(32<<10), res.n, "the released write is counted")
		assert.Equal(t, 1, w.Writes(), "nothing is written after the cancellation")
		assert.Equal(t, 32<<10, w.Len())
	})
}

// downloadCancelWriter cancels a context on its first Write, and keeps every
// byte.
type downloadCancelWriter struct {
	testutil.CountingWriter

	cancel context.CancelFunc
}

// Write keeps p and cancels the context.
func (w *downloadCancelWriter) Write(p []byte) (int, error) {
	n, err := w.CountingWriter.Write(p)
	w.cancel()
	return n, err
}

// TestDownloadChecksTheContextBeforeEachRead checks that a cancellation
// between two chunks stops the copy before the next read: the first chunk is
// counted, and the bytes already buffered never reach the writer.
func TestDownloadChecksTheContextBeforeEachRead(t *testing.T) {
	t.Parallel()
	body := downloadCSVBody(60 << 10) // all of it fits the sniff buffer
	c := newClient(t, downloadBody(downloadCSVHeader(), int64(len(body)), body))
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	w := &downloadCancelWriter{cancel: cancel}
	n, err := downloadOf(ctx, c, bouncer.FormatCSV, w)
	requireCallError(t, err, downloadFailure(bouncer.FailureCanceled, 32<<10))
	assert.Equal(t, int64(32<<10), n)
	assert.Equal(t, 1, w.Writes())
}

// TestDownloadIncompleteBodies checks bodies that end early: one short of its
// declared length, or cut by the transport, fails as ErrTransport. Within the
// sniff window nothing is written; past it, BytesWritten counts what was
// copied.
func TestDownloadIncompleteBodies(t *testing.T) {
	t.Parallel()
	small, large := csvFile, downloadCSVBody(100<<10)
	cut := func(content string) http.RoundTripper {
		b := testutil.NewBody(content)
		b.End = io.ErrUnexpectedEOF
		return testutil.TransportWith(http.StatusOK, downloadCSVHeader(), -1, b)
	}
	stalled := func(content string) http.RoundTripper {
		b := testutil.NewBody(content)
		b.Stall = true
		return testutil.TransportWith(http.StatusOK, downloadCSVHeader(), -1, b)
	}
	tests := []struct {
		name    string
		rt      http.RoundTripper
		written int64
	}{
		{"small, short of its length", downloadBody(downloadCSVHeader(), int64(len(small))+1, small), 0},
		{"large, short of its length", downloadBody(downloadCSVHeader(), int64(len(large))+1, large), int64(len(large))},
		{"small, cut", cut(small), 0},
		{"large, cut", cut(large), int64(len(large))},
		{"small, stalled", stalled(small), 0},
		{"large, stalled", stalled(large), int64(len(large))},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			c := newClient(t, tt.rt)
			var w testutil.CountingWriter
			n, err := downloadOf(t.Context(), c, bouncer.FormatCSV, &w)
			requireCallError(t, err, downloadFailure(bouncer.FailureTransport, tt.written))
			assert.Equal(t, tt.written, n)
			assert.Equal(t, int(tt.written), w.Len())
		})
	}
}

// TestDownloadEmptyCSV checks that an empty CSV answer is a successful
// download of zero bytes, with no write at all.
func TestDownloadEmptyCSV(t *testing.T) {
	t.Parallel()
	for _, declared := range []int64{0, -1} {
		t.Run(strconv.FormatInt(declared, 10), func(t *testing.T) {
			t.Parallel()
			c := newClient(t, downloadBody(downloadCSVHeader(), declared, ""))
			var w testutil.CountingWriter
			n, err := downloadOf(t.Context(), c, bouncer.FormatCSV, &w)
			require.NoError(t, err)
			assert.Zero(t, n)
			assert.Zero(t, w.Writes())
		})
	}
}

// TestDownloadReturnsBytesWrittenOnEveryPath checks, across successes and
// failures, that the count Download returns is what the writer received, and
// that a failure's BytesWritten is that same count.
func TestDownloadReturnsBytesWrittenOnEveryPath(t *testing.T) {
	t.Parallel()
	large := downloadCSVBody(100 << 10)
	tests := []struct {
		name string
		rt   http.RoundTripper
		opts []bouncer.Option
	}{
		{"success", downloadBody(downloadCSVHeader(), int64(len(large)), large), nil},
		{"too large", downloadBody(downloadCSVHeader(), -1, large), []bouncer.Option{bouncer.WithMaxDownloadBytes(70_000)}},
		{"truncated", downloadBody(downloadCSVHeader(), int64(len(large))+5, large), nil},
		{"status", statusRoundTripper(http.StatusNotFound), nil},
		{"content type", downloadBody(http.Header{"Content-Type": {mediaHTML}}, -1, large), nil},
		{"transport", testutil.NewScript(testutil.Step{Err: io.ErrUnexpectedEOF}), nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			c := newClient(t, tt.rt, tt.opts...)
			var w testutil.CountingWriter
			n, err := downloadOf(t.Context(), c, bouncer.FormatCSV, &w)
			assert.Equal(t, int64(w.Len()), n)
			if err != nil {
				ce := testutil.RequireErrorAs[*bouncer.CallError](t, err)
				assert.Equal(t, n, ce.BytesWritten)
				assert.Equal(t, testBatchID, ce.BatchID)
			}
		})
	}
}
