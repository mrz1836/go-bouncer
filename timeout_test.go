package bouncer_test

import (
	"context"
	"errors"
	"io"
	"net/http"
	"testing"
	"testing/synctest"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/mrz1836/go-bouncer"
	"github.com/mrz1836/go-bouncer/internal/testutil"
)

// TestSDKTimeoutVersusCallerContext runs every operation against a transport
// that never answers, and checks which deadline ends it: the SDK's own
// (timeout, matching ErrTimeout and context.DeadlineExceeded), the caller's
// earlier deadline (deadline_exceeded, not ErrTimeout), or the caller's
// cancellation (canceled).
func TestSDKTimeoutVersusCallerContext(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		timeout time.Duration // both WithTimeout and WithDownloadTimeout
		ctx     func(context.Context) (context.Context, context.CancelFunc)
		kind    bouncer.FailureKind
		elapsed time.Duration
	}{
		{
			name: "SDK timeout", timeout: 20 * time.Second, kind: bouncer.FailureTimeout, elapsed: 20 * time.Second,
			ctx: context.WithCancel,
		},
		{
			name: "caller deadline", timeout: time.Minute, kind: bouncer.FailureDeadlineExceeded, elapsed: 5 * time.Second,
			ctx: func(ctx context.Context) (context.Context, context.CancelFunc) {
				return context.WithTimeout(ctx, 5*time.Second)
			},
		},
		{
			name: "caller cancel", timeout: time.Minute, kind: bouncer.FailureCanceled, elapsed: 3 * time.Second,
			ctx: func(ctx context.Context) (context.Context, context.CancelFunc) {
				ctx, cancel := context.WithCancel(ctx)
				time.AfterFunc(3*time.Second, cancel)
				return ctx, cancel
			},
		},
	}
	for _, oc := range opCases() {
		for _, tt := range tests {
			t.Run(oc.name+"/"+tt.name, func(t *testing.T) {
				t.Parallel()
				synctest.Test(t, func(t *testing.T) {
					c := newClient(t, testutil.RoundTripFunc(testutil.BlockUntilDone),
						bouncer.WithTimeout(tt.timeout), bouncer.WithDownloadTimeout(tt.timeout))
					ctx, cancel := tt.ctx(t.Context())
					defer cancel()
					start := time.Now()
					err := oc.call(ctx, c)
					ce := requireCallError(t, err, oc.wantFor(wantCall{Kind: tt.kind}))
					deadline := tt.kind != bouncer.FailureCanceled
					assert.Equal(t, tt.kind == bouncer.FailureTimeout, errors.Is(err, bouncer.ErrTimeout), "ErrTimeout")
					assert.Equal(t, deadline, errors.Is(err, context.DeadlineExceeded), "context.DeadlineExceeded")
					assert.Equal(t, deadline, ce.Timeout())
					assert.Equal(t, tt.elapsed, time.Since(start))
				})
			})
		}
	}
}

// TestTimeoutWhileReadingTheBody checks that the SDK's deadline also bounds
// the body: a response whose body blocks after its headers fails as a
// timeout, and its body is closed exactly once.
func TestTimeoutWhileReadingTheBody(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		body := testutil.NewBody(`{"credits":`)
		body.Block = true
		c := newClient(t, testutil.TransportWith(http.StatusOK, nil, -1, body), bouncer.WithTimeout(10*time.Second))
		start := time.Now()
		_, err := c.Credits(context.Background())
		requireCallError(t, err, wantCall{Kind: bouncer.FailureTimeout, Op: bouncer.OpCredits, StatusCode: http.StatusOK})
		assert.Equal(t, 10*time.Second, time.Since(start))
		synctest.Wait()
		assert.Equal(t, 1, body.Closes(), "closed exactly once")
	})
}

// TestDownloadTimeoutIsSeparate checks that WithTimeout does not bound
// Results and Download, which WithDownloadTimeout bounds instead: a slow body
// that takes longer than WithTimeout but less than WithDownloadTimeout
// completes, and one that takes longer than WithDownloadTimeout fails.
func TestDownloadTimeoutIsSeparate(t *testing.T) {
	t.Parallel()
	slowCSV := func() *testutil.Body {
		b := testutil.NewBody(csvFile)
		b.Step, b.Gap = 8, time.Second // 7 reads of content, 1 second apart
		return b
	}
	downloadReq := bouncer.DownloadBatchRequest{BatchID: testBatchID, Format: bouncer.FormatCSV}
	header := http.Header{"Content-Type": {mediaCSV}}

	t.Run("completes within the download timeout", func(t *testing.T) {
		t.Parallel()
		synctest.Test(t, func(t *testing.T) {
			c := newClient(t, testutil.TransportWith(http.StatusOK, header, -1, slowCSV()),
				bouncer.WithTimeout(2*time.Second), bouncer.WithDownloadTimeout(time.Minute))
			var w testutil.CountingWriter
			n, err := c.Batches().Download(context.Background(), downloadReq, &w)
			require.NoError(t, err)
			assert.Equal(t, int64(len(csvFile)), n)
			assert.Equal(t, csvFile, string(w.Bytes()))
		})
	})

	t.Run("fails past the download timeout", func(t *testing.T) {
		t.Parallel()
		synctest.Test(t, func(t *testing.T) {
			c := newClient(t, testutil.TransportWith(http.StatusOK, header, -1, slowCSV()),
				bouncer.WithTimeout(time.Minute), bouncer.WithDownloadTimeout(3*time.Second))
			var w testutil.CountingWriter
			n, err := c.Batches().Download(context.Background(), downloadReq, &w)
			requireCallError(t, err, wantCall{
				Kind: bouncer.FailureTimeout, Op: bouncer.OpBatchDownload, StatusCode: http.StatusOK, BatchID: testBatchID,
				BytesWritten: n, checkCounts: true,
			})
			assert.Equal(t, int64(w.Len()), n, "the count returned is what the writer received")
		})
	})
}

// TestResultsTimeoutIncludesTheLoopBody checks that WithDownloadTimeout
// bounds a whole range over Results, the time the caller's loop body takes
// included: records already decoded are not yielded once it has passed.
func TestResultsTimeoutIncludesTheLoopBody(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		body := `[` + verifyOK + `,` + verifyOK + `,` + verifyOK + `]`
		c := newClient(t, testutil.StaticTransport(http.StatusOK, body), bouncer.WithDownloadTimeout(5*time.Second))
		var yielded int
		var final error
		for v, err := range c.Batches().Results(context.Background(), bouncer.BatchResultsRequest{BatchID: testBatchID}) {
			if err != nil {
				final = err
				break
			}
			require.Equal(t, testEmail, v.Email)
			yielded++
			<-time.After(3 * time.Second) // the caller's own slow work
		}
		requireCallError(t, final, wantCall{
			Kind: bouncer.FailureTimeout, Op: bouncer.OpBatchResults, StatusCode: http.StatusOK, BatchID: testBatchID,
			Records: 2, checkCounts: true,
		})
		assert.Equal(t, 2, yielded)
	})
}

// TestTimeoutReleasesTheBody checks that a call ending in a timeout leaves
// nothing behind: the body that was blocking is closed, and nothing reads it
// afterwards.
func TestTimeoutReleasesTheBody(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		body := testutil.NewBody("")
		body.Block = true
		c := newClient(t, testutil.TransportWith(http.StatusOK, http.Header{"Content-Type": {mediaCSV}}, -1, body),
			bouncer.WithDownloadTimeout(4*time.Second))
		_, err := c.Batches().Download(context.Background(),
			bouncer.DownloadBatchRequest{BatchID: testBatchID, Format: bouncer.FormatCSV}, io.Discard)
		require.ErrorIs(t, err, bouncer.ErrTimeout)
		synctest.Wait()
		reads := body.Reads()
		assert.Equal(t, 1, body.Closes())
		time.Sleep(time.Hour) //nolint:forbidigo // synctest's fake clock: proves nothing reads after the call returned
		assert.Equal(t, reads, body.Reads())
	})
}

// TestStreamingErrorExcerptIsBoundedByTheTimeout checks that the excerpt of
// an error answer to Results or Download, read only for diagnostics, is
// bounded by WithTimeout: a 503 whose body stalls fails after WithTimeout,
// not after the far longer WithDownloadTimeout.
func TestStreamingErrorExcerptIsBoundedByTheTimeout(t *testing.T) {
	t.Parallel()
	calls := map[string]func(ctx context.Context, c *bouncer.Client) error{
		"Results": func(ctx context.Context, c *bouncer.Client) error {
			_, err := collect(c.Batches().Results(ctx, bouncer.BatchResultsRequest{BatchID: testBatchID}))
			return err
		},
		"Download": func(ctx context.Context, c *bouncer.Client) error {
			_, err := c.Batches().Download(ctx,
				bouncer.DownloadBatchRequest{BatchID: testBatchID, Format: bouncer.FormatCSV}, io.Discard)
			return err
		},
	}
	for name, call := range calls {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			synctest.Test(t, func(t *testing.T) {
				body := testutil.NewBody(`{"status":"503"`)
				body.Block = true
				c := newClient(t, testutil.TransportWith(http.StatusServiceUnavailable, nil, 100, body),
					bouncer.WithTimeout(5*time.Second), bouncer.WithDownloadTimeout(time.Hour))
				start := time.Now()
				err := call(context.Background(), c)
				require.ErrorIs(t, err, bouncer.ErrUnavailable)
				assert.Equal(t, 5*time.Second, time.Since(start))
				synctest.Wait()
				assert.Equal(t, 1, body.Closes())
			})
		})
	}
}
