package bouncer_test

import (
	"context"
	"net/http"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/mrz1836/go-bouncer"
	"github.com/mrz1836/go-bouncer/internal/testutil"
)

// pollLog is an in-memory transport that answers each Status poll with the
// next step and records when each poll arrived, on the synctest clock.
type pollLog struct {
	script *testutil.Script
	mu     sync.Mutex
	at     []time.Duration
	start  time.Time
}

// newPollLog returns a pollLog over steps, timed from now.
func newPollLog(steps ...testutil.Step) *pollLog {
	return &pollLog{script: testutil.NewScript(steps...), start: time.Now()}
}

// RoundTrip records the poll's time and answers it.
func (p *pollLog) RoundTrip(r *http.Request) (*http.Response, error) {
	p.mu.Lock()
	p.at = append(p.at, time.Since(p.start))
	p.mu.Unlock()
	return p.script.RoundTrip(r)
}

// times returns when each poll arrived.
func (p *pollLog) times() []time.Duration {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]time.Duration(nil), p.at...)
}

// waitFor runs Wait for testBatchID with interval and maxWait.
func waitFor(ctx context.Context, c *bouncer.Client, interval, maxWait time.Duration) (*bouncer.Batch, error) {
	return c.Batches().Wait(ctx, bouncer.WaitBatchRequest{BatchID: testBatchID, Interval: interval, MaxWait: maxWait})
}

// TestWaitPollsUntilCompleted checks the cadence: the first poll at once,
// then each one Interval after the previous ended, until the batch completes.
func TestWaitPollsUntilCompleted(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		polls := newPollLog(jsonStep(batchQueued), jsonStep(batchProcessing), jsonStep(batchCompleted))
		c := newClient(t, polls)
		st, err := waitFor(t.Context(), c, 15*time.Second, time.Hour)
		require.NoError(t, err)
		assert.Equal(t, bouncer.BatchStateCompleted, st.State)
		assert.Equal(t, []time.Duration{0, 15 * time.Second, 30 * time.Second}, polls.times())
		for _, r := range polls.script.Requests() {
			assert.Equal(t, http.MethodGet, r.Method, "Wait only ever calls Status")
			assert.Equal(t, pathBatchID, r.Path)
		}
	})
}

// TestWaitDefaultIntervalAndStats checks that Interval 0 means
// DefaultWaitInterval, and that WithStats reaches every poll.
func TestWaitDefaultIntervalAndStats(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		polls := newPollLog(jsonStep(batchQueued), jsonStep(batchCompleted))
		c := newClient(t, polls)
		st, err := c.Batches().Wait(t.Context(), bouncer.WaitBatchRequest{
			BatchID: testBatchID, MaxWait: time.Hour, WithStats: true,
		})
		require.NoError(t, err)
		require.NotNil(t, st)
		assert.Equal(t, []time.Duration{0, bouncer.DefaultWaitInterval}, polls.times())
		for _, r := range polls.script.Requests() {
			assert.Equal(t, pathBatchID+"?with-stats=true", r.URL[len("https://127.0.0.1"):])
		}
	})
}

// TestWaitBudgetExhausted checks that MaxWait ends the wait with the last
// status read, and that no poll starts at or after it.
func TestWaitBudgetExhausted(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		steps := make([]testutil.Step, 10)
		for i := range steps {
			steps[i] = jsonStep(batchProcessing)
		}
		polls := newPollLog(steps...)
		c := newClient(t, polls)
		st, err := waitFor(t.Context(), c, 10*time.Second, 35*time.Second)
		requireCallError(t, err, wantCall{
			Kind: bouncer.FailureBudgetExhausted, Op: bouncer.OpBatchStatus, BatchID: testBatchID,
		})
		require.NotNil(t, st, "the last status read")
		assert.Equal(t, bouncer.BatchStateProcessing, st.State)
		assert.Equal(t, []time.Duration{0, 10 * time.Second, 20 * time.Second, 30 * time.Second}, polls.times())
		assert.Equal(t, 30*time.Second, time.Since(polls.start), "it returns as soon as the next poll could not start")
	})
}

// TestWaitPollDueAtMaxWaitNeverStarts checks the boundary: a poll due exactly
// when MaxWait ends is not made.
func TestWaitPollDueAtMaxWaitNeverStarts(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		polls := newPollLog(jsonStep(batchQueued), jsonStep(batchCompleted))
		c := newClient(t, polls)
		_, err := waitFor(t.Context(), c, 10*time.Second, 10*time.Second)
		requireCallError(t, err, wantCall{Kind: bouncer.FailureBudgetExhausted, Op: bouncer.OpBatchStatus, BatchID: testBatchID})
		assert.Len(t, polls.times(), 1)
	})
}

// TestWaitBudgetCutsOffARunningPoll checks that a poll still running when
// MaxWait ends is cut off and reported as budget_exhausted.
func TestWaitBudgetCutsOffARunningPoll(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		polls := newPollLog(jsonStep(batchQueued), testutil.Step{Respond: testutil.BlockUntilDone})
		c := newClient(t, polls)
		st, err := waitFor(t.Context(), c, 10*time.Second, 25*time.Second)
		requireCallError(t, err, wantCall{
			Kind: bouncer.FailureBudgetExhausted, Op: bouncer.OpBatchStatus, BatchID: testBatchID,
		})
		require.NotNil(t, st)
		assert.Equal(t, bouncer.BatchStateQueued, st.State)
		assert.Equal(t, 25*time.Second, time.Since(polls.start))
	})
}

// TestWaitStopsOnUnknownState checks that an undocumented state ends the wait
// at once, with that status, rather than polling through it.
func TestWaitStopsOnUnknownState(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		polls := newPollLog(jsonStep(`{"batchId":"5f0c2b9e8d7a6b5c4d3e2f1a","status":"paused"}`), jsonStep(batchCompleted))
		c := newClient(t, polls)
		st, err := waitFor(t.Context(), c, 10*time.Second, time.Hour)
		requireCallError(t, err, wantCall{
			Kind: bouncer.FailureUnknownBatchState, Op: bouncer.OpBatchStatus, BatchID: testBatchID,
		})
		require.NotNil(t, st)
		assert.Equal(t, bouncer.BatchState("paused"), st.State)
		assert.False(t, st.State.Known())
		assert.Len(t, polls.times(), 1)
	})
}

// TestWaitFailedPollIsNotRetried checks that a poll that fails ends the wait
// with that error and the last status read, after exactly one attempt.
func TestWaitFailedPollIsNotRetried(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		polls := newPollLog(jsonStep(batchQueued), statusStep(http.StatusServiceUnavailable, `{}`), jsonStep(batchCompleted))
		c := newClient(t, polls)
		st, err := waitFor(t.Context(), c, 10*time.Second, time.Hour)
		requireCallError(t, err, wantCall{
			Kind: bouncer.FailureUnavailable, Op: bouncer.OpBatchStatus, StatusCode: http.StatusServiceUnavailable,
			BatchID: testBatchID,
		})
		require.NotNil(t, st)
		assert.Equal(t, bouncer.BatchStateQueued, st.State)
		assert.Len(t, polls.times(), 2)
	})

	synctest.Test(t, func(t *testing.T) {
		polls := newPollLog(statusStep(http.StatusNotFound, `{}`))
		c := newClient(t, polls)
		st, err := waitFor(t.Context(), c, 10*time.Second, time.Hour)
		requireCallError(t, err, wantCall{
			Kind: bouncer.FailureNotFound, Op: bouncer.OpBatchStatus, StatusCode: http.StatusNotFound, BatchID: testBatchID,
		})
		assert.Nil(t, st, "no status was read")
	})
}

// TestWaitCallerContext checks that the caller's cancellation and deadline
// end the wait with their own kinds, never budget_exhausted, and that nothing
// runs after Wait returns.
func TestWaitCallerContext(t *testing.T) {
	t.Parallel()
	t.Run("canceled during a pause", func(t *testing.T) {
		t.Parallel()
		synctest.Test(t, func(t *testing.T) {
			polls := newPollLog(jsonStep(batchQueued), jsonStep(batchCompleted))
			c := newClient(t, polls)
			ctx, cancel := context.WithCancel(t.Context())
			time.AfterFunc(5*time.Second, cancel)
			st, err := waitFor(ctx, c, 10*time.Second, time.Hour)
			requireCallError(t, err, wantCall{Kind: bouncer.FailureCanceled, Op: bouncer.OpBatchStatus, BatchID: testBatchID})
			require.NotNil(t, st)
			assert.Len(t, polls.times(), 1)
			time.Sleep(time.Hour) //nolint:forbidigo // synctest's fake clock: proves nothing polls after Wait returned
			assert.Len(t, polls.times(), 1)
		})
	})

	t.Run("caller deadline during a poll", func(t *testing.T) {
		t.Parallel()
		synctest.Test(t, func(t *testing.T) {
			polls := newPollLog(jsonStep(batchQueued), testutil.Step{Respond: testutil.BlockUntilDone})
			c := newClient(t, polls)
			ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
			defer cancel()
			st, err := waitFor(ctx, c, 10*time.Second, time.Hour)
			requireCallError(t, err, wantCall{
				Kind: bouncer.FailureDeadlineExceeded, Op: bouncer.OpBatchStatus, BatchID: testBatchID,
			})
			require.NotNil(t, st)
			require.NotErrorIs(t, err, bouncer.ErrBudgetExhausted)
			require.NotErrorIs(t, err, bouncer.ErrTimeout)
		})
	})
}
