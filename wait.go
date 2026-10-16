package bouncer

import (
	"context"
	"errors"
	"time"
)

// Wait bounds.
const (
	minWaitInterval = time.Second
	maxWaitInterval = 10 * time.Minute
	maxWaitLimit    = 72 * time.Hour
)

// WaitBatchRequest is one Wait call.
type WaitBatchRequest struct {
	// BatchID is the batch to watch.
	BatchID BatchID

	// Interval is the pause between the end of one poll and the start of the
	// next: 0 means DefaultWaitInterval (10 seconds), otherwise 1 second to 10
	// minutes. Mind the provider's rate limits on status calls.
	Interval time.Duration

	// MaxWait is the required elapsed-time budget, more than 0 and at most 72
	// hours. It holds even when ctx has no deadline.
	MaxWait time.Duration

	// WithStats asks each poll for Batch.Processed and Batch.Stats.
	WithStats bool
}

// Wait polls Status until the batch completes, and returns the last status it
// read.
//
// Free and read-only: it only ever calls Status, first immediately and then
// Interval after each poll ends, in the caller's goroutine. It never creates,
// finishes, deletes or downloads a batch, starts no goroutine, and does
// nothing after it returns. It returns:
//   - (status, nil) for BatchStateCompleted;
//   - (status, *CallError{Kind: unknown_batch_state}) for a state this
//     package does not document, which it surfaces rather than polls through;
//   - (last, *CallError{Kind: budget_exhausted}) as soon as the next poll
//     could not start before MaxWait ends (so up to one Interval early: it
//     does not sleep out the rest), or when MaxWait cuts off a poll still
//     running;
//   - (last, a canceled or deadline_exceeded *CallError) when ctx ends;
//   - (last, err) when a poll fails before MaxWait: it never retries, so
//     polling policy stays the caller's.
//
// last is the last status read, or nil when there was none. Canceling ctx
// stops the polling only: the provider keeps verifying, and billing, the
// batch. Errors that are not a *ValidationError carry Op batch_status and
// BatchID req.BatchID.
func (s BatchService) Wait(ctx context.Context, req WaitBatchRequest) (*Batch, error) {
	if err := s.c.prepare(ctx); err != nil {
		return nil, err
	}
	interval, err := req.validate()
	if err != nil {
		return nil, err
	}
	start := time.Now()
	waitCtx, cancel := context.WithDeadlineCause(ctx, start.Add(req.MaxWait), errWaitBudget)
	defer cancel()
	var last *Batch
	for {
		st, err := s.Status(waitCtx, BatchStatusRequest{BatchID: req.BatchID, WithStats: req.WithStats})
		if err != nil {
			return last, req.pollFailed(waitCtx, err)
		}
		last = st
		switch {
		case st.State.Terminal():
			return st, nil
		case !st.State.Known():
			return st, req.stopped(FailureUnknownBatchState, errUnknownState)
		}
		if err := req.pause(waitCtx, start, interval); err != nil {
			return last, err
		}
	}
}

// pollFailed returns the error for a poll that failed within waitCtx:
// budget_exhausted when MaxWait cut it off, and the poll's own error
// otherwise. Only the deadline failure MaxWait itself caused is relabeled: an
// answer that arrived as MaxWait ended, such as an HTTP 401, keeps its own
// kind, and so does the caller's own deadline.
func (r *WaitBatchRequest) pollFailed(waitCtx context.Context, err error) error {
	ce, ok := errors.AsType[*CallError](err)
	if ok && ce.Kind == FailureDeadlineExceeded && errors.Is(context.Cause(waitCtx), errWaitBudget) {
		return r.stopped(FailureBudgetExhausted, errWaitBudget)
	}
	return err
}

// pause waits interval before the next poll, or returns the error that ends
// the wait instead: budget_exhausted when the next poll could not start
// before MaxWait, counted from start, ends, or the caller's context failure.
// A poll due exactly when MaxWait ends is never started.
func (r *WaitBatchRequest) pause(waitCtx context.Context, start time.Time, interval time.Duration) error {
	if time.Since(start)+interval >= r.MaxWait {
		return r.stopped(FailureBudgetExhausted, errWaitBudget)
	}
	timer := time.NewTimer(interval)
	defer timer.Stop()
	select {
	case <-waitCtx.Done():
		if errors.Is(context.Cause(waitCtx), errWaitBudget) {
			return r.stopped(FailureBudgetExhausted, errWaitBudget)
		}
		return contextFailure(OpBatchStatus, waitCtx.Err(), 0).forBatch(r.BatchID)
	case <-timer.C:
		return nil
	}
}

// validate checks the request and returns the effective interval.
func (r *WaitBatchRequest) validate() (time.Duration, error) {
	if err := checkBatchID(r.BatchID); err != nil {
		return 0, err
	}
	interval := r.Interval
	switch {
	case interval == 0:
		interval = DefaultWaitInterval
	case interval < minWaitInterval || interval > maxWaitInterval:
		return 0, invalidRequest("Interval", reasonOutOfRange)
	}
	switch {
	case r.MaxWait == 0:
		return 0, invalidRequest("MaxWait", reasonRequired)
	case r.MaxWait < 0 || r.MaxWait > maxWaitLimit:
		return 0, invalidRequest("MaxWait", reasonOutOfRange)
	}
	return interval, nil
}

// stopped returns the CallError for a wait that ended without a failed call.
func (r *WaitBatchRequest) stopped(kind FailureKind, cause error) *CallError {
	return newCallError(OpBatchStatus, kind, 0, cause).forBatch(r.BatchID)
}
