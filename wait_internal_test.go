package bouncer

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/mrz1836/go-bouncer/internal/testutil"
)

// TestWaitPauseEndsOnTheBudget checks the pause between polls when MaxWait
// ends it. Wait starts no pause that the budget would cut short, so only a
// scheduling delay that leaves the timer and the deadline both due can take
// this path: the test cancels the context with the budget's cause instead.
func TestWaitPauseEndsOnTheBudget(t *testing.T) {
	t.Parallel()
	req := WaitBatchRequest{BatchID: "5f0c2b9e8d7a6b5c4d3e2f1a", MaxWait: time.Hour}
	waitCtx, cancel := context.WithCancelCause(t.Context())
	cancel(errWaitBudget)
	err := req.pause(waitCtx, time.Now(), time.Minute)
	ce := testutil.RequireErrorAs[*CallError](t, err)
	assert.Equal(t, FailureBudgetExhausted, ce.Kind)
	assert.Equal(t, OpBatchStatus, ce.Op)
	assert.Equal(t, req.BatchID, ce.BatchID)
}
