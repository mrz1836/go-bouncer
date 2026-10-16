package testutil_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/mrz1836/go-bouncer/internal/testutil"
)

func TestSkipUnderRace(t *testing.T) {
	t.Parallel()
	testutil.SkipUnderRace(t)
	assert.False(t, testutil.RaceEnabled, "only reached without the race detector")
}

// TestCheckCeilings is not parallel: testing.AllocsPerRun counts the whole
// process's allocations.
func TestCheckCeilings(t *testing.T) {
	testutil.SkipUnderRace(t)
	// Storing into sink makes each allocation escape to the heap.
	sink := make([][]byte, 1)
	testutil.CheckCeilings(t, []testutil.Ceiling{
		{Name: "no allocations", Max: 0, Run: func() {}},
		{Name: "one allocation", Max: 1, Run: func() { sink[0] = make([]byte, 1<<10) }},
	})
}
