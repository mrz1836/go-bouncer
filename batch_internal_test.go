package bouncer

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/mrz1836/go-bouncer/internal/testutil"
)

// TestCreateBodyOverTheLimit checks the 64 MiB bound on Create's encoded
// body, which only entries near every other limit at once can reach: 60,000
// entries of 1024-byte addresses and 256-byte names encode to about 78 MB.
// It builds that body, so -short skips it.
func TestCreateBodyOverTheLimit(t *testing.T) {
	t.Parallel()
	if testing.Short() {
		t.Skip("encodes a body of about 78 MB")
	}
	entry := BatchEntry{
		Email: strings.Repeat("a", MaxEmailBytes-len("@example.com")) + "@example.com",
		Name:  strings.Repeat("n", maxNameBytes),
	}
	entries := make([]BatchEntry, 60_000)
	for i := range entries {
		entries[i] = entry
	}
	out, err := CreateBatchRequest{Entries: entries}.outgoing()
	assert.Nil(t, out)
	require.ErrorIs(t, err, ErrInvalidRequest)
	ve := testutil.RequireErrorAs[*ValidationError](t, err)
	assert.Equal(t, "Entries", ve.Field)
	assert.Equal(t, reasonTooLarge, ve.Reason)
}
