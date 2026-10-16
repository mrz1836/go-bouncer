package bouncer

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/mrz1836/go-bouncer/internal/testutil"
)

// TestOwnTransportDroppedCallIsNotResent repeats the HTTP/1.1 drop test on
// the SDK's own transport: after a warm-up call, every operation's request
// is dropped on the reused connection, fails with ErrTransport, and reaches
// the server exactly once.
func TestOwnTransportDroppedCallIsNotResent(t *testing.T) {
	t.Parallel()
	for _, sc := range shapeCases() {
		t.Run(sc.name, func(t *testing.T) {
			t.Parallel()
			srv := testutil.NewDropServer(t, jsonAnswer(0, `{"credits":7}`), func(n int) bool { return n == 2 })
			c, _ := ownTransportClient(t, srv.URL(), srv.RootCAs())
			_, err := c.Credits(t.Context())
			require.NoError(t, err, "warm-up call")

			err = sc.call(t.Context(), c)
			require.ErrorIs(t, err, ErrTransport)
			assert.Equal(t, 2, srv.Hits(), "warm-up and the dropped call, never a resend")
			assert.Equal(t, 1, srv.Conns(), "the dropped call reused the warm-up connection")
		})
	}
}
