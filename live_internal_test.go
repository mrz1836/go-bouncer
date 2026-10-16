//go:build live

package bouncer

// Live contract tests. They call the real Bouncer API and some are billable.
// CI never runs them: the "live" tag is excluded from auto-discovered tag
// runs. Run them only by hand, after the owner has approved the addresses,
// the call count, the budget and any batch left behind:
//
//	BOUNCER_LIVE=1 BOUNCER_LIVE_TIERS=credits,verify,batch BOUNCER_API_KEY=… \
//	    go test -tags live -run '^TestLive' -count=1 -v .
//
// Tiers, each skipped unless listed in BOUNCER_LIVE_TIERS:
//   - credits: one Credits call (free);
//   - verify: one Verify of a documented sandbox address;
//   - batch: one two-entry batch of sandbox addresses, then Wait (status
//     polls only), Results and a CSV Download. Delete is never called: the
//     batch is left for the owner, and its ID is logged.
//
// Output is value-free where the answer could hold contact data: JSON shapes
// (key names and types, never values), counts and the CSV header row.

import (
	"bytes"
	"context"
	"net/http"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/mrz1836/go-bouncer/internal/testutil"
)

// sandboxDomain is the provider's documented domain of free test addresses,
// such as "deliverable@" and "unknown@" at it. It is served by the same API
// host.
const sandboxDomain = "sandbox.usebouncer.com"

// sandboxAddress returns the documented sandbox address with local part
// local.
func sandboxAddress(local string) string { return local + "@" + sandboxDomain }

// liveClient returns a Client for the live API, skipping the test unless
// BOUNCER_LIVE is "1" and tier is listed in BOUNCER_LIVE_TIERS.
func liveClient(t *testing.T, tier string) *Client {
	t.Helper()
	if os.Getenv("BOUNCER_LIVE") != "1" {
		t.Skip("live tests need BOUNCER_LIVE=1 and the owner's approval")
	}
	if !slices.Contains(strings.Split(os.Getenv("BOUNCER_LIVE_TIERS"), ","), tier) {
		t.Skipf("tier %q is not listed in BOUNCER_LIVE_TIERS", tier)
	}
	c, err := NewClient(os.Getenv("BOUNCER_API_KEY"), WithUserAgent("go-bouncer-live-test"))
	require.NoError(t, err, "BOUNCER_API_KEY must hold a valid key")
	t.Cleanup(c.CloseIdleConnections)
	return c
}

// logShape logs the value-free shape of a raw JSON answer.
func logShape(t *testing.T, label string, body []byte) {
	t.Helper()
	shape, ok := testutil.JSONShape(body)
	if !ok {
		t.Logf("%s: not valid JSON (%d bytes)", label, len(body))
		return
	}
	t.Logf("%s shape: %s", label, shape)
}

func TestLiveCredits(t *testing.T) {
	c := liveClient(t, "credits")
	rep, cerr := c.exchange(t.Context(), &outgoing{op: OpCredits, method: http.MethodGet, path: pathCredits, accept: mediaJSON})
	require.Nil(t, cerr)
	logShape(t, "credits", rep.body)
	_, derr := decodeCredits(rep.body)
	require.Nil(t, derr)
}

func TestLiveVerify(t *testing.T) {
	c := liveClient(t, "verify")
	req := VerifyRequest{Email: sandboxAddress("deliverable"), Timeout: 20 * time.Second}
	out, err := req.outgoing(c.timeout)
	require.NoError(t, err)
	rep, cerr := c.exchange(t.Context(), out)
	require.Nil(t, cerr)
	logShape(t, "verify", rep.body)
	v, derr := decodeVerification(rep.body, "")
	require.Nil(t, derr)
	t.Logf("verify: status %q reason %q score set %t", v.Status, v.Reason, v.Score != nil)
}

func TestLiveBatch(t *testing.T) {
	c := liveClient(t, "batch")
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Minute)
	defer cancel()
	s := c.Batches()

	b, err := s.Create(ctx, CreateBatchRequest{Entries: []BatchEntry{
		{Email: sandboxAddress("deliverable"), Name: "live-row-1"},
		{Email: sandboxAddress("unknown")},
	}})
	require.NoError(t, err)
	t.Logf("batch: created %s (left for the owner: Delete is never called), state %q", b.ID, b.State)

	st, err := s.Wait(ctx, WaitBatchRequest{BatchID: b.ID, Interval: 15 * time.Second, MaxWait: 10 * time.Minute, WithStats: true})
	require.NoError(t, err)
	t.Logf("batch: state %q, quantity set %t, credits set %t", st.State, st.Quantity != nil, st.CreditsUsed != nil)

	out, err := (&BatchResultsRequest{BatchID: b.ID}).outgoing()
	require.NoError(t, err)
	callCtx, cancelCall := context.WithTimeout(ctx, c.downloadTimeout)
	defer cancelCall()
	resp, release, cerr := c.openStream(ctx, callCtx, out) //nolint:bodyclose // closed by release
	require.Nil(t, cerr)
	raw, rerr := readBody(resp.Body, resp.ContentLength, c.maxDownloadBytes)
	release()
	require.NoError(t, rerr)
	logShape(t, "results", raw)

	records := 0
	for v, err := range s.Results(ctx, BatchResultsRequest{BatchID: b.ID}) {
		require.NoError(t, err)
		records++
		t.Logf("results: record %d status %q, name echoed %t", records, v.Status, v.Name != "")
	}

	var csv bytes.Buffer
	n, err := s.Download(ctx, DownloadBatchRequest{BatchID: b.ID, Format: FormatCSV}, &csv)
	require.NoError(t, err)
	header, _, _ := strings.Cut(csv.String(), "\n")
	t.Logf("download: %d CSV bytes, header row %q", n, strings.TrimRight(header, "\r"))
}
