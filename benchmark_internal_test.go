package bouncer

import (
	"bytes"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/mrz1836/go-bouncer/internal/testutil"
)

// benchInternalRecord is one realistic verification record.
const benchInternalRecord = `{"email":"avery.example@example.com","status":"deliverable","reason":"accepted_email",` +
	`"domain":{"name":"example.com","acceptAll":"no","disposable":"no","free":"yes"},` +
	`"account":{"role":"no","disabled":"no","fullMailbox":"no"},"dns":{"type":"MX","record":"mx1.example.com"},` +
	`"provider":"example-mail","score":94,"toxic":"unknown","toxicity":0}`

// BenchmarkDecodeVerification decodes one full record.
func BenchmarkDecodeVerification(b *testing.B) {
	raw := []byte(benchInternalRecord)
	b.SetBytes(int64(len(raw)))
	b.ReportAllocs()
	for b.Loop() {
		if _, derr := decodeVerification(raw, ""); derr != nil {
			b.Fatal(derr)
		}
	}
}

// BenchmarkScanArray frames a 10,000-record array without decoding it.
func BenchmarkScanArray(b *testing.B) {
	const records = 10_000
	body := []byte("[" + strings.TrimSuffix(strings.Repeat(benchInternalRecord+",", records), ",") + "]")
	b.SetBytes(int64(len(body)))
	b.ReportAllocs()
	for b.Loop() {
		sc := newArrayScanner(bytes.NewReader(body))
		n := 0
		for {
			_, err := sc.next()
			if errors.Is(err, io.EOF) {
				break
			}
			if err != nil {
				b.Fatal(err)
			}
			n++
		}
		if n != records {
			b.Fatalf("got %d elements", n)
		}
	}
}

// BenchmarkEncodeCreateBatch10k validates and encodes a 10,000-entry batch.
func BenchmarkEncodeCreateBatch10k(b *testing.B) {
	entries := make([]BatchEntry, 10_000)
	for i := range entries {
		entries[i] = BatchEntry{Email: "avery.example@example.com", Name: "crm-row"}
	}
	req := CreateBatchRequest{Entries: entries}
	b.ReportAllocs()
	for b.Loop() {
		if _, err := req.outgoing(); err != nil {
			b.Fatal(err)
		}
	}
}

// TestAllocationCeilings guards the allocation counts of the hot paths
// against regressions: decoding one record, a whole Verify call over an
// in-memory transport, and one record of a Results stream. Each ceiling
// leaves headroom over today's count, so a failure means a change made the
// path allocate noticeably more, which should be a deliberate choice. (Go
// 1.26 counts 59, 105 and 63; Go 1.27 counts 42, 83 and 46.) It is not
// parallel: testing.AllocsPerRun counts the whole process's allocations.
func TestAllocationCeilings(t *testing.T) {
	testutil.SkipUnderRace(t)
	ctx := t.Context()
	raw := []byte(benchInternalRecord)
	c := newTestClient(t, testutil.StaticTransport(http.StatusOK, benchInternalRecord))
	req := VerifyRequest{Email: "avery.example@example.com"}
	body := "[" + strings.TrimSuffix(strings.Repeat(benchInternalRecord+",", 500), ",") + "]"
	resp := testutil.Response(nil, http.StatusOK, io.NopCloser(strings.NewReader(body)), -1)
	defer func() { _ = resp.Body.Close() }()
	rs := newResultStream(ctx, ctx, c, resp)

	// Each path succeeds before it is measured.
	_, derr := decodeVerification(raw, "")
	require.Nil(t, derr)
	_, err := c.Verify(ctx, req)
	require.NoError(t, err)
	_, done, cerr := rs.next()
	require.Nil(t, cerr)
	require.False(t, done)

	testutil.CheckCeilings(t, []testutil.Ceiling{
		{Name: "decodeVerification", Max: 75, Run: func() { _, _ = decodeVerification(raw, "") }},
		{Name: "Verify", Max: 130, Run: func() { _, _ = c.Verify(ctx, req) }},
		{Name: "Results record", Max: 80, Run: func() { _, _, _ = rs.next() }},
	})
}
