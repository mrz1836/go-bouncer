package bouncer_test

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"runtime"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/mrz1836/go-bouncer"
	"github.com/mrz1836/go-bouncer/internal/testutil"
)

// resultsRecord is a small verification record whose email is
// "<local>@example.com".
func resultsRecord(local string) string {
	return `{"email":"` + local + `@example.com","status":"deliverable","reason":"accepted_email"}`
}

// resultsArray returns a JSON array of records.
func resultsArray(records ...string) string { return "[" + strings.Join(records, ",") + "]" }

// resultsRange ranges over Results for testBatchID with filter on c.
func resultsRange(ctx context.Context, c *bouncer.Client, filter bouncer.ResultFilter,
) ([]bouncer.Verification, error) {
	return collect(c.Batches().Results(ctx, bouncer.BatchResultsRequest{BatchID: testBatchID, Filter: filter}))
}

// resultsFailure is the CallError a failed range of Results must carry.
func resultsFailure(kind bouncer.FailureKind, field string, records int64) wantCall {
	return wantCall{
		Kind: kind, Op: bouncer.OpBatchResults, StatusCode: http.StatusOK, BatchID: testBatchID, Field: field,
		Records: records, checkCounts: true,
	}
}

// TestResultsSendsEveryFilter checks the one GET each filter makes: always
// download=<filter>, "" sent as "all", and an Accept of application/json.
func TestResultsSendsEveryFilter(t *testing.T) {
	t.Parallel()
	tests := []struct {
		filter bouncer.ResultFilter
		want   string
	}{
		{"", "all"},
		{bouncer.FilterAll, "all"},
		{bouncer.FilterDeliverable, "deliverable"},
		{bouncer.FilterRisky, "risky"},
		{bouncer.FilterUndeliverable, "undeliverable"},
		{bouncer.FilterUnknown, "unknown"},
	}
	for _, tt := range tests {
		t.Run(tt.want+"/"+string(tt.filter), func(t *testing.T) {
			t.Parallel()
			c, script := newScriptClient(t, jsonStep(`[]`))
			records, err := resultsRange(t.Context(), c, tt.filter)
			require.NoError(t, err)
			assert.Empty(t, records)
			req := testutil.OnlyRequest(t, script)
			u, err := url.Parse(req.URL)
			require.NoError(t, err)
			assert.Equal(t, http.MethodGet, req.Method)
			assert.Equal(t, pathDownload, req.Path)
			assert.Equal(t, "download="+tt.want, u.RawQuery)
			assert.Equal(t, []string{mediaJSON}, req.Header["Accept"])
		})
	}
}

// TestResultsDecodesTheFixture checks the mixed-results fixture: three records
// in the provider's order, with a real score of 0 apart from a score of ""
// (not evaluated), and the echoed name kept.
func TestResultsDecodesTheFixture(t *testing.T) {
	t.Parallel()
	c, _ := newScriptClient(t, jsonStep(string(testutil.Fixture(t, "synthetic/results_mixed.json"))))
	records, err := resultsRange(t.Context(), c, "")
	require.NoError(t, err)
	require.Len(t, records, 3)

	assert.Equal(t, bouncer.Verification{
		Email: "avery.example@example.com", Status: bouncer.StatusDeliverable, Reason: bouncer.ReasonAcceptedEmail,
		Score: new(91), Name: "row-1",
	}, records[0])
	assert.Equal(t, bouncer.Verification{
		Email: "blake.example@example.net", Status: bouncer.StatusRisky, Reason: bouncer.ReasonLowQuality,
		Score: new(0),
		Domain: &bouncer.Domain{
			Name: "example.net", AcceptAll: bouncer.FlagYes, Disposable: bouncer.FlagNo, Free: bouncer.FlagNo,
		},
	}, records[1])
	assert.Equal(t, bouncer.Verification{
		Email: "casey.example@example.org", Status: bouncer.StatusUndeliverable, Reason: bouncer.ReasonRejectedEmail,
	}, records[2])
	assert.Nil(t, records[2].Score, `"" means not evaluated`)
}

// TestResultsIsLazyAndUncached checks that calling Results does nothing, not
// even validation, until the sequence is ranged over, and that every range
// makes its own GET.
func TestResultsIsLazyAndUncached(t *testing.T) {
	t.Parallel()
	c, script := newScriptClient(t, jsonStep(resultsOK), jsonStep(resultsOK))
	seq := c.Batches().Results(t.Context(), bouncer.BatchResultsRequest{BatchID: testBatchID})
	assert.Zero(t, script.Calls(), "calling Results sends nothing")

	first, err := collect(seq)
	require.NoError(t, err)
	assert.Equal(t, 1, script.Calls())
	second, err := collect(seq)
	require.NoError(t, err)
	assert.Equal(t, 2, script.Calls(), "a second range makes a second GET")
	assert.Equal(t, first, second)

	bad := c.Batches().Results(t.Context(), bouncer.BatchResultsRequest{BatchID: testBatchID, Filter: "everything"})
	assert.Equal(t, 2, script.Calls())
	_, err = collect(bad)
	requireValidation(t, err, bouncer.ErrInvalidRequest, "Filter", reasonInvalidValue)
	assert.Equal(t, 2, script.Calls(), "an invalid request sends nothing")
}

// resultsGenerator is a response body that writes a JSON array of total
// records as it is read, so that a huge answer never exists in memory at
// once.
type resultsGenerator struct {
	total   int
	next    int
	started bool
	ended   bool
	buf     []byte
	pos     int
	read    atomic.Int64
	closes  atomic.Int32
}

// Read serves the next part of the array.
func (g *resultsGenerator) Read(p []byte) (int, error) {
	for g.pos == len(g.buf) {
		g.buf, g.pos = g.buf[:0], 0
		switch {
		case !g.started:
			g.started = true
			g.buf = append(g.buf, '[')
		case g.next < g.total:
			if g.next > 0 {
				g.buf = append(g.buf, ',')
			}
			g.buf = append(g.buf, `{"email":"user-`...)
			g.buf = strconv.AppendInt(g.buf, int64(g.next), 10)
			g.buf = append(g.buf, `@example.com","status":"deliverable","reason":"accepted_email","score":`...)
			g.buf = strconv.AppendInt(g.buf, int64(g.next%101), 10)
			g.buf = append(g.buf, `,"domain":{"name":"example.com","acceptAll":"no","disposable":"no","free":"no"}}`...)
			g.next++
		case !g.ended:
			g.ended = true
			g.buf = append(g.buf, ']')
		default:
			return 0, io.EOF
		}
	}
	n := copy(p, g.buf[g.pos:])
	g.pos += n
	g.read.Add(int64(n))
	return n, nil
}

// Close counts the close.
func (g *resultsGenerator) Close() error {
	g.closes.Add(1)
	return nil
}

// TestResultsStreamsWithBoundedMemory ranges over a generated answer of
// 200,000 records, tens of megabytes, and checks that every record arrives in
// order while the live heap stays far below the size of the answer: the SDK
// holds one record at a time. It is not parallel: runtime.ReadMemStats
// measures the whole process's heap.
func TestResultsStreamsWithBoundedMemory(t *testing.T) {
	testutil.SkipUnderRace(t)
	const total = 200_000
	gen := &resultsGenerator{total: total}
	c := newClient(t, testutil.Transport(http.StatusOK, -1, func() io.ReadCloser { return gen }))

	var ms runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&ms)
	baseline := ms.HeapAlloc
	var peak uint64
	count := 0
	for v, err := range c.Batches().Results(t.Context(), bouncer.BatchResultsRequest{BatchID: testBatchID}) {
		require.NoError(t, err)
		if want := "user-" + strconv.Itoa(count) + "@example.com"; v.Email != want {
			require.Equal(t, want, v.Email, "records arrive in the provider's order")
		}
		count++
		if count%20_000 == 0 {
			runtime.GC()
			runtime.ReadMemStats(&ms)
			peak = max(peak, ms.HeapAlloc)
		}
	}
	require.Equal(t, total, count)
	bodySize := gen.read.Load()
	var growth uint64
	if peak > baseline {
		growth = peak - baseline
	}
	t.Logf("body %d bytes; live heap growth at most %d bytes", bodySize, growth)
	assert.Greater(t, bodySize, int64(20<<20), "the answer is tens of megabytes")
	assert.Less(t, growth, uint64(4<<20), "the live heap stays bounded by one record and the buffers")
	assert.Equal(t, int32(1), gen.closes.Load(), "the body is closed once")
}

// TestResultsRecordSizeBound checks the 64 KiB bound per record: a record of
// exactly 64 KiB is decoded, and one byte more fails as ErrResponseTooLarge at
// its index, after the records before it were yielded.
func TestResultsRecordSizeBound(t *testing.T) {
	t.Parallel()
	padded := func(size int) string {
		head := `{"email":"avery.example@example.com","status":"deliverable","reason":"accepted_email","pad":"`
		tail := `"}`
		return head + strings.Repeat("p", size-len(head)-len(tail)) + tail
	}
	exact, over := padded(64<<10), padded(64<<10+1)
	require.Len(t, exact, 64<<10)
	require.Len(t, over, 64<<10+1)

	c, _ := newScriptClient(t, jsonStep(resultsArray(resultsRecord("first"), exact, over, resultsRecord("never"))))
	records, err := resultsRange(t.Context(), c, "")
	require.Len(t, records, 2)
	assert.Equal(t, "first@example.com", records[0].Email)
	assert.Equal(t, testEmail, records[1].Email, "a record of exactly 64 KiB is decoded")
	requireCallError(t, err, resultsFailure(bouncer.FailureResponseTooLarge, "[2]", 2))
}

// TestResultsBreakClosesTheBody checks that breaking out of the loop closes
// the response at once, and that nothing reads it afterwards.
func TestResultsBreakClosesTheBody(t *testing.T) {
	t.Parallel()
	records := make([]string, 50)
	for i := range records {
		records[i] = resultsRecord("row-" + strconv.Itoa(i))
	}
	content := resultsArray(records...)
	body := testutil.NewBody(content)
	body.Step = 64
	c := newClient(t, testutil.TransportWith(http.StatusOK, nil, int64(len(content)), body))

	count, readsAtBreak := 0, 0
	for v, err := range c.Batches().Results(t.Context(), bouncer.BatchResultsRequest{BatchID: testBatchID}) {
		require.NoError(t, err)
		require.NotEmpty(t, v.Email)
		count++
		if count == 3 {
			assert.Zero(t, body.Closes(), "the body is open while the loop runs")
			readsAtBreak = body.Reads()
			break
		}
	}
	assert.Equal(t, 3, count)
	assert.Equal(t, 1, body.Closes(), "breaking out closes the body at once")
	assert.Equal(t, readsAtBreak, body.Reads(), "nothing reads the body after the break")
	assert.Less(t, body.BytesRead(), int64(len(content)), "the rest of the answer is never read")
}

// TestResultsCancelBetweenRecords checks that canceling the context between
// records ends the sequence with canceled, counting the records yielded,
// even when the next records are already buffered.
func TestResultsCancelBetweenRecords(t *testing.T) {
	t.Parallel()
	c, _ := newScriptClient(t, jsonStep(resultsArray(
		resultsRecord("one"), resultsRecord("two"), resultsRecord("three"), resultsRecord("four"),
	)))
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	var (
		count int
		final error
	)
	for _, err := range c.Batches().Results(ctx, bouncer.BatchResultsRequest{BatchID: testBatchID}) {
		require.NoError(t, final, "nothing follows the error")
		if err != nil {
			final = err
			continue
		}
		count++
		if count == 2 {
			cancel()
		}
	}
	assert.Equal(t, 2, count)
	requireCallError(t, final, resultsFailure(bouncer.FailureCanceled, "", 2))
}

// TestResultsIncompleteAnswers checks answers that end early: a clean end
// before the closing bracket is malformed (truncated), and a body short of its
// declared length or cut by the transport is a transport failure. Either way
// the records before the cut are yielded, and the error comes last.
func TestResultsIncompleteAnswers(t *testing.T) {
	t.Parallel()
	one, two := resultsRecord("one"), resultsRecord("two")
	tests := []struct {
		name    string
		rt      http.RoundTripper
		kind    bouncer.FailureKind
		field   string
		records int64
	}{
		{
			"clean end after an element", testutil.StaticTransport(http.StatusOK, "["+one+","+two),
			bouncer.FailureMalformedResponse, "[2]", 2,
		},
		{
			"clean end after a comma", testutil.StaticTransport(http.StatusOK, "["+one+","),
			bouncer.FailureMalformedResponse, "[1]", 1,
		},
		{
			"clean end inside an element", testutil.StaticTransport(http.StatusOK, "["+one+`,{"email":"tw`),
			bouncer.FailureMalformedResponse, "[1]", 1,
		},
		{
			"clean end inside a string with brackets", testutil.StaticTransport(http.StatusOK, "["+one+`,{"email":"]}`),
			bouncer.FailureMalformedResponse, "[1]", 1,
		},
		{"empty body", testutil.StaticTransport(http.StatusOK, ""), bouncer.FailureMalformedResponse, "", 0},
		{
			"shorter than its Content-Length",
			testutil.TransportWith(http.StatusOK, nil, int64(len(resultsArray(one, two))+10),
				io.NopCloser(strings.NewReader(resultsArray(one, two)))),
			bouncer.FailureTransport, "", 2,
		},
		{
			"cut by the transport", func() http.RoundTripper {
				b := testutil.NewBody("[" + one + "," + two)
				b.End = io.ErrUnexpectedEOF
				return testutil.TransportWith(http.StatusOK, nil, -1, b)
			}(),
			bouncer.FailureTransport, "", 2,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			c := newClient(t, tt.rt)
			records, err := resultsRange(t.Context(), c, "")
			assert.Len(t, records, int(tt.records))
			requireCallError(t, err, resultsFailure(tt.kind, tt.field, tt.records))
		})
	}
}

// TestResultsFraming checks the array's framing through Results: an empty
// array is success with nothing yielded; data after the array, elements that
// are not objects, a trailing comma and a missing comma are malformed, after
// the records before them were yielded.
func TestResultsFraming(t *testing.T) {
	t.Parallel()
	one, two := resultsRecord("one"), resultsRecord("two")
	tests := []struct {
		name    string
		body    string
		ok      bool
		field   string
		records int64
	}{
		{"empty array", `[]`, true, "", 0},
		{"empty array with whitespace", " \r\n\t[ \n ]\n ", true, "", 0},
		{"whitespace between records", "[\n " + one + " ,\n\t" + two + "\r\n]", true, "", 2},
		{"data after the array", resultsArray(one, two) + ` x`, false, "", 2},
		{"a second array", resultsArray(one) + `[]`, false, "", 1},
		{"null element", `[null]`, false, "[0]", 0},
		{"number element", `[1]`, false, "[0]", 0},
		{"string element", `["` + testEmail + `"]`, false, "[0]", 0},
		{"null after a record", `[` + one + `,null]`, false, "[1]", 1},
		{"trailing comma", `[` + one + `,]`, false, "[1]", 1},
		{"missing comma", `[` + one + ` ` + two + `]`, false, "[1]", 1},
		{"not an array", `"` + testEmail + `"`, false, "", 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			c, _ := newScriptClient(t, jsonStep(tt.body))
			records, err := resultsRange(t.Context(), c, "")
			assert.Len(t, records, int(tt.records))
			if tt.ok {
				require.NoError(t, err)
				return
			}
			requireCallError(t, err, resultsFailure(bouncer.FailureMalformedResponse, tt.field, tt.records))
		})
	}
}

// TestResultsStringsWithBrackets checks that brackets, braces and escaped
// quotes inside strings never end a record early.
func TestResultsStringsWithBrackets(t *testing.T) {
	t.Parallel()
	tricky := `{"email":"avery.example@example.com","status":"risky","reason":"low_quality",` +
		`"didYouMean":"a]}b,[{c","provider":"x\"]}\"y","name":"back\\\\slash\\"}`
	c, _ := newScriptClient(t, jsonStep(resultsArray(tricky, resultsRecord("after"))))
	records, err := resultsRange(t.Context(), c, "")
	require.NoError(t, err)
	require.Len(t, records, 2)
	assert.Equal(t, "a]}b,[{c", records[0].DidYouMean)
	assert.Equal(t, `x"]}"y`, records[0].Provider)
	assert.Equal(t, `back\\slash\`, records[0].Name)
	assert.Equal(t, "after@example.com", records[1].Email)
}

// TestResultsPassDuplicatesThrough checks that duplicate records are yielded
// as the provider sends them: the SDK never deduplicates or correlates.
func TestResultsPassDuplicatesThrough(t *testing.T) {
	t.Parallel()
	c, _ := newScriptClient(t, jsonStep(resultsArray(verifyOK, verifyOK, verifyOK)))
	records, err := resultsRange(t.Context(), c, "")
	require.NoError(t, err)
	require.Len(t, records, 3)
	assert.Equal(t, records[0], records[1])
	assert.Equal(t, records[1], records[2])
}

// TestResultsByteCap checks WithMaxDownloadBytes on Results: an answer of
// exactly the cap is read, a declared length over it fails before any read,
// and an undeclared body over it fails as ErrResponseTooLarge after the
// records within the cap were yielded.
func TestResultsByteCap(t *testing.T) {
	t.Parallel()
	one, two, three := resultsRecord("one"), resultsRecord("two"), resultsRecord("three")
	full := resultsArray(one, two, three)

	t.Run("exactly the cap", func(t *testing.T) {
		t.Parallel()
		c := newClient(t, testutil.TransportWith(http.StatusOK, nil, -1, io.NopCloser(strings.NewReader(full))),
			bouncer.WithMaxDownloadBytes(int64(len(full))))
		records, err := resultsRange(t.Context(), c, "")
		require.NoError(t, err)
		assert.Len(t, records, 3)
	})

	t.Run("declared over the cap", func(t *testing.T) {
		t.Parallel()
		body := testutil.NewBody(full)
		c := newClient(t, testutil.TransportWith(http.StatusOK, nil, int64(len(full)), body),
			bouncer.WithMaxDownloadBytes(int64(len(full)-1)))
		records, err := resultsRange(t.Context(), c, "")
		assert.Empty(t, records)
		requireCallError(t, err, resultsFailure(bouncer.FailureResponseTooLarge, "", 0))
		assert.Zero(t, body.Reads(), "a declared length over the cap is refused before any read")
		assert.Equal(t, 1, body.Closes())
	})

	t.Run("undeclared over the cap", func(t *testing.T) {
		t.Parallel()
		limit := int64(len("[" + one + "," + two + ","))
		c := newClient(t, testutil.TransportWith(http.StatusOK, nil, -1, io.NopCloser(strings.NewReader(full))),
			bouncer.WithMaxDownloadBytes(limit))
		records, err := resultsRange(t.Context(), c, "")
		assert.Len(t, records, 2, "the records within the cap are yielded")
		requireCallError(t, err, resultsFailure(bouncer.FailureResponseTooLarge, "", 2))
	})

	t.Run("endless body", func(t *testing.T) {
		t.Parallel()
		body := &testutil.EndlessBody{}
		stream := io.MultiReader(strings.NewReader(`[`+one+`,{"pad":"`), body)
		c := newClient(t, testutil.TransportWith(http.StatusOK, nil, -1, io.NopCloser(stream)),
			bouncer.WithMaxDownloadBytes(1<<20))
		records, err := resultsRange(t.Context(), c, "")
		assert.Len(t, records, 1)
		requireCallError(t, err, resultsFailure(bouncer.FailureResponseTooLarge, "[1]", 1))
		assert.LessOrEqual(t, body.BytesRead(), int64(1<<20), "reading stops at the cap or the record bound")
	})
}

// TestResultsContentType checks the content-type gate of Results: JSON, a
// JSON type with parameters and no type at all are read; anything else is
// refused before any record.
func TestResultsContentType(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		header http.Header
		ok     bool
	}{
		{"application/json", http.Header{"Content-Type": {mediaJSON}}, true},
		{"with charset", http.Header{"Content-Type": {"application/json; charset=utf-8"}}, true},
		{"+json", http.Header{"Content-Type": {"application/vnd.example+json"}}, true},
		{"none", http.Header{}, true},
		{"text/csv", http.Header{"Content-Type": {mediaCSV}}, false},
		{"text/html", http.Header{"Content-Type": {mediaHTML}}, false},
		{"octet-stream", http.Header{"Content-Type": {mediaOctet}}, false},
		{"two types", http.Header{"Content-Type": {mediaJSON, mediaJSON}}, false},
		{"unparsable", http.Header{"Content-Type": {"application/"}}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			c, _ := newScriptClient(t, testutil.Step{Header: tt.header, Body: resultsOK})
			records, err := resultsRange(t.Context(), c, "")
			if tt.ok {
				require.NoError(t, err)
				assert.Len(t, records, 1)
				return
			}
			assert.Empty(t, records)
			requireCallError(t, err, resultsFailure(bouncer.FailureUnexpectedResponse, "", 0))
		})
	}
}

// TestResultsFailureEndsTheSequence checks failures that end a range of
// Results: the records before the failure are yielded, the error carries
// their count, and nothing after it arrives.
//   - A body that keeps answering nothing fails as a transport failure
//     instead of spinning, and is closed.
//   - HTTP 405, a batch that is not completed or whose results were removed,
//     is ErrBatchState with the batch ID, and no record.
//   - A record that fails to decode ends the sequence at once.
func TestResultsFailureEndsTheSequence(t *testing.T) {
	t.Parallel()
	stalled := testutil.NewBody("[" + resultsRecord("one") + ",")
	stalled.Stall = true
	bad := `{"email":"avery.example@example.com","status":"deliverable"}`
	notCompleted := resultsFailure(bouncer.FailureBatchState, "", 0)
	notCompleted.StatusCode, notCompleted.APIStatus = http.StatusMethodNotAllowed, http.StatusMethodNotAllowed
	tests := []struct {
		name    string
		rt      http.RoundTripper
		records int
		want    wantCall
		body    *testutil.Body // a body that must be closed exactly once
	}{
		{
			name: "stalled body", rt: testutil.TransportWith(http.StatusOK, nil, -1, stalled), body: stalled,
			records: 1, want: resultsFailure(bouncer.FailureTransport, "", 1),
		},
		{
			name: "batch not completed", records: 0, want: notCompleted,
			rt: testutil.NewScript(statusStep(http.StatusMethodNotAllowed, `{"status":405,"error":"Method Not Allowed"}`)),
		},
		{
			name: "record that fails to decode", records: 2,
			rt: testutil.NewScript(jsonStep(resultsArray(resultsRecord("one"), resultsRecord("two"), bad,
				resultsRecord("four")))),
			want: resultsFailure(bouncer.FailureMalformedResponse, "[2].reason", 2),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			records, err := resultsRange(t.Context(), newClient(t, tt.rt), bouncer.FilterRisky)
			assert.Len(t, records, tt.records)
			requireCallError(t, err, tt.want)
			if tt.body != nil {
				assert.Equal(t, 1, tt.body.Closes())
			}
		})
	}
}
