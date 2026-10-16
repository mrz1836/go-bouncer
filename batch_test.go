package bouncer_test

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/mrz1836/go-bouncer"
	"github.com/mrz1836/go-bouncer/internal/testutil"
)

// batchTestCreate makes a one-entry Create call.
func batchTestCreate(ctx context.Context, c *bouncer.Client) (*bouncer.Batch, error) {
	return c.Batches().Create(ctx, bouncer.CreateBatchRequest{Entries: []bouncer.BatchEntry{{Email: testEmail}}})
}

// batchTestQuery returns the query of the one request script recorded.
func batchTestQuery(t *testing.T, script *testutil.Script) url.Values {
	t.Helper()
	u, err := url.Parse(testutil.OnlyRequest(t, script).URL)
	require.NoError(t, err)
	return u.Query()
}

// TestCreateAcceptedStatusesDecodeTheFixture answers Create with each
// accepted status and the synthetic fixture, and checks every field.
func TestCreateAcceptedStatusesDecodeTheFixture(t *testing.T) {
	t.Parallel()
	fixture := string(testutil.Fixture(t, "synthetic/batch_created.json"))
	for _, status := range []int{http.StatusOK, http.StatusCreated, http.StatusAccepted} {
		t.Run(strconv.Itoa(status), func(t *testing.T) {
			t.Parallel()
			c, script := newScriptClient(t, statusStep(status, fixture))
			b, err := batchTestCreate(t.Context(), c)
			require.NoError(t, err)
			assert.Equal(t, &bouncer.Batch{
				ID:         testBatchID,
				State:      bouncer.BatchStateQueued,
				Created:    "2026-01-02T03:04:05.678Z",
				Quantity:   new(int64(2)),
				Duplicates: new(int64(0)),
			}, b)
			assert.Equal(t, 1, script.Calls())
		})
	}
}

// TestCreateKeepsTheBatchIDOfAnUnusableReply checks that a reply carrying a
// valid batchId but otherwise unusable fails as malformed with that ID in
// BatchID, so that the batch the provider created is not lost; and which
// replies cannot offer the ID at all.
func TestCreateKeepsTheBatchIDOfAnUnusableReply(t *testing.T) {
	t.Parallel()
	id := `"batchId":"` + string(testBatchID) + `"`
	tests := []struct {
		name    string
		body    string
		field   string
		batchID bouncer.BatchID
	}{
		{"missing status", `{` + id + `}`, "status", testBatchID},
		{"null status", `{` + id + `,"status":null}`, "status", testBatchID},
		{"empty status", `{` + id + `,"status":""}`, "status", testBatchID},
		{"status of the wrong type", `{` + id + `,"status":1}`, "status", testBatchID},
		{"counter of the wrong type", `{` + id + `,"status":"queued","quantity":"2"}`, "quantity", testBatchID},
		{"fractional counter", `{` + id + `,"status":"queued","duplicates":0.5}`, "duplicates", testBatchID},
		{"stats of the wrong type", `{` + id + `,"status":"queued","stats":[]}`, "stats", testBatchID},
		{"stats counter of the wrong type", `{` + id + `,"status":"queued","stats":{"risky":true}}`, "stats.risky", testBatchID},
		{"timestamp of the wrong type", `{` + id + `,"status":"queued","created":1700000000}`, "created", testBatchID},
		// Data after the object or invalid UTF-8 elsewhere does not hide the
		// batchId; an object that never ends has none to read.
		{"trailing garbage", `{` + id + `,"status":"queued"} x`, "", testBatchID},
		{"invalid UTF-8", `{` + id + `,"status":"qu` + "\xff" + `"}`, "", testBatchID},
		{"truncated object", `{` + id + `,"status":"que`, "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			c, script := newScriptClient(t, jsonStep(tt.body))
			b, err := batchTestCreate(t.Context(), c)
			assert.Nil(t, b)
			requireCallError(t, err, wantCall{
				Kind: bouncer.FailureMalformedResponse, Op: bouncer.OpBatchCreate, StatusCode: http.StatusOK,
				BatchID: tt.batchID, Field: tt.field,
			})
			assert.Equal(t, 1, script.Calls(), "never resubmitted")
		})
	}
}

// TestCreateUnusableReplyThatFailsToRead checks a Create reply that is
// unusable before its body is read, here for its content type, and whose body
// then fails to read: the call fails for the content type, and no batch ID
// can be offered.
func TestCreateUnusableReplyThatFailsToRead(t *testing.T) {
	t.Parallel()
	body := testutil.NewBody(`{"batchId":"` + string(testBatchID) + `"`)
	body.End = io.ErrUnexpectedEOF
	c := newClient(t, testutil.TransportWith(http.StatusOK, http.Header{"Content-Type": {mediaHTML}}, -1, body))
	b, err := batchTestCreate(t.Context(), c)
	assert.Nil(t, b)
	requireCallError(t, err, wantCall{Kind: bouncer.FailureUnexpectedResponse, Op: bouncer.OpBatchCreate, StatusCode: http.StatusOK})
	assert.Equal(t, 1, body.Closes())
}

// TestCreateRefusesAnInvalidBatchID checks that a reply whose batchId is not
// a usable batch handle fails at "batchId" without offering it.
func TestCreateRefusesAnInvalidBatchID(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		value string
	}{
		{"slash", `"a/b"`},
		{"empty", `""`},
		{"129 bytes", `"` + strings.Repeat("f", 129) + `"`},
		{"number", `42`},
		{"null", `null`},
		{"sync", `"sync"`},
		{"space", `"a b"`},
		{"non-ASCII", `"ä1"`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			c, _ := newScriptClient(t, jsonStep(`{"batchId":`+tt.value+`,"status":"queued"}`))
			_, err := batchTestCreate(t.Context(), c)
			ce := requireCallError(t, err, wantCall{
				Kind: bouncer.FailureMalformedResponse, Op: bouncer.OpBatchCreate, StatusCode: http.StatusOK,
				Field: "batchId",
			})
			assert.Empty(t, ce.BatchID)
		})
	}
}

// TestCreateIsNeverResubmitted answers Create with one failure of each kind
// and checks that the SDK made exactly one attempt, whatever the outcome.
func TestCreateIsNeverResubmitted(t *testing.T) {
	t.Parallel()
	steps := map[string]testutil.Step{
		"transport":           {Err: io.ErrUnexpectedEOF},
		"timeout":             {Err: testutil.TimeoutError{}},
		"400":                 statusStep(http.StatusBadRequest, `{"status":400}`),
		"402":                 statusStep(http.StatusPaymentRequired, `{"status":"402"}`),
		"429":                 statusStep(http.StatusTooManyRequests, `{}`),
		"500":                 statusStep(http.StatusInternalServerError, `{}`),
		"503":                 statusStep(http.StatusServiceUnavailable, `{}`),
		"envelope in a 200":   jsonStep(`{"status":402,"error":"Payment Required"}`),
		"unexpected 2xx":      statusStep(http.StatusNoContent, ``),
		"malformed":           jsonStep(`{"batchId":`),
		"wrong content type":  {Header: http.Header{"Content-Type": {mediaHTML}}, Body: batchQueued},
		"redirect":            {Status: http.StatusTemporaryRedirect, Header: http.Header{"Location": {"/elsewhere"}}},
		"oversized":           jsonStep(`{"batchId":"` + string(testBatchID) + `","status":"` + strings.Repeat("q", 1<<20) + `"}`),
		"unusable with an ID": jsonStep(`{"batchId":"` + string(testBatchID) + `"}`),
	}
	for name, step := range steps {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			c, script := newScriptClient(t, step, jsonStep(batchQueued))
			b, err := batchTestCreate(t.Context(), c)
			require.Error(t, err)
			assert.Nil(t, b)
			assert.Equal(t, 1, script.Calls(), "one attempt, never a resubmission")
		})
	}
}

// TestCreateCallbackQuery checks that callback is sent only when set, and
// that the batch body and the call are otherwise the same.
func TestCreateCallbackQuery(t *testing.T) {
	t.Parallel()
	t.Run("unset", func(t *testing.T) {
		t.Parallel()
		c, script := newScriptClient(t, jsonStep(batchQueued))
		_, err := batchTestCreate(t.Context(), c)
		require.NoError(t, err)
		assert.Empty(t, testutil.OnlyRequest(t, script).URL[len(loopbackOrigin+pathBatch):], "no query at all")
	})
	t.Run("set", func(t *testing.T) {
		t.Parallel()
		c, script := newScriptClient(t, jsonStep(batchQueued))
		_, err := c.Batches().Create(t.Context(), bouncer.CreateBatchRequest{
			Entries: []bouncer.BatchEntry{{Email: testEmail}}, CallbackURL: testCallback,
		})
		require.NoError(t, err)
		q := batchTestQuery(t, script)
		assert.Equal(t, url.Values{"callback": {testCallback}}, q)
	})
}

// TestCreateBatchRequestPrintsItsShapeOnly checks that no fmt verb prints a
// request's addresses, names or callback URL, only its shape.
func TestCreateBatchRequestPrintsItsShapeOnly(t *testing.T) {
	t.Parallel()
	req := bouncer.CreateBatchRequest{
		Entries: []bouncer.BatchEntry{
			{Email: testEmail, Name: testName}, {Email: testEmail2},
		},
		CallbackURL: testCallback,
	}
	const want = "{entries: 2, names: 1, callbackURL: set}"
	assert.Equal(t, want, req.String())
	assert.Equal(t, want, req.GoString())
	for _, verb := range testutil.FormatVerbs() {
		if verb == "%p" {
			continue // a pointer verb on a struct value prints a bad-verb notice by reflection
		}
		assert.Equal(t, want, fmt.Sprintf(verb, req), "verb %s on the value", verb)
		assert.Equal(t, want, fmt.Sprintf(verb, &req), "verb %s on the pointer", verb)
	}
	for _, verb := range testutil.FormatVerbs() {
		if verb != "%p" {
			testutil.AssertRedacted(t, fmt.Sprintf(verb, req), markers(), "verb %s on the value", verb)
		}
		testutil.AssertRedacted(t, fmt.Sprintf(verb, []bouncer.CreateBatchRequest{req}), markers(), "verb %s on a slice", verb)
	}
	testutil.AssertNeverPrints(t, &req, markers()...)

	// The one gap fmt leaves: %p on a struct value is a bad verb, which fmt
	// prints by reflection without calling Format. The README tells callers
	// not to print requests that way.
	assert.True(t, strings.HasPrefix(fmt.Sprintf("%p", req), "%!p(bouncer.CreateBatchRequest="))

	assert.Equal(t, "{entries: 0, names: 0, callbackURL: unset}", bouncer.CreateBatchRequest{}.String())
}

// TestStatusDecodesTheFixture checks every field of a completed status with
// stats, timestamps kept as received.
func TestStatusDecodesTheFixture(t *testing.T) {
	t.Parallel()
	c, script := newScriptClient(t, jsonStep(string(testutil.Fixture(t, "synthetic/batch_status_completed.json"))))
	st, err := c.Batches().Status(t.Context(), bouncer.BatchStatusRequest{BatchID: testBatchID, WithStats: true})
	require.NoError(t, err)
	assert.Equal(t, &bouncer.Batch{
		ID:          testBatchID,
		State:       bouncer.BatchStateCompleted,
		Created:     "2026-01-02T03:04:05.678Z",
		Started:     "2026-01-02T03:04:06.789Z",
		Completed:   "2026-01-02T03:09:10.111Z",
		Quantity:    new(int64(2)),
		Duplicates:  new(int64(0)),
		CreditsUsed: new(int64(2)),
		Processed:   new(int64(2)),
		Stats: &bouncer.BatchStats{
			Deliverable: new(int64(1)), Risky: new(int64(1)), Undeliverable: new(int64(0)), Unknown: new(int64(0)),
		},
	}, st)
	assert.True(t, st.State.Terminal())
	completed, ok := st.Completed.Time()
	require.True(t, ok)
	assert.Equal(t, time.Date(2026, 1, 2, 3, 9, 10, 111_000_000, time.UTC), completed)
	assert.Equal(t, url.Values{"with-stats": {"true"}}, batchTestQuery(t, script))
}

// TestStatusStates checks that every state is kept as received, documented or
// not.
func TestStatusStates(t *testing.T) {
	t.Parallel()
	tests := []struct {
		state    bouncer.BatchState
		known    bool
		terminal bool
	}{
		{bouncer.BatchStateQueued, true, false},
		{bouncer.BatchStateProcessing, true, false},
		{bouncer.BatchStateCompleted, true, true},
		{"paused", false, false},
		{"COMPLETED", false, false},
		{"finished", false, false},
	}
	for _, tt := range tests {
		t.Run(string(tt.state), func(t *testing.T) {
			t.Parallel()
			c, _ := newScriptClient(t, jsonStep(`{"batchId":"`+string(testBatchID)+`","status":"`+string(tt.state)+`"}`))
			st, err := c.Batches().Status(t.Context(), bouncer.BatchStatusRequest{BatchID: testBatchID})
			require.NoError(t, err)
			assert.Equal(t, tt.state, st.State)
			assert.Equal(t, tt.known, st.State.Known())
			assert.Equal(t, tt.terminal, st.State.Terminal())
		})
	}
}

// TestStatusWithStatsIsAlwaysSent checks the with-stats query for both
// values, and that stats are decoded whenever present.
func TestStatusWithStatsIsAlwaysSent(t *testing.T) {
	t.Parallel()
	withStats := `{"batchId":"` + string(testBatchID) + `","status":"processing","processed":1,` +
		`"stats":{"deliverable":1,"risky":0,"undeliverable":0,"unknown":0}}`
	for _, ws := range []bool{false, true} {
		t.Run(strconv.FormatBool(ws), func(t *testing.T) {
			t.Parallel()
			c, script := newScriptClient(t, jsonStep(withStats))
			st, err := c.Batches().Status(t.Context(), bouncer.BatchStatusRequest{BatchID: testBatchID, WithStats: ws})
			require.NoError(t, err)
			assert.Equal(t, url.Values{"with-stats": {strconv.FormatBool(ws)}}, batchTestQuery(t, script))
			require.NotNil(t, st.Stats, "stats are decoded whenever the provider sends them")
			assert.Equal(t, new(int64(1)), st.Processed)
		})
	}
	t.Run("without stats in the answer", func(t *testing.T) {
		t.Parallel()
		c, _ := newScriptClient(t, jsonStep(batchProcessing))
		st, err := c.Batches().Status(t.Context(), bouncer.BatchStatusRequest{BatchID: testBatchID, WithStats: true})
		require.NoError(t, err)
		assert.Nil(t, st.Stats)
		assert.Nil(t, st.Processed)
	})
}

// TestStatusCounters checks that an absent or null counter is nil and a
// reported zero is a pointer to 0.
func TestStatusCounters(t *testing.T) {
	t.Parallel()
	members := []struct {
		name string
		get  func(*bouncer.Batch) *int64
	}{
		{"quantity", func(b *bouncer.Batch) *int64 { return b.Quantity }},
		{"duplicates", func(b *bouncer.Batch) *int64 { return b.Duplicates }},
		{"credits", func(b *bouncer.Batch) *int64 { return b.CreditsUsed }},
		{"processed", func(b *bouncer.Batch) *int64 { return b.Processed }},
	}
	for _, m := range members {
		for _, tt := range []struct {
			name string
			raw  string
			want *int64
		}{
			{"absent", "", nil},
			{"null", "null", nil},
			{"zero", "0", new(int64(0))},
			{"large", "9007199254740993", new(int64(9007199254740993))},
		} {
			t.Run(m.name+"/"+tt.name, func(t *testing.T) {
				t.Parallel()
				body := `{"batchId":"` + string(testBatchID) + `","status":"queued"`
				if tt.raw != "" {
					body += `,"` + m.name + `":` + tt.raw
				}
				c, _ := newScriptClient(t, jsonStep(body+`}`))
				st, err := c.Batches().Status(t.Context(), bouncer.BatchStatusRequest{BatchID: testBatchID})
				require.NoError(t, err)
				assert.Equal(t, tt.want, m.get(st))
			})
		}
	}
}

// TestStatusForAnotherBatch checks that an answer naming another batch is
// unexpected, reported for the requested batch.
func TestStatusForAnotherBatch(t *testing.T) {
	t.Parallel()
	for _, other := range []string{"5f0c2b9e8d7a6b5c4d3e2f1b", strings.ToUpper(string(testBatchID)), string(testBatchID) + "0"} {
		t.Run(other, func(t *testing.T) {
			t.Parallel()
			c, _ := newScriptClient(t, jsonStep(`{"batchId":"`+other+`","status":"completed"}`))
			st, err := c.Batches().Status(t.Context(), bouncer.BatchStatusRequest{BatchID: testBatchID})
			assert.Nil(t, st)
			requireCallError(t, err, wantCall{
				Kind: bouncer.FailureUnexpectedResponse, Op: bouncer.OpBatchStatus, StatusCode: http.StatusOK,
				BatchID: testBatchID, Field: "batchId",
			})
		})
	}
}

// TestFinishAndDelete checks both control calls' outcomes for a missing
// batch, a batch in the wrong state and a success.
func TestFinishAndDelete(t *testing.T) {
	t.Parallel()
	calls := []struct {
		name   string
		op     bouncer.Operation
		method string
		path   string
		call   func(ctx context.Context, c *bouncer.Client) error
	}{
		{"Finish", bouncer.OpBatchFinish, http.MethodPost, pathFinish, func(ctx context.Context, c *bouncer.Client) error {
			return c.Batches().Finish(ctx, bouncer.FinishBatchRequest{BatchID: testBatchID})
		}},
		{"Delete", bouncer.OpBatchDelete, http.MethodDelete, pathBatchID, func(ctx context.Context, c *bouncer.Client) error {
			return c.Batches().Delete(ctx, bouncer.DeleteBatchRequest{BatchID: testBatchID})
		}},
	}
	for _, call := range calls {
		t.Run(call.name+"/404", func(t *testing.T) {
			t.Parallel()
			c, script := newScriptClient(t, statusStep(http.StatusNotFound, `{"status":"404","error":"Not Found"}`))
			requireCallError(t, call.call(t.Context(), c), wantCall{
				Kind: bouncer.FailureNotFound, Op: call.op, StatusCode: http.StatusNotFound, APIStatus: 404,
				BatchID: testBatchID,
			})
			assert.Equal(t, 1, script.Calls())
		})
		t.Run(call.name+"/405", func(t *testing.T) {
			t.Parallel()
			c, script := newScriptClient(t, statusStep(http.StatusMethodNotAllowed, `{"status":405}`))
			requireCallError(t, call.call(t.Context(), c), wantCall{
				Kind: bouncer.FailureBatchState, Op: call.op, StatusCode: http.StatusMethodNotAllowed, APIStatus: 405,
				BatchID: testBatchID,
			})
			assert.Equal(t, 1, script.Calls())
		})
		for _, ok := range []testutil.Step{
			statusStep(http.StatusOK, `{}`),
			statusStep(http.StatusAccepted, `{}`),
			{Status: http.StatusNoContent},
		} {
			t.Run(call.name+"/success "+strconv.Itoa(ok.Status), func(t *testing.T) {
				t.Parallel()
				c, script := newScriptClient(t, ok)
				require.NoError(t, call.call(t.Context(), c))
				req := testutil.OnlyRequest(t, script)
				assert.Equal(t, call.method, req.Method)
				assert.Equal(t, call.path, req.Path)
			})
		}
	}
}

// batchTestFailures are answers that fail a read call in every way.
func batchTestFailures() map[string]testutil.Step {
	return map[string]testutil.Step{
		"transport":         {Err: io.ErrUnexpectedEOF},
		"timeout":           {Err: testutil.TimeoutError{}},
		"404":               statusStep(http.StatusNotFound, `{}`),
		"405":               statusStep(http.StatusMethodNotAllowed, `{}`),
		"429":               statusStep(http.StatusTooManyRequests, `{}`),
		"500":               statusStep(http.StatusInternalServerError, `{}`),
		"503":               statusStep(http.StatusServiceUnavailable, `{}`),
		"envelope in a 200": jsonStep(`{"status":400,"error":"Bad Request"}`),
		"malformed":         jsonStep(`[{"email":`),
		"unknown state":     jsonStep(`{"batchId":"` + string(testBatchID) + `","status":"paused"}`),
		"wrong type":        {Header: http.Header{"Content-Type": {mediaHTML}}, Body: `<html></html>`},
		"redirect":          {Status: http.StatusFound},
	}
}

// TestReadCallsNeverChangeABatch fails every read call (Status, Wait, Results,
// Download) in each way and checks that the SDK only ever read: nothing is
// created, finished or deleted on a failure.
func TestReadCallsNeverChangeABatch(t *testing.T) {
	t.Parallel()
	reads := []struct {
		name string
		call func(ctx context.Context, c *bouncer.Client) error
	}{
		{"Status", func(ctx context.Context, c *bouncer.Client) error {
			return noValue(c.Batches().Status(ctx, bouncer.BatchStatusRequest{BatchID: testBatchID, WithStats: true}))
		}},
		{"Wait", func(ctx context.Context, c *bouncer.Client) error {
			_, err := c.Batches().Wait(ctx, bouncer.WaitBatchRequest{BatchID: testBatchID, Interval: time.Second, MaxWait: time.Hour})
			return err
		}},
		{"Results", func(ctx context.Context, c *bouncer.Client) error {
			_, err := collect(c.Batches().Results(ctx, bouncer.BatchResultsRequest{BatchID: testBatchID}))
			return err
		}},
		{"Download", func(ctx context.Context, c *bouncer.Client) error {
			var w bytes.Buffer
			_, err := c.Batches().Download(ctx, bouncer.DownloadBatchRequest{BatchID: testBatchID, Format: bouncer.FormatJSON}, &w)
			return err
		}},
	}
	for _, read := range reads {
		for name, step := range batchTestFailures() {
			t.Run(read.name+"/"+name, func(t *testing.T) {
				t.Parallel()
				c, script := newScriptClient(t, step, step, step)
				ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
				defer cancel()
				err := read.call(ctx, c)
				if name != "unknown state" || read.name == "Wait" {
					require.Error(t, err)
				}
				require.NotZero(t, script.Calls())
				for _, r := range script.Requests() {
					assert.Equal(t, http.MethodGet, r.Method, "only reads, never POST or DELETE")
					assert.NotEqual(t, pathFinish, r.Path)
					assert.NotEqual(t, pathBatch, r.Path)
				}
			})
		}
	}
}

// TestTimestampTime checks the parse helper on the documented shape.
func TestTimestampTime(t *testing.T) {
	t.Parallel()
	tests := []struct {
		in   bouncer.Timestamp
		want time.Time // the zero Time when the timestamp must not parse
	}{
		{"2026-01-02T03:04:05.678Z", time.Date(2026, 1, 2, 3, 4, 5, 678_000_000, time.UTC)},
		{"2026-01-02T03:04:05Z", time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)}, // fractional seconds are optional
		{"2026-01-02T03:04:05+02:00", time.Date(2026, 1, 2, 1, 4, 5, 0, time.UTC)},
		{"", time.Time{}},
		{"garbage", time.Time{}},
		{"02/01/2026", time.Time{}},
		{"2026-01-02", time.Time{}},
		{"2026-01-02 03:04:05", time.Time{}},
		{"2026-01-02T03:04:05.678", time.Time{}}, // no zone
	}
	for _, tt := range tests {
		t.Run(string(tt.in), func(t *testing.T) {
			t.Parallel()
			got, ok := tt.in.Time()
			assert.Equal(t, !tt.want.IsZero(), ok)
			assert.True(t, tt.want.Equal(got), "got %v", got)
		})
	}
}

// TestBatchesReturnsUsableCopies checks that BatchService values are
// independent copies that keep working, and that copying one is harmless.
func TestBatchesReturnsUsableCopies(t *testing.T) {
	t.Parallel()
	c, script := newScriptClient(t, jsonStep(batchCompleted), jsonStep(batchCompleted))
	first := c.Batches()
	second := first
	_, err := first.Status(t.Context(), bouncer.BatchStatusRequest{BatchID: testBatchID})
	require.NoError(t, err)
	_, err = second.Status(t.Context(), bouncer.BatchStatusRequest{BatchID: testBatchID})
	require.NoError(t, err)
	assert.Equal(t, c.Batches(), first)
	assert.Equal(t, 2, script.Calls())
}

// TestStatusBatchIDRoundTrip checks that IDs needing path escaping reach the
// server as one segment that decodes to the ID, and that non-ASCII IDs are
// refused locally.
func TestStatusBatchIDRoundTrip(t *testing.T) {
	t.Parallel()
	for _, id := range []bouncer.BatchID{`a"b`, "a[b]", "a:b@c", "x=y&z"} {
		t.Run(string(id), func(t *testing.T) {
			t.Parallel()
			c, srv := newServerClient(t, testutil.HTTP1, func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", mediaJSON)
				_, _ = fmt.Fprintf(w, `{"batchId":%q,"status":"queued"}`, string(id))
			})
			st, err := c.Batches().Status(t.Context(), bouncer.BatchStatusRequest{BatchID: id})
			require.NoError(t, err)
			assert.Equal(t, id, st.ID)
			assert.Equal(t, pathBatch+"/"+string(id), testutil.OnlyRequest(t, srv).Path, "one segment that decodes to the ID")
		})
	}
	t.Run("non-ASCII", func(t *testing.T) {
		t.Parallel()
		counter := &testutil.CountingTransport{Next: testutil.StaticTransport(http.StatusOK, batchQueued)}
		c := newClient(t, counter)
		_, err := c.Batches().Status(t.Context(), bouncer.BatchStatusRequest{BatchID: "ä"})
		requireValidation(t, err, bouncer.ErrInvalidRequest, "BatchID", reasonInvalidFormat)
		assert.Zero(t, counter.Attempts())
	})
}

// TestStatusAnswerForAnInvalidBatchID checks that a Status answer whose
// batchId is not even a usable handle counts as another batch's answer
// (unexpected), as any batchId other than the one requested does.
func TestStatusAnswerForAnInvalidBatchID(t *testing.T) {
	t.Parallel()
	for _, id := range []string{"a/b", "sync", "..", "5f0c2b9e8d7a6b5c4d3e2f1a0"} {
		t.Run(id, func(t *testing.T) {
			t.Parallel()
			c, _ := newScriptClient(t, jsonStep(`{"batchId":"`+id+`","status":"queued"}`))
			_, err := c.Batches().Status(t.Context(), bouncer.BatchStatusRequest{BatchID: testBatchID})
			requireCallError(t, err, wantCall{
				Kind: bouncer.FailureUnexpectedResponse, Op: bouncer.OpBatchStatus, StatusCode: http.StatusOK,
				BatchID: testBatchID, Field: "batchId",
			})
		})
	}
}

// TestCreateKeepsTheBatchIDBehindAnUnusableEnvelope checks that an error
// envelope in a 2xx that still names a valid batchId reports it.
func TestCreateKeepsTheBatchIDBehindAnUnusableEnvelope(t *testing.T) {
	t.Parallel()
	c, _ := newScriptClient(t, statusStep(http.StatusAccepted, `{"status":500,"batchId":"`+string(testBatchID)+`"}`))
	_, err := batchTestCreate(t.Context(), c)
	requireCallError(t, err, wantCall{
		Kind: bouncer.FailureUpstream, Op: bouncer.OpBatchCreate, StatusCode: http.StatusAccepted, APIStatus: 500,
		BatchID: testBatchID,
	})
}
