package bouncer_test

import (
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/mrz1836/go-bouncer"
	"github.com/mrz1836/go-bouncer/internal/testutil"
)

// syncTestRecord returns a minimal verification record for email.
func syncTestRecord(email string, status bouncer.Status) string {
	return `{"email":"` + email + `","status":"` + string(status) + `","reason":"accepted_email"}`
}

// syncTestEmails returns n distinct synthetic addresses, padded to at least
// width bytes when width is not 0.
func syncTestEmails(n, width int) []string {
	out := make([]string, n)
	for i := range out {
		local := "user" + strconv.Itoa(i)
		if pad := width - len(local) - len("@example.com"); pad > 0 {
			local += strings.Repeat("x", pad)
		}
		out[i] = local + "@example.com"
	}
	return out
}

// TestSyncPartialFixture checks the documented partial answer: two addresses
// in, one result out.
func TestSyncPartialFixture(t *testing.T) {
	t.Parallel()
	c, script := newScriptClient(t, jsonStep(string(testutil.Fixture(t, "synthetic/sync_partial.json"))))
	res, err := c.VerifyBatchSync(t.Context(), bouncer.BatchSyncRequest{Emails: []string{testEmail, testEmail2}})
	require.NoError(t, err)
	assert.Equal(t, 2, res.Requested)
	require.Len(t, res.Available, 1, "only what the provider already had")
	assert.Equal(t, testEmail, res.Available[0].Email)
	assert.Equal(t, bouncer.StatusDeliverable, res.Available[0].Status)
	assert.Equal(t, new(88), res.Available[0].Score)
	assert.Equal(t, 1, script.Calls(), "no drain loop, no follow-up call")
}

// TestSyncKeepsWhatTheProviderSent checks that results are kept in the
// provider's order, duplicates included, and that more results than
// requested are all kept: paid results are never discarded.
func TestSyncKeepsWhatTheProviderSent(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		emails []string
		answer []string
		want   []string
	}{
		{
			name:   "provider order",
			emails: []string{testEmail, testEmail2, "casey.example@example.org"},
			answer: []string{"casey.example@example.org", testEmail},
			want:   []string{"casey.example@example.org", testEmail},
		},
		{
			name:   "duplicates sent and passed through",
			emails: []string{testEmail, testEmail},
			answer: []string{testEmail, testEmail},
			want:   []string{testEmail, testEmail},
		},
		{
			name:   "more results than requested",
			emails: []string{testEmail},
			answer: []string{testEmail, testEmail2, testEmail},
			want:   []string{testEmail, testEmail2, testEmail},
		},
		{
			name:   "nothing available yet",
			emails: []string{testEmail, testEmail2},
			answer: nil,
			want:   nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			records := make([]string, len(tt.answer))
			for i, email := range tt.answer {
				records[i] = syncTestRecord(email, bouncer.StatusRisky)
			}
			c, script := newScriptClient(t, jsonStep("["+strings.Join(records, ",")+"]"))
			res, err := c.VerifyBatchSync(t.Context(), bouncer.BatchSyncRequest{Emails: tt.emails})
			require.NoError(t, err)
			assert.Equal(t, len(tt.emails), res.Requested)
			got := make([]string, 0, len(res.Available))
			for _, v := range res.Available {
				got = append(got, v.Email)
			}
			if tt.want == nil {
				assert.Empty(t, res.Available)
			} else {
				assert.Equal(t, tt.want, got)
			}

			var sent []string
			require.NoError(t, json.Unmarshal(testutil.OnlyRequest(t, script).Body, &sent))
			assert.Equal(t, tt.emails, sent, "sent in order, duplicates included")
		})
	}
}

// TestSyncRequestBounds checks the local limits: 10,000 addresses are sent,
// 10,001 are refused, and so is a body over 8 MiB, both without any I/O.
func TestSyncRequestBounds(t *testing.T) {
	t.Parallel()
	t.Run("10,000 addresses", func(t *testing.T) {
		t.Parallel()
		emails := syncTestEmails(bouncer.MaxSyncEmails, 0)
		c, script := newScriptClient(t, jsonStep(`[]`))
		res, err := c.VerifyBatchSync(t.Context(), bouncer.BatchSyncRequest{Emails: emails})
		require.NoError(t, err)
		assert.Equal(t, bouncer.MaxSyncEmails, res.Requested)
		var sent []string
		require.NoError(t, json.Unmarshal(testutil.OnlyRequest(t, script).Body, &sent))
		assert.Len(t, sent, bouncer.MaxSyncEmails)
	})
	t.Run("10,001 addresses", func(t *testing.T) {
		t.Parallel()
		counter := &testutil.CountingTransport{Next: testutil.StaticTransport(http.StatusOK, `[]`)}
		c := newClient(t, counter)
		_, err := c.VerifyBatchSync(t.Context(), bouncer.BatchSyncRequest{Emails: syncTestEmails(bouncer.MaxSyncEmails+1, 0)})
		requireValidation(t, err, bouncer.ErrInvalidRequest, "Emails", reasonTooMany)
		assert.Zero(t, counter.Attempts())
	})
	t.Run("body over 8 MiB", func(t *testing.T) {
		t.Parallel()
		emails := syncTestEmails(bouncer.MaxSyncEmails, 900)
		require.LessOrEqual(t, len(emails[len(emails)-1]), bouncer.MaxEmailBytes, "each address is valid on its own")
		counter := &testutil.CountingTransport{Next: testutil.StaticTransport(http.StatusOK, `[]`)}
		c := newClient(t, counter)
		_, err := c.VerifyBatchSync(t.Context(), bouncer.BatchSyncRequest{Emails: emails})
		requireValidation(t, err, bouncer.ErrInvalidRequest, "Emails", "too_large")
		assert.Zero(t, counter.Attempts())
	})
}

// TestSyncFailures checks the documented refusals and the answers that are
// not an array of records.
func TestSyncFailures(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		step testutil.Step
		want wantCall
	}{
		{
			name: "400 too many",
			step: statusStep(http.StatusBadRequest, `{"status":"404","error":"Bad Request","message":"synthetic: too many"}`),
			want: wantCall{Kind: bouncer.FailureRejected, StatusCode: http.StatusBadRequest, APIStatus: 404},
		},
		{
			name: "402",
			step: statusStep(http.StatusPaymentRequired, string(testutil.Fixture(t, "synthetic/envelope_payment.json"))),
			want: wantCall{Kind: bouncer.FailurePaymentRequired, StatusCode: http.StatusPaymentRequired, APIStatus: 402},
		},
		{
			name: "429",
			step: statusStep(http.StatusTooManyRequests, `{}`),
			want: wantCall{Kind: bouncer.FailureRateLimited, StatusCode: http.StatusTooManyRequests},
		},
		{
			name: "object that is not an envelope",
			step: jsonStep(syncTestRecord(testEmail, bouncer.StatusDeliverable)),
			want: wantCall{Kind: bouncer.FailureUnexpectedResponse, StatusCode: http.StatusOK},
		},
		{
			name: "envelope in a 200",
			step: jsonStep(`{"status":429,"error":"Too Many Requests"}`),
			want: wantCall{Kind: bouncer.FailureRateLimited, StatusCode: http.StatusOK, APIStatus: 429},
		},
		{
			name: "malformed record mid-array",
			step: jsonStep(`[` + syncTestRecord(testEmail, bouncer.StatusRisky) + `,` +
				`{"email":"` + testEmail2 + `","status":"risky","reason":"low_quality","score":"87"}]`),
			want: wantCall{Kind: bouncer.FailureMalformedResponse, StatusCode: http.StatusOK, Field: "[1].score"},
		},
		{
			name: "truncated array",
			step: jsonStep(`[` + syncTestRecord(testEmail, bouncer.StatusRisky) + `,`),
			want: wantCall{Kind: bouncer.FailureMalformedResponse, StatusCode: http.StatusOK, Field: "[1]"},
		},
		{
			name: "trailing data",
			step: jsonStep(`[` + syncTestRecord(testEmail, bouncer.StatusRisky) + `] []`),
			want: wantCall{Kind: bouncer.FailureMalformedResponse, StatusCode: http.StatusOK},
		},
		{
			name: "null instead of a record",
			step: jsonStep(`[null]`),
			want: wantCall{Kind: bouncer.FailureMalformedResponse, StatusCode: http.StatusOK, Field: "[0]"},
		},
		{
			name: "a string",
			step: jsonStep(`"queued"`),
			want: wantCall{Kind: bouncer.FailureMalformedResponse, StatusCode: http.StatusOK},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			c, script := newScriptClient(t, tt.step)
			res, err := c.VerifyBatchSync(t.Context(), bouncer.BatchSyncRequest{Emails: []string{testEmail, testEmail2}})
			assert.Nil(t, res, "no partial result on failure")
			tt.want.Op = bouncer.OpBatchSync
			requireCallError(t, err, tt.want)
			assert.Equal(t, 1, script.Calls(), "never resubmitted")
		})
	}
}

// syncTestLargeArray returns an answer of at least size bytes: an array of
// records padded with a provider name.
func syncTestLargeArray(size int) string {
	record := `{"email":"` + testEmail + `","status":"deliverable","reason":"accepted_email","provider":"` +
		strings.Repeat("p", 200) + `"}`
	n := size/(len(record)+1) + 1
	return "[" + strings.TrimSuffix(strings.Repeat(record+",", n), ",") + "]"
}

// TestSyncResponseLimit checks that batch-sync answers are bounded by
// WithMaxResponseBytes, not by the 1 MiB cap of the other buffered calls.
func TestSyncResponseLimit(t *testing.T) {
	t.Parallel()
	body := syncTestLargeArray(2 << 20)
	require.Greater(t, len(body), 2<<20)

	t.Run("default limit", func(t *testing.T) {
		t.Parallel()
		c, _ := newScriptClient(t, jsonStep(body))
		res, err := c.VerifyBatchSync(t.Context(), bouncer.BatchSyncRequest{Emails: []string{testEmail}})
		require.NoError(t, err)
		assert.Len(t, res.Available, strings.Count(body, `"email"`), "every record of the 2 MiB answer")
		assert.Equal(t, 1, res.Requested)
	})
	t.Run("1 MiB limit", func(t *testing.T) {
		t.Parallel()
		s := testutil.NewScript(jsonStep(body))
		c := newClient(t, s, bouncer.WithMaxResponseBytes(1<<20))
		_, err := c.VerifyBatchSync(t.Context(), bouncer.BatchSyncRequest{Emails: []string{testEmail}})
		requireCallError(t, err, wantCall{
			Kind: bouncer.FailureResponseTooLarge, Op: bouncer.OpBatchSync, StatusCode: http.StatusOK,
		})
	})
	t.Run("undeclared length over the limit", func(t *testing.T) {
		t.Parallel()
		c := newClient(t, testutil.Transport(http.StatusOK, -1, func() io.ReadCloser {
			return io.NopCloser(strings.NewReader(body))
		}), bouncer.WithMaxResponseBytes(1<<20))
		_, err := c.VerifyBatchSync(t.Context(), bouncer.BatchSyncRequest{Emails: []string{testEmail}})
		requireCallError(t, err, wantCall{
			Kind: bouncer.FailureResponseTooLarge, Op: bouncer.OpBatchSync, StatusCode: http.StatusOK,
		})
	})
}

// TestBatchSyncResultJSON checks the JSON names of a result and a round
// trip.
func TestBatchSyncResultJSON(t *testing.T) {
	t.Parallel()
	res := bouncer.BatchSyncResult{
		Requested: 2,
		Available: []bouncer.Verification{{
			Email: testEmail, Status: bouncer.StatusDeliverable, Reason: bouncer.ReasonAcceptedEmail, Score: new(0),
		}},
	}
	data, err := json.Marshal(res)
	require.NoError(t, err)
	assert.JSONEq(t, `{"requested":2,"available":[{"email":"avery.example@example.com","status":"deliverable",`+
		`"reason":"accepted_email","score":0}]}`, string(data))
	var back bouncer.BatchSyncResult
	require.NoError(t, json.Unmarshal(data, &back))
	assert.Equal(t, res, back)

	empty, err := json.Marshal(bouncer.BatchSyncResult{Requested: 3})
	require.NoError(t, err)
	assert.JSONEq(t, `{"requested":3}`, string(empty), "no results: available omitted")
}
