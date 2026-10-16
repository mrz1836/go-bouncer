package bouncer

import (
	"context"
	"io"
	"maps"
	"net/http"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/mrz1836/go-bouncer/internal/testutil"
)

// shapeBatch is the batch every shape case names.
const shapeBatch BatchID = "5f0c2b9e8d7a6b5c4d3e2f1a"

// shapeSeen is a request as the RoundTripper received it, before anything
// read its body.
type shapeSeen struct {
	req     *http.Request
	header  http.Header // the very map the request carried
	body    []byte
	noBody  bool
	nilBody bool
}

// shapeRecorder records every request it receives and answers each with the
// next answer.
type shapeRecorder struct {
	mu      sync.Mutex
	seen    []shapeSeen
	answers []testutil.Step
}

// RoundTrip records r and answers it.
func (s *shapeRecorder) RoundTrip(r *http.Request) (*http.Response, error) {
	rec := shapeSeen{req: r, header: r.Header, noBody: r.Body == http.NoBody, nilBody: r.Body == nil}
	if r.Body != nil {
		rec.body, _ = io.ReadAll(r.Body)
		_ = r.Body.Close()
	}
	s.mu.Lock()
	i := len(s.seen)
	s.seen = append(s.seen, rec)
	step := testutil.Step{Status: http.StatusInternalServerError}
	if i < len(s.answers) {
		step = s.answers[i]
	}
	s.mu.Unlock()
	status := step.Status
	if status == 0 {
		status = http.StatusOK
	}
	resp := testutil.Response(r, status, io.NopCloser(strings.NewReader(step.Body)), int64(len(step.Body)))
	if step.Header != nil {
		resp.Header = step.Header.Clone()
	}
	return resp, nil
}

// requests returns a copy of the recorded requests, in order.
func (s *shapeRecorder) requests() []shapeSeen {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.seen)
}

// shapeCase is one operation as the request-shape tests call it.
type shapeCase struct {
	name   string
	method string
	path   string
	accept string
	body   string // the exact JSON body, "" for none
	finish bool
	answer testutil.Step
	call   func(ctx context.Context, c *Client) error
}

// shapeCases returns every operation, called with a valid request that
// reaches each optional part of its wire form, such as a Verify timeout.
func shapeCases() []shapeCase {
	const (
		email  = "avery.example@example.com"
		email2 = "blake.example@example.net"
		batch  = `{"batchId":"5f0c2b9e8d7a6b5c4d3e2f1a","status":"completed"}`
	)
	batchPath := "/v1.1/email/verify/batch/" + string(shapeBatch)
	return []shapeCase{
		{
			name: "Verify", method: http.MethodGet, path: "/v1.1/email/verify", accept: "application/json",
			answer: jsonAnswer(http.StatusOK, verifyAnswer),
			call: func(ctx context.Context, c *Client) error {
				_, err := c.Verify(ctx, VerifyRequest{Email: email, Timeout: 5 * time.Second})
				return err
			},
		},
		{
			name: "VerifyBatchSync", method: http.MethodPost, path: "/v1.1/email/verify/batch/sync",
			accept: "application/json", body: `["avery.example@example.com","blake.example@example.net"]`,
			answer: jsonAnswer(http.StatusOK, "["+verifyAnswer+"]"),
			call: func(ctx context.Context, c *Client) error {
				_, err := c.VerifyBatchSync(ctx, BatchSyncRequest{Emails: []string{email, email2}})
				return err
			},
		},
		{
			name: "Credits", method: http.MethodGet, path: "/v1.1/credits", accept: "application/json",
			answer: jsonAnswer(http.StatusOK, `{"credits":3}`),
			call: func(ctx context.Context, c *Client) error {
				_, err := c.Credits(ctx)
				return err
			},
		},
		{
			name: "Create", method: http.MethodPost, path: "/v1.1/email/verify/batch", accept: "application/json",
			body:   `[{"email":"avery.example@example.com"},{"email":"blake.example@example.net","name":"row-2"}]`,
			answer: jsonAnswer(http.StatusOK, `{"batchId":"5f0c2b9e8d7a6b5c4d3e2f1a","status":"queued"}`),
			call: func(ctx context.Context, c *Client) error {
				_, err := c.Batches().Create(ctx, CreateBatchRequest{Entries: []BatchEntry{
					{Email: email}, {Email: email2, Name: "row-2"},
				}})
				return err
			},
		},
		{
			name: "Status", method: http.MethodGet, path: batchPath, accept: "application/json", answer: jsonAnswer(http.StatusOK, batch),
			call: func(ctx context.Context, c *Client) error {
				_, err := c.Batches().Status(ctx, BatchStatusRequest{BatchID: shapeBatch, WithStats: true})
				return err
			},
		},
		{
			name: "Wait", method: http.MethodGet, path: batchPath, accept: "application/json", answer: jsonAnswer(http.StatusOK, batch),
			call: func(ctx context.Context, c *Client) error {
				_, err := c.Batches().Wait(ctx, WaitBatchRequest{BatchID: shapeBatch, MaxWait: time.Hour})
				return err
			},
		},
		{
			name: "Results", method: http.MethodGet, path: batchPath + "/download", accept: "application/json",
			answer: jsonAnswer(http.StatusOK, "["+verifyAnswer+"]"),
			call: func(ctx context.Context, c *Client) error {
				for _, err := range c.Batches().Results(ctx, BatchResultsRequest{BatchID: shapeBatch}) {
					if err != nil {
						return err
					}
				}
				return nil
			},
		},
		{
			name: "Download JSON", method: http.MethodGet, path: batchPath + "/download", accept: "application/json",
			answer: jsonAnswer(http.StatusOK, "["+verifyAnswer+"]"),
			call: func(ctx context.Context, c *Client) error {
				_, err := c.Batches().Download(ctx, DownloadBatchRequest{BatchID: shapeBatch, Format: FormatJSON}, io.Discard)
				return err
			},
		},
		{
			name: "Download CSV", method: http.MethodGet, path: batchPath + "/download", accept: "text/csv",
			answer: testutil.Step{Header: http.Header{"Content-Type": {"text/csv"}}, Body: "email\r\n" + email + "\r\n"},
			call: func(ctx context.Context, c *Client) error {
				_, err := c.Batches().Download(ctx, DownloadBatchRequest{BatchID: shapeBatch, Format: FormatCSV}, io.Discard)
				return err
			},
		},
		{
			name: "Finish", method: http.MethodPost, path: batchPath + "/finish", accept: "application/json", finish: true,
			answer: jsonAnswer(http.StatusAccepted, `{}`),
			call: func(ctx context.Context, c *Client) error {
				return c.Batches().Finish(ctx, FinishBatchRequest{BatchID: shapeBatch})
			},
		},
		{
			name: "Delete", method: http.MethodDelete, path: batchPath, accept: "application/json", answer: jsonAnswer(http.StatusOK, `{}`),
			call: func(ctx context.Context, c *Client) error {
				return c.Batches().Delete(ctx, DeleteBatchRequest{BatchID: shapeBatch})
			},
		},
	}
}

func TestRequestShape(t *testing.T) {
	t.Parallel()
	for _, sc := range shapeCases() {
		t.Run(sc.name, func(t *testing.T) {
			t.Parallel()
			rec := &shapeRecorder{answers: []testutil.Step{sc.answer}}
			require.NoError(t, sc.call(t.Context(), newTestClient(t, rec)))
			reqs := rec.requests()
			require.Len(t, reqs, 1, "exactly one request")
			seen := reqs[0]
			r := seen.req

			assert.Equal(t, sc.method, r.Method)
			assert.Equal(t, "https", r.URL.Scheme)
			assert.Equal(t, "127.0.0.1", r.URL.Host)
			assert.Equal(t, sc.path, r.URL.Path)
			assert.Nil(t, r.URL.User)
			assert.Empty(t, r.URL.Fragment)
			assert.Nil(t, r.GetBody, "no GetBody: the standard library can never rewind and resend the body")
			assert.False(t, seen.nilBody, "the body is never nil")

			want := []string{"Accept", "User-Agent", "X-Api-Key"}
			if sc.body != "" {
				want = []string{"Accept", "Content-Type", "User-Agent", "X-Api-Key"}
			}
			assert.Equal(t, want, slices.Sorted(maps.Keys(seen.header)), "exactly the SDK's headers")
			assert.Equal(t, []string{testKey}, seen.header["X-Api-Key"])
			assert.Equal(t, []string{sc.accept}, seen.header["Accept"])
			assert.Equal(t, []string{"go-bouncer"}, seen.header["User-Agent"])
			for _, k := range []string{"Idempotency-Key", "X-Idempotency-Key", "Authorization", "Cookie", "Referer", "Expect"} {
				_, ok := seen.header[k]
				assert.False(t, ok, "no %s key, not even with an empty value", k)
			}

			switch {
			case sc.finish:
				assert.True(t, seen.noBody, "Finish, a POST without a body, uses http.NoBody")
				assert.Zero(t, r.ContentLength)
				assert.Empty(t, seen.body)
				assert.Equal(t, http.MethodPost, r.Method, "a POST is never replayable without an idempotency key")
			case sc.body != "":
				assert.False(t, seen.noBody)
				assert.Equal(t, []string{"application/json"}, seen.header["Content-Type"])
				assert.Equal(t, int64(len(sc.body)), r.ContentLength)
				assert.Equal(t, sc.body, string(seen.body), "the exact JSON body")
			default:
				assert.False(t, seen.noBody, "a GET or DELETE carries an empty body that is not http.NoBody")
				assert.IsType(t, emptyBody{}, r.Body)
				assert.Zero(t, r.ContentLength)
				assert.Empty(t, seen.body)
			}

			// The standard library's rule (Request.isReplayable): a request is
			// replayable when its body is nil or http.NoBody, or it has a GetBody,
			// and its method is idempotent or it carries an idempotency key.
			bodyless := seen.nilBody || seen.noBody || r.GetBody != nil
			idempotent := r.Method == http.MethodGet || r.Method == http.MethodHead
			assert.False(t, bodyless && idempotent, "the request must not count as replayable")
		})
	}
}

func TestRequestHeadersAreFreshPerCall(t *testing.T) {
	t.Parallel()
	rec := &shapeRecorder{answers: []testutil.Step{jsonAnswer(http.StatusOK, `{"credits":1}`), jsonAnswer(http.StatusOK, `{"credits":2}`)}}
	c := newTestClient(t, rec)
	for range 2 {
		_, err := c.Credits(t.Context())
		require.NoError(t, err)
	}
	reqs := rec.requests()
	require.Len(t, reqs, 2)
	h1, h2 := reqs[0].header, reqs[1].header
	for _, k := range []string{"X-Api-Key", "Accept", "User-Agent"} {
		require.Len(t, h1[k], 1, k)
		require.Len(t, h2[k], 1, k)
		assert.Equal(t, 1, cap(h1[k]), "%s is a full slice expression, so an append cannot reach another value", k)
		assert.NotSame(t, &h1[k][0], &h2[k][0], "%s is not shared between calls", k)
	}
	h1["Accept"] = append(h1["Accept"], "text/html")
	h1["X-Api-Key"][0] = "changed"
	assert.Equal(t, []string{"go-bouncer"}, h1["User-Agent"], "an append to one value leaves the others alone")
	assert.Equal(t, []string{"application/json"}, h2["Accept"])
	assert.Equal(t, []string{testKey}, h2["X-Api-Key"])
}

func TestRequestBodyIsEncodedBeforeSending(t *testing.T) {
	t.Parallel()
	entries := []BatchEntry{{Email: "avery.example@example.com"}}
	emails := []string{"avery.example@example.com"}
	rec := &shapeRecorder{answers: []testutil.Step{
		jsonAnswer(http.StatusOK, `{"batchId":"5f0c2b9e8d7a6b5c4d3e2f1a","status":"queued"}`),
		jsonAnswer(http.StatusOK, `[]`),
	}}
	c := newTestClient(t, rec)
	req := CreateBatchRequest{Entries: entries}
	_, err := c.Batches().Create(t.Context(), req)
	require.NoError(t, err)
	_, err = c.VerifyBatchSync(t.Context(), BatchSyncRequest{Emails: emails})
	require.NoError(t, err)
	entries[0].Email = "changed@example.com"
	emails[0] = "changed@example.com"
	reqs := rec.requests()
	require.Len(t, reqs, 2)
	wantCreate, wantSync := `[{"email":"avery.example@example.com"}]`, `["avery.example@example.com"]`
	assert.Equal(t, wantCreate, string(reqs[0].body), "the body as it was when the call was made")
	assert.Equal(t, wantSync, string(reqs[1].body))
}

func TestEmptyBody(t *testing.T) {
	t.Parallel()
	var b emptyBody
	n, err := b.Read(make([]byte, 8))
	assert.Zero(t, n)
	require.ErrorIs(t, err, io.EOF)
	require.NoError(t, b.Close())
	assert.NotEqual(t, any(http.NoBody), any(b))
}
