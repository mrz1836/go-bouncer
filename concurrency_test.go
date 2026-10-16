package bouncer_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/mrz1836/go-bouncer"
	"github.com/mrz1836/go-bouncer/internal/testutil"
)

// errConcurrencyWrongAnswer reports a call whose answer was not the one its
// own request asked for.
var errConcurrencyWrongAnswer = errors.New("a call got an answer that is not its own")

// concurrencyRecord returns a minimal verification record for email.
func concurrencyRecord(email string) map[string]string {
	return map[string]string{"email": email, "status": "deliverable", "reason": "accepted_email"}
}

// concurrencyWriteJSON answers with status and v as JSON.
func concurrencyWriteJSON(w http.ResponseWriter, status int, v any) {
	body, err := json.Marshal(v)
	if err != nil {
		http.Error(w, "encoding failed", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", mediaJSON)
	w.WriteHeader(status)
	_, _ = w.Write(body)
}

// concurrencyHandler plays a synthetic Bouncer that answers every operation,
// echoing the addresses it was sent, so that each caller can check that it got
// its own answer.
func concurrencyHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method + " " + r.URL.Path {
	case "GET " + pathVerify:
		concurrencyWriteJSON(w, http.StatusOK, concurrencyRecord(r.URL.Query().Get("email")))
	case "GET " + pathCredits:
		concurrencyWriteJSON(w, http.StatusOK, map[string]int{"credits": 7})
	case "POST " + pathSync:
		var emails []string
		_ = json.NewDecoder(r.Body).Decode(&emails)
		out := make([]map[string]string, 0, len(emails))
		for _, e := range emails {
			out = append(out, concurrencyRecord(e))
		}
		concurrencyWriteJSON(w, http.StatusOK, out)
	case "POST " + pathBatch:
		var entries []map[string]string
		_ = json.NewDecoder(r.Body).Decode(&entries)
		concurrencyWriteJSON(w, http.StatusOK, map[string]any{
			"batchId": string(testBatchID), "status": "queued", "quantity": len(entries),
		})
	case "GET " + pathBatchID:
		concurrencyWriteJSON(w, http.StatusOK, map[string]string{"batchId": string(testBatchID), "status": "completed"})
	case "GET " + pathDownload:
		if r.Header.Get("Accept") == mediaCSV {
			w.Header().Set("Content-Type", mediaCSV)
			_, _ = io.WriteString(w, csvFile)
			return
		}
		concurrencyWriteJSON(w, http.StatusOK, []map[string]string{concurrencyRecord(testEmail)})
	case "POST " + pathFinish:
		concurrencyWriteJSON(w, http.StatusAccepted, map[string]string{})
	case "DELETE " + pathBatchID:
		concurrencyWriteJSON(w, http.StatusOK, map[string]string{})
	default:
		concurrencyWriteJSON(w, http.StatusNotFound, map[string]string{"status": "404"})
	}
}

// concurrencyEmail returns the address worker uses in round.
func concurrencyEmail(worker, round int) string {
	return fmt.Sprintf("user%02d-%d@example.com", worker, round)
}

// concurrencyCall is one operation a worker runs, checking its own answer.
type concurrencyCall func(ctx context.Context, c *bouncer.Client, s bouncer.BatchService, worker, round int) error

// concurrencyOp is one operation and the request the server must see for it,
// as "METHOD path".
type concurrencyOp struct {
	key string
	run concurrencyCall
}

// concurrencyOps returns every operation, each checking that the answer is
// the one its own request asked for.
func concurrencyOps() []concurrencyOp {
	return []concurrencyOp{
		{"GET " + pathVerify, concurrencyVerify},
		{"POST " + pathSync, concurrencySync},
		{"GET " + pathCredits, concurrencyCredits},
		{"POST " + pathBatch, concurrencyCreate},
		{"GET " + pathBatchID, concurrencyStatus},
		{"GET " + pathBatchID, concurrencyWait},
		{"GET " + pathDownload, concurrencyResults},
		{"GET " + pathDownload, concurrencyDownload},
		{"POST " + pathFinish, func(ctx context.Context, _ *bouncer.Client, s bouncer.BatchService, _, _ int) error {
			return s.Finish(ctx, bouncer.FinishBatchRequest{BatchID: testBatchID})
		}},
		{"DELETE " + pathBatchID, func(ctx context.Context, _ *bouncer.Client, s bouncer.BatchService, _, _ int) error {
			return s.Delete(ctx, bouncer.DeleteBatchRequest{BatchID: testBatchID})
		}},
	}
}

func concurrencyVerify(ctx context.Context, c *bouncer.Client, _ bouncer.BatchService, w, r int) error {
	v, err := c.Verify(ctx, bouncer.VerifyRequest{Email: concurrencyEmail(w, r)})
	if err == nil && v.Email != concurrencyEmail(w, r) {
		return fmt.Errorf("%w: worker %d Verify", errConcurrencyWrongAnswer, w)
	}
	return err
}

func concurrencySync(ctx context.Context, c *bouncer.Client, _ bouncer.BatchService, w, r int) error {
	emails := []string{concurrencyEmail(w, r), concurrencyEmail(w, r+100)}
	res, err := c.VerifyBatchSync(ctx, bouncer.BatchSyncRequest{Emails: emails})
	if err != nil {
		return err
	}
	if res.Requested != 2 || len(res.Available) != 2 ||
		res.Available[0].Email != emails[0] || res.Available[1].Email != emails[1] {
		return fmt.Errorf("%w: worker %d VerifyBatchSync", errConcurrencyWrongAnswer, w)
	}
	return nil
}

func concurrencyCredits(ctx context.Context, c *bouncer.Client, _ bouncer.BatchService, w, _ int) error {
	b, err := c.Credits(ctx)
	if err == nil && b.Credits != 7 {
		return fmt.Errorf("%w: worker %d Credits", errConcurrencyWrongAnswer, w)
	}
	return err
}

func concurrencyCreate(ctx context.Context, _ *bouncer.Client, s bouncer.BatchService, w, r int) error {
	b, err := s.Create(ctx, bouncer.CreateBatchRequest{Entries: []bouncer.BatchEntry{
		{Email: concurrencyEmail(w, r)}, {Email: concurrencyEmail(w, r+100), Name: testName},
	}})
	if err == nil && (b.ID != testBatchID || b.Quantity == nil || *b.Quantity != 2) {
		return fmt.Errorf("%w: worker %d Create", errConcurrencyWrongAnswer, w)
	}
	return err
}

func concurrencyStatus(ctx context.Context, _ *bouncer.Client, s bouncer.BatchService, w, _ int) error {
	b, err := s.Status(ctx, bouncer.BatchStatusRequest{BatchID: testBatchID, WithStats: true})
	if err == nil && b.State != bouncer.BatchStateCompleted {
		return fmt.Errorf("%w: worker %d Status", errConcurrencyWrongAnswer, w)
	}
	return err
}

func concurrencyWait(ctx context.Context, _ *bouncer.Client, s bouncer.BatchService, w, _ int) error {
	b, err := s.Wait(ctx, bouncer.WaitBatchRequest{BatchID: testBatchID, MaxWait: time.Minute})
	if err == nil && b.State != bouncer.BatchStateCompleted {
		return fmt.Errorf("%w: worker %d Wait", errConcurrencyWrongAnswer, w)
	}
	return err
}

func concurrencyResults(ctx context.Context, _ *bouncer.Client, s bouncer.BatchService, w, _ int) error {
	got, err := collect(s.Results(ctx, bouncer.BatchResultsRequest{BatchID: testBatchID}))
	if err == nil && (len(got) != 1 || got[0].Email != testEmail) {
		return fmt.Errorf("%w: worker %d Results", errConcurrencyWrongAnswer, w)
	}
	return err
}

func concurrencyDownload(ctx context.Context, _ *bouncer.Client, s bouncer.BatchService, w, _ int) error {
	var buf bytes.Buffer
	n, err := s.Download(ctx, bouncer.DownloadBatchRequest{BatchID: testBatchID, Format: bouncer.FormatCSV}, &buf)
	if err == nil && (n != int64(len(csvFile)) || buf.String() != csvFile) {
		return fmt.Errorf("%w: worker %d Download", errConcurrencyWrongAnswer, w)
	}
	return err
}

// concurrencyErrors collects errors from many goroutines, for the test
// goroutine to check: require must not be called from other goroutines.
type concurrencyErrors struct {
	mu   sync.Mutex
	errs []error
}

// add records err when it is not nil.
func (e *concurrencyErrors) add(err error) {
	if err == nil {
		return
	}
	e.mu.Lock()
	e.errs = append(e.errs, err)
	e.mu.Unlock()
}

// require fails t when any error was recorded.
func (e *concurrencyErrors) require(t *testing.T) {
	t.Helper()
	e.mu.Lock()
	defer e.mu.Unlock()
	require.NoError(t, errors.Join(e.errs...))
}

// concurrencyChurn closes the Client's idle connections and prints it, over
// and over, until stop is closed.
func concurrencyChurn(c *bouncer.Client, stop <-chan struct{}) {
	for {
		select {
		case <-stop:
			return
		default:
			c.CloseIdleConnections()
			_ = c.String()
			runtime.Gosched()
		}
	}
}

// TestConcurrencySharedClient runs 32 workers, each making a mix of every
// operation through one shared Client, over HTTP/1.1 and HTTP/2, while another
// goroutine closes idle connections and prints the Client. Each worker checks
// its own answers, and the server sees exactly the requests made.
func TestConcurrencySharedClient(t *testing.T) {
	t.Parallel()
	const workers, rounds = 32, 5
	for _, proto := range testutil.Protocols() {
		t.Run(proto.Name(), func(t *testing.T) {
			t.Parallel()
			c, srv := newServerClient(t, proto, concurrencyHandler, bouncer.WithUserAgent("go-bouncer-concurrency-test"))
			defer c.CloseIdleConnections()
			shared := c.Batches()
			ops := concurrencyOps()
			ctx := t.Context()

			var (
				mu    sync.Mutex
				want  = map[string]int{}
				fails concurrencyErrors
				wg    sync.WaitGroup
				churn sync.WaitGroup
			)
			stop := make(chan struct{})
			churn.Go(func() { concurrencyChurn(c, stop) })
			for w := range workers {
				wg.Go(func() {
					for r := range rounds {
						op := ops[(w+r)%len(ops)]
						batches := shared
						if r%2 == 1 {
							batches = c.Batches()
						}
						fails.add(op.run(ctx, c, batches, w, r))
						mu.Lock()
						want[op.key]++
						mu.Unlock()
					}
				})
			}
			wg.Wait()
			close(stop)
			churn.Wait()
			fails.require(t)

			got := map[string]int{}
			for _, req := range srv.Requests() {
				got[req.Method+" "+req.Path]++
				assert.Equal(t, "go-bouncer-concurrency-test", req.Header.Get("User-Agent"))
			}
			assert.Equal(t, want, got, "the server saw exactly the requests made, once each")
			assert.Equal(t, workers*rounds, srv.Hits())
		})
	}
}

// TestConcurrencyInjectedClientMutationsHaveNoEffect changes every field of
// the injected *http.Client after NewClient: the Client keeps using the copy
// it took, with its own transport, no timeout, no cookie jar and redirects
// refused.
func TestConcurrencyInjectedClientMutationsHaveNoEffect(t *testing.T) {
	t.Parallel()
	target := testutil.NewServer(t, testutil.Serve(jsonStep(creditsOK)))
	srv := testutil.NewServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == pathVerify {
			w.Header().Set("Location", target.URL()+pathCredits)
			w.WriteHeader(http.StatusFound)
			return
		}
		http.SetCookie(w, &http.Cookie{
			Name: "session", Value: "cookie-marker", Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode,
		})
		testutil.Serve(jsonStep(creditsOK))(w, r)
	})
	jar, err := cookiejar.New(nil)
	require.NoError(t, err)
	hc := &http.Client{Transport: srv.Client().Transport, Jar: jar}
	c := newClientAt(t, srv.URL(), hc)
	defer c.CloseIdleConnections()

	swapped := &testutil.CountingTransport{Next: testutil.StaticTransport(http.StatusOK, `{"credits":1}`)}
	otherJar, err := cookiejar.New(nil)
	require.NoError(t, err)
	hc.Timeout = time.Nanosecond
	hc.Transport = swapped
	hc.CheckRedirect = followAll
	hc.Jar = otherJar

	for range 3 {
		b, callErr := c.Credits(t.Context())
		require.NoError(t, callErr, "the injected Timeout of 1ns, set after NewClient, does not apply")
		assert.Equal(t, int64(7), b.Credits, "the original transport answered")
	}
	assert.Zero(t, swapped.Attempts(), "a transport swapped in after NewClient is never used")
	for _, req := range srv.Requests() {
		assert.Empty(t, req.Header.Values("Cookie"), "no cookie jar: cookies are never sent back")
	}

	_, err = c.Verify(t.Context(), bouncer.VerifyRequest{Email: testEmail})
	requireCallError(t, err, wantCall{Kind: bouncer.FailureUnexpectedResponse, Op: bouncer.OpVerify, StatusCode: http.StatusFound})
	assert.Zero(t, target.Hits(), "a CheckRedirect set after NewClient does not make the Client follow redirects")
}

// concurrencyCapture is an in-memory transport that runs hook while the
// request is in flight, then records the body it carried.
type concurrencyCapture struct {
	hook   func()
	answer string
	mu     sync.Mutex
	bodies [][]byte
}

// RoundTrip runs the hook, then reads the request body.
func (c *concurrencyCapture) RoundTrip(r *http.Request) (*http.Response, error) {
	c.hook()
	rec := testutil.Record(r)
	c.mu.Lock()
	c.bodies = append(c.bodies, rec.Body)
	c.mu.Unlock()
	return testutil.Response(r, http.StatusOK, io.NopCloser(bytes.NewReader([]byte(c.answer))), int64(len(c.answer))), nil
}

// TestConcurrencyRequestEncodedBeforeSend changes the caller's request slices
// while the call is in flight: the body sent is the request as it was when the
// call was made, because the SDK encodes it before any I/O.
func TestConcurrencyRequestEncodedBeforeSend(t *testing.T) {
	t.Parallel()
	t.Run("Create", func(t *testing.T) {
		t.Parallel()
		entries := []bouncer.BatchEntry{{Email: testEmail, Name: testName}, {Email: testEmail2}}
		capture := &concurrencyCapture{answer: batchQueued, hook: func() {
			entries[0] = bouncer.BatchEntry{Email: "changed@example.org", Name: "changed"}
			entries[1].Email = "changed@example.net"
		}}
		c := newClient(t, capture)
		_, err := c.Batches().Create(t.Context(), bouncer.CreateBatchRequest{Entries: entries})
		require.NoError(t, err)
		require.Len(t, capture.bodies, 1)
		assert.JSONEq(t, `[{"email":"`+testEmail+`","name":"`+testName+`"},{"email":"`+testEmail2+`"}]`,
			string(capture.bodies[0]))
	})

	t.Run("VerifyBatchSync", func(t *testing.T) {
		t.Parallel()
		emails := []string{testEmail, testEmail2}
		capture := &concurrencyCapture{answer: `[` + verifyOK + `]`, hook: func() {
			emails[0], emails[1] = "changed@example.org", "changed@example.net"
		}}
		c := newClient(t, capture)
		res, err := c.VerifyBatchSync(t.Context(), bouncer.BatchSyncRequest{Emails: emails})
		require.NoError(t, err)
		assert.Equal(t, 2, res.Requested)
		require.Len(t, capture.bodies, 1)
		assert.JSONEq(t, `["`+testEmail+`","`+testEmail2+`"]`, string(capture.bodies[0]))

		emails[0] = "after@example.org"
		assert.Equal(t, testEmail, res.Available[0].Email, "the result never aliases the request")
	})
}

// TestConcurrencyRequestsAreNotRetained mutates request slices from other
// goroutines right after their calls return, while the shared Client keeps
// working. Under -race this proves the SDK keeps no reference to a request
// once its call has returned.
func TestConcurrencyRequestsAreNotRetained(t *testing.T) {
	t.Parallel()
	c, _ := newServerClient(t, testutil.HTTP1, concurrencyHandler)
	defer c.CloseIdleConnections()
	ctx := t.Context()
	var (
		wg    sync.WaitGroup
		fails concurrencyErrors
	)
	for w := range 16 {
		wg.Go(func() {
			entries := []bouncer.BatchEntry{{Email: fmt.Sprintf("user%02d@example.com", w)}}
			emails := []string{fmt.Sprintf("user%02d@example.net", w)}
			_, err := c.Batches().Create(ctx, bouncer.CreateBatchRequest{Entries: entries})
			fails.add(err)
			_, err = c.VerifyBatchSync(ctx, bouncer.BatchSyncRequest{Emails: emails})
			fails.add(err)
			var mutators sync.WaitGroup
			mutators.Go(func() {
				for i := range 100 {
					entries[0].Email = fmt.Sprintf("mutated%d@example.org", i)
					emails[0] = entries[0].Email
				}
			})
			_, err = c.Credits(ctx)
			fails.add(err)
			mutators.Wait()
		})
	}
	wg.Wait()
	fails.require(t)
}
