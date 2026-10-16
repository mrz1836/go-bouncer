package bouncer_test

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/mrz1836/go-bouncer"
)

// secretKey stands in for the application's secret store. Examples that call
// the provider have no Output line, so `go test` compiles them but never runs
// them; the others make no call, and run.
func secretKey() string { return "bk-SYNTHETIC-KEY-EXAMPLE" }

// exampleClient builds the client the examples share.
func exampleClient() *bouncer.Client {
	client, err := bouncer.NewClient(secretKey())
	if err != nil {
		log.Fatal(err)
	}
	return client
}

// save stands in for the application's own storage of a batch ID.
func save(bouncer.BatchID) {}

// handle stands in for the application's own handling of a result; true stops
// the loop.
func handle(bouncer.Verification) bool { return false }

func ExampleNewClient() {
	// Build one client at startup. The key comes from the app's secret store: the SDK never reads the environment.
	client, err := bouncer.NewClient(secretKey(),
		bouncer.WithTimeout(40*time.Second), // must be ≥ VerifyRequest.Timeout + 10s
		bouncer.WithDownloadTimeout(20*time.Minute),
		bouncer.WithUserAgent("acme-signup/1.4"))
	if err != nil {
		log.Fatal(err) // ErrInvalidConfig: nothing was sent
	}
	fmt.Println(client) // settings only, never the key
	// Output:
	// bouncer.Client{timeout: 40s, maxResponseBytes: 16777216, downloadTimeout: 20m0s, maxDownloadBytes: 1073741824, userAgent: "acme-signup/1.4", testBaseURL: false, providerDiagnostics: false}
}

func ExampleClient_Verify() {
	client, ctx := exampleClient(), context.Background()

	// Single check. Status and Reason are separate axes, and "unknown" is a successful, billed answer.
	v, err := client.Verify(ctx, bouncer.VerifyRequest{Email: "avery.example@example.com", Timeout: 20 * time.Second})
	if err != nil {
		log.Fatal(err) // the call may already be billed: never resend blindly
	}
	fmt.Println(v.Status, v.Reason)
	if d := v.Domain; d != nil {
		fmt.Println(d.Name, d.AcceptAll == bouncer.FlagYes, d.Free)
	}
	if v.Score != nil {
		fmt.Println("score", *v.Score) // &0 is a real score; nil means not evaluated
	}
	if v.DidYouMean != "" {
		fmt.Println("suggestion only:", v.DidYouMean) // never verified automatically
	}
	if !v.Status.Known() {
		fmt.Println("a verdict newer than this SDK: apply your own policy")
	}
}

func ExampleClient_VerifyBatchSync() {
	client, ctx := exampleClient(), context.Background()

	// Batch-sync returns only the results Bouncer already has; the rest keep verifying, and are billed.
	res, err := client.VerifyBatchSync(ctx, bouncer.BatchSyncRequest{Emails: []string{
		"avery.example@example.com", "blake.example@example.net",
	}})
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("%d of %d available now\n", len(res.Available), res.Requested)
	for _, v := range res.Available {
		fmt.Println(v.Email, v.Status) // provider order; no correlation is promised
	}
}

func ExampleClient_Credits() {
	client, ctx := exampleClient(), context.Background()

	// Free and read-only; Bouncer allows 10 calls a minute.
	balance, err := client.Credits(ctx)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(balance.Credits, "credits left")
}

func ExampleBatchService_Create() {
	client, ctx := exampleClient(), context.Background()

	// Async batch. Creating it queues verification immediately; there is no separate start step.
	b, err := client.Batches().Create(ctx, bouncer.CreateBatchRequest{Entries: []bouncer.BatchEntry{
		{Email: "avery.example@example.com"}, {Email: "blake.example@example.net", Name: "crm-1042"},
	}})
	if ce, ok := errors.AsType[*bouncer.CallError](err); ok && ce.BatchID != "" {
		save(ce.BatchID) // created, but the reply was unusable
	}
	if err == nil {
		save(b.ID)
	}
}

func ExampleBatchService_Status() {
	client, ctx := exampleClient(), context.Background()
	id := bouncer.BatchID("5f0c2b9e8d7a6b5c4d3e2f1a")

	// Free and read-only. WithStats adds Processed and Stats; nil counters were not reported.
	st, err := client.Batches().Status(ctx, bouncer.BatchStatusRequest{BatchID: id, WithStats: true})
	if err != nil {
		log.Fatal(err)
	}
	if st.Processed != nil && st.Quantity != nil {
		fmt.Printf("%s: %d of %d verified\n", st.State, *st.Processed, *st.Quantity)
	}
	if created, ok := st.Created.Time(); ok { // timestamps stay text; Time parses them on demand
		fmt.Println("created", created.Format(time.RFC3339))
	}
	if st.State.Terminal() {
		fmt.Println("completed: read it with Results or Download")
	}
}

func ExampleBatchService_Wait() {
	client, ctx := exampleClient(), context.Background()
	id := bouncer.BatchID("5f0c2b9e8d7a6b5c4d3e2f1a")

	st, err := client.Batches().Wait(ctx, bouncer.WaitBatchRequest{BatchID: id, Interval: 15 * time.Second, MaxWait: 30 * time.Minute})
	if errors.Is(err, bouncer.ErrBudgetExhausted) {
		fmt.Println("still", st.State) // st is the last status seen; nothing was finished or deleted
		return
	}
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(st.State, st.Completed)
}

func ExampleBatchService_Results() {
	client, ctx := exampleClient(), context.Background()
	id := bouncer.BatchID("5f0c2b9e8d7a6b5c4d3e2f1a")

	// Stream results with bounded memory: one GET per range. Breaking out closes the body immediately.
	for v, err := range client.Batches().Results(ctx, bouncer.BatchResultsRequest{BatchID: id, Filter: bouncer.FilterRisky}) {
		if err != nil {
			log.Fatal(err) // e.g. ErrBatchState: not completed; CallError.Records = how many were yielded
		}
		if handle(v) {
			break
		}
	}
}

func ExampleBatchService_Finish() {
	client, ctx := exampleClient(), context.Background()
	id := bouncer.BatchID("5f0c2b9e8d7a6b5c4d3e2f1a")

	// Ask Bouncer to stop and return the credits of unverified entries. Success means only "accepted".
	if err := client.Batches().Finish(ctx, bouncer.FinishBatchRequest{BatchID: id}); err != nil {
		log.Fatal(err) // ErrBatchState (405): the batch's state does not allow it
	}
	st, err := client.Batches().Wait(ctx, bouncer.WaitBatchRequest{BatchID: id, MaxWait: 10 * time.Minute})
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(st.State, st.CreditsUsed != nil)
}

func ExampleBatchService_Delete() {
	client, ctx := exampleClient(), context.Background()
	id := bouncer.BatchID("5f0c2b9e8d7a6b5c4d3e2f1a")

	// Destructive: the batch and its results are gone for good. Download them first if you need them.
	err := client.Batches().Delete(ctx, bouncer.DeleteBatchRequest{BatchID: id})
	if errors.Is(err, bouncer.ErrBatchState) {
		fmt.Println("not deletable in its current state")
		return
	}
	if err != nil {
		log.Fatal(err)
	}
}

func ExampleBatchService_Download() {
	client, ctx := exampleClient(), context.Background()
	id := bouncer.BatchID("5f0c2b9e8d7a6b5c4d3e2f1a")
	f, err := os.Create("results.csv")
	if err != nil {
		log.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	bw := bufio.NewWriter(f)

	// Raw CSV to a caller-owned writer. The SDK never closes or flushes it.
	n, err := client.Batches().Download(ctx, bouncer.DownloadBatchRequest{BatchID: id, Format: bouncer.FormatCSV}, bw)
	if err != nil {
		log.Fatalf("partial file of %d bytes: %v", n, err) // discard it
	}
	if err := bw.Flush(); err != nil {
		log.Fatal(err)
	}
}

func Example_errors() {
	client, ctx := exampleClient(), context.Background()
	_, err := client.Verify(ctx, bouncer.VerifyRequest{Email: "avery.example@example.com"})

	// Classify outcomes.
	var ve *bouncer.ValidationError
	switch {
	case errors.As(err, &ve): // local only: nothing was sent
	case errors.Is(err, bouncer.ErrTimeout): // SDK deadline (also matches context.DeadlineExceeded)
	case errors.Is(err, context.Canceled): // caller canceled; remote work and billing may continue
	case errors.Is(err, bouncer.ErrRateLimited): // CallError.RetryAfter is data only; nothing retries
	case errors.Is(err, bouncer.ErrMalformedResponse): // the provider answered but the reply is unusable; may be billed
	case errors.Is(err, bouncer.ErrBatchState): // 405: not completed, results removed, or not deletable now
	}
}

func ExampleCallError() {
	client, ctx := exampleClient(), context.Background()
	_, err := client.Credits(ctx)

	// Every exported field is safe to log: none holds the key, an address, a URL or Bouncer's text.
	if ce, ok := errors.AsType[*bouncer.CallError](err); ok {
		log.Printf("bouncer: op=%s kind=%s http=%d api=%d timeout=%t", ce.Op, ce.Kind, ce.StatusCode, ce.APIStatus, ce.Timeout())
		if ce.HasRetryAfter {
			log.Printf("Bouncer asks to wait %s; the SDK never retries", ce.RetryAfter)
		}
		if msg := ce.Diagnostics().Message; msg != "" { // only with WithProviderDiagnostics
			fmt.Println("Bouncer says:", msg) // may echo the address: keep it out of shared logs
		}
	}
}

func ExampleValidationError() {
	client := exampleClient()
	_, err := client.Verify(context.Background(), bouncer.VerifyRequest{Email: "avery.example@example.com", Timeout: 1500 * time.Millisecond})

	// A refused request names the field and a fixed reason, never the value. Nothing was sent.
	if ve, ok := errors.AsType[*bouncer.ValidationError](err); ok {
		fmt.Println(ve.Field, ve.Reason, errors.Is(err, bouncer.ErrInvalidRequest))
	}
	// Output:
	// Timeout not_whole_seconds true
}

func ExampleWithHTTPClient() {
	// The SDK's own transport never reads the proxy environment variables: bring a transport that does.
	var protocols http.Protocols
	protocols.SetHTTP1(true) // HTTP/1.1 only, so the HTTP/2 client's own retries never apply
	transport := &http.Transport{
		Proxy:               http.ProxyFromEnvironment,
		Protocols:           &protocols,
		TLSHandshakeTimeout: 10 * time.Second,
		IdleConnTimeout:     4 * time.Second,
	}
	client, err := bouncer.NewClient(secretKey(), bouncer.WithHTTPClient(&http.Client{Transport: transport}))
	if err != nil {
		log.Fatal(err)
	}
	defer client.CloseIdleConnections()
	// Output:
}

// Verifier is the one method a signup handler needs. *bouncer.Client
// satisfies it, and so does a fake in the application's tests.
type Verifier interface {
	Verify(ctx context.Context, req bouncer.VerifyRequest) (*bouncer.Verification, error)
}

// signupHandler rejects addresses Bouncer finds undeliverable, and lets
// every other outcome through: a verification failure must not block a
// signup.
func signupHandler(v Verifier) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
		defer cancel()
		res, err := v.Verify(ctx, bouncer.VerifyRequest{Email: r.FormValue("email")})
		if err == nil && res.Status == bouncer.StatusUndeliverable {
			http.Error(w, "please check your email address", http.StatusUnprocessableEntity)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

func Example_handler() {
	mux := http.NewServeMux()
	mux.Handle("POST /signup", signupHandler(exampleClient()))
	// Output:
}

// fakeVerifier answers like Bouncer would, without any network.
type fakeVerifier struct {
	res *bouncer.Verification
	err error
}

// Verify returns the fake's answer.
func (f fakeVerifier) Verify(context.Context, bouncer.VerifyRequest) (*bouncer.Verification, error) {
	return f.res, f.err
}

func Example_testingWithAFake() {
	// A CallError built from its exported fields matches errors.Is like a real one.
	rateLimited := fakeVerifier{err: &bouncer.CallError{Kind: bouncer.FailureRateLimited, Op: bouncer.OpVerify, StatusCode: 429}}
	_, err := rateLimited.Verify(context.Background(), bouncer.VerifyRequest{Email: "avery.example@example.com"})
	fmt.Println(errors.Is(err, bouncer.ErrRateLimited))

	deliverable := fakeVerifier{res: &bouncer.Verification{
		Email: "avery.example@example.com", Status: bouncer.StatusDeliverable, Reason: bouncer.ReasonAcceptedEmail,
	}}
	v, _ := deliverable.Verify(context.Background(), bouncer.VerifyRequest{Email: "avery.example@example.com"})
	fmt.Println(v.Status)
	// Output:
	// true
	// deliverable
}

func ExampleVerification_jsonRoundTrip() {
	// A score of zero is a real score: it survives a round trip, apart from "not evaluated" (nil).
	v := bouncer.Verification{
		Email: "avery.example@example.com", Status: bouncer.StatusRisky, Reason: bouncer.ReasonLowQuality, Score: new(0),
	}
	data, err := json.Marshal(v)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(string(data))
	var back bouncer.Verification
	if err := json.Unmarshal(data, &back); err != nil {
		log.Fatal(err)
	}
	fmt.Println(back.Score != nil, *back.Score)
	// Output:
	// {"email":"avery.example@example.com","status":"risky","reason":"low_quality","score":0}
	// true 0
}
