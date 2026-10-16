package bouncer_test

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/mrz1836/go-bouncer"
	"github.com/mrz1836/go-bouncer/internal/testutil"
)

// benchRecord is one realistic verification record.
const benchRecord = `{"email":"avery.example@example.com","status":"deliverable","reason":"accepted_email",` +
	`"domain":{"name":"example.com","acceptAll":"no","disposable":"no","free":"yes"},` +
	`"account":{"role":"no","disabled":"no","fullMailbox":"no"},"dns":{"type":"MX","record":"mx1.example.com"},` +
	`"provider":"example-mail","score":94,"toxic":"unknown","toxicity":0}`

// benchArray returns a JSON array of n records.
func benchArray(n int) string {
	var b strings.Builder
	b.Grow(n * (len(benchRecord) + 1))
	b.WriteByte('[')
	for i := range n {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(benchRecord)
	}
	b.WriteByte(']')
	return b.String()
}

// BenchmarkVerifyEndToEnd makes whole Verify calls against an in-memory
// transport: request building, response classification and decoding.
func BenchmarkVerifyEndToEnd(b *testing.B) {
	c := newClient(b, testutil.StaticTransport(http.StatusOK, benchRecord))
	ctx := context.Background()
	req := bouncer.VerifyRequest{Email: testEmail}
	b.ReportAllocs()
	for b.Loop() {
		if _, err := c.Verify(ctx, req); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkResultsStream ranges over a 10,000-record Results answer.
func BenchmarkResultsStream(b *testing.B) {
	const records = 10_000
	body := benchArray(records)
	c := newClient(b, testutil.StaticTransport(http.StatusOK, body))
	ctx := context.Background()
	req := bouncer.BatchResultsRequest{BatchID: testBatchID}
	b.SetBytes(int64(len(body)))
	b.ReportAllocs()
	for b.Loop() {
		n := 0
		for _, err := range c.Batches().Results(ctx, req) {
			if err != nil {
				b.Fatal(err)
			}
			n++
		}
		if n != records {
			b.Fatalf("got %d records", n)
		}
	}
}

// BenchmarkVerifyBatchSync10k decodes a 10,000-record batch-sync answer.
func BenchmarkVerifyBatchSync10k(b *testing.B) {
	const records = 10_000
	body := benchArray(records)
	c := newClient(b, testutil.StaticTransport(http.StatusOK, body))
	ctx := context.Background()
	emails := make([]string, records)
	for i := range emails {
		emails[i] = testEmail
	}
	req := bouncer.BatchSyncRequest{Emails: emails}
	b.SetBytes(int64(len(body)))
	b.ReportAllocs()
	for b.Loop() {
		res, err := c.VerifyBatchSync(ctx, req)
		if err != nil || len(res.Available) != records {
			b.Fatal(err)
		}
	}
}

// BenchmarkDownloadCopy streams a 64 MiB CSV download to io.Discard.
func BenchmarkDownloadCopy(b *testing.B) {
	const size = 64 << 20
	row := []byte("avery.example@example.com,deliverable,accepted_email\r\n")
	content := bytes.Repeat(row, size/len(row))
	rt := testutil.RoundTripFunc(func(r *http.Request) (*http.Response, error) {
		testutil.Drain(r)
		resp := testutil.Response(r, http.StatusOK, io.NopCloser(bytes.NewReader(content)), int64(len(content)))
		resp.Header = http.Header{"Content-Type": {mediaCSV}}
		return resp, nil
	})
	c := newClient(b, rt, bouncer.WithMaxDownloadBytes(size))
	ctx := context.Background()
	req := bouncer.DownloadBatchRequest{BatchID: testBatchID, Format: bouncer.FormatCSV}
	b.SetBytes(int64(len(content)))
	b.ReportAllocs()
	for b.Loop() {
		n, err := c.Batches().Download(ctx, req, io.Discard)
		if err != nil || n != int64(len(content)) {
			b.Fatal(n, err)
		}
	}
}
