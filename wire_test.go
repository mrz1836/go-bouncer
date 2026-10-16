package bouncer_test

import (
	"context"
	"encoding/json"
	"io"
	"maps"
	"net/http"
	"slices"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/mrz1836/go-bouncer"
	"github.com/mrz1836/go-bouncer/internal/testutil"
)

// wireSeen is one request as the server saw it.
type wireSeen struct {
	method           string
	proto            string
	path             string
	escapedPath      string
	rawQuery         string
	header           http.Header
	body             []byte
	contentLength    int64
	transferEncoding []string
}

// wireServer starts a TLS server speaking proto that records every request and
// answers each with answer(r), and returns a client for it.
func wireServer(t *testing.T, proto testutil.Protocol, answer func(r *http.Request) testutil.Step,
) (*bouncer.Client, func() []wireSeen) {
	t.Helper()
	var (
		mu   sync.Mutex
		seen []wireSeen
	)
	c, _ := newServerClient(t, proto, func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		mu.Lock()
		seen = append(seen, wireSeen{
			method: r.Method, proto: r.Proto, path: r.URL.Path, escapedPath: r.URL.EscapedPath(),
			rawQuery: r.URL.RawQuery, header: r.Header.Clone(), body: body,
			contentLength: r.ContentLength, transferEncoding: slices.Clone(r.TransferEncoding),
		})
		mu.Unlock()
		testutil.Serve(answer(r))(w, r)
	})
	return c, func() []wireSeen {
		mu.Lock()
		defer mu.Unlock()
		return slices.Clone(seen)
	}
}

// wireOnly returns the one request a server saw.
func wireOnly(t *testing.T, seen func() []wireSeen) wireSeen {
	t.Helper()
	all := seen()
	require.Len(t, all, 1, "exactly one request")
	return all[0]
}

// wireStatic answers every request with step.
func wireStatic(step testutil.Step) func(*http.Request) testutil.Step {
	return func(*http.Request) testutil.Step { return step }
}

// wireCase is one call and the request it must send.
type wireCase struct {
	name        string
	answer      testutil.Step
	call        func(ctx context.Context, c *bouncer.Client) error
	method      string
	path        string
	escapedPath string // "" means the same as path
	rawQuery    string
	accept      string
	body        string // the exact body, "" for none
}

func wireCases() []wireCase {
	results := func(req bouncer.BatchResultsRequest) func(context.Context, *bouncer.Client) error {
		return func(ctx context.Context, c *bouncer.Client) error {
			_, err := collect(c.Batches().Results(ctx, req))
			return err
		}
	}
	return []wireCase{
		{
			name: "Verify", answer: jsonStep(verifyOK), call: verifyCall(bouncer.VerifyRequest{Email: testEmail}),
			method: http.MethodGet, path: pathVerify, rawQuery: "email=avery.example%40example.com", accept: mediaJSON,
		},
		{
			name: "Verify with timeout", answer: jsonStep(verifyOK),
			call:   verifyCall(bouncer.VerifyRequest{Email: testEmail, Timeout: 20 * time.Second}),
			method: http.MethodGet, path: pathVerify, rawQuery: "email=avery.example%40example.com&timeout=20",
			accept: mediaJSON,
		},
		{
			name: "Verify strict encoding", answer: jsonStep(verifyOK),
			call:   verifyCall(bouncer.VerifyRequest{Email: "a+b c&d=e/f?g#h%i~j_k.l-m@example.com"}),
			method: http.MethodGet, path: pathVerify,
			rawQuery: "email=a%2Bb%20c%26d%3De%2Ff%3Fg%23h%25i~j_k.l-m%40example.com", accept: mediaJSON,
		},
		{
			name: "Verify non-ASCII", answer: jsonStep(verifyOK),
			call:   verifyCall(bouncer.VerifyRequest{Email: "zoë@example.com", Timeout: time.Second}),
			method: http.MethodGet, path: pathVerify, rawQuery: "email=zo%C3%AB%40example.com&timeout=1", accept: mediaJSON,
		},
		{
			name: "Credits", answer: jsonStep(creditsOK),
			call:   func(ctx context.Context, c *bouncer.Client) error { return noValue(c.Credits(ctx)) },
			method: http.MethodGet, path: pathCredits, accept: mediaJSON,
		},
		{
			name: "VerifyBatchSync", answer: jsonStep("[" + verifyOK + "]"),
			call: func(ctx context.Context, c *bouncer.Client) error {
				return noValue(c.VerifyBatchSync(ctx, bouncer.BatchSyncRequest{Emails: []string{testEmail, testEmail2, testEmail}}))
			},
			method: http.MethodPost, path: pathSync, accept: mediaJSON,
			body: `["avery.example@example.com","blake.example@example.net","avery.example@example.com"]`,
		},
		{
			name: "VerifyBatchSync verbatim", answer: jsonStep("[]"),
			call: func(ctx context.Context, c *bouncer.Client) error {
				return noValue(c.VerifyBatchSync(ctx, bouncer.BatchSyncRequest{Emails: []string{
					`"a<b>&c"@example.com`, " padded@example.org ", `back\slash@example.com`, "zoë@example.com",
				}}))
			},
			method: http.MethodPost, path: pathSync, accept: mediaJSON,
			body: `["\"a<b>&c\"@example.com"," padded@example.org ","back\\slash@example.com","zoë@example.com"]`,
		},
		{
			name: "Create", answer: jsonStep(batchQueued),
			call: createCall(bouncer.CreateBatchRequest{Entries: []bouncer.BatchEntry{
				{Email: testEmail}, {Email: testEmail2, Name: testName},
			}}),
			method: http.MethodPost, path: pathBatch, accept: mediaJSON,
			body: `[{"email":"avery.example@example.com"},{"email":"blake.example@example.net","name":"name-marker-5d1e"}]`,
		},
		{
			name: "Create with callback", answer: jsonStep(batchQueued),
			call: createCall(bouncer.CreateBatchRequest{
				Entries: []bouncer.BatchEntry{{Email: `"a<b>&c"@example.com`, Name: "<n&m>"}}, CallbackURL: testCallback,
			}),
			method: http.MethodPost, path: pathBatch, accept: mediaJSON,
			rawQuery: "callback=https%3A%2F%2Fhooks.example.org%2Fbouncer%3Ftoken%3Dcbmarker-91aa",
			body:     `[{"email":"\"a<b>&c\"@example.com","name":"<n&m>"}]`,
		},
		{
			name: "Status", answer: jsonStep(batchCompleted),
			call: func(ctx context.Context, c *bouncer.Client) error {
				return noValue(c.Batches().Status(ctx, bouncer.BatchStatusRequest{BatchID: testBatchID}))
			},
			method: http.MethodGet, path: pathBatchID, rawQuery: "with-stats=false", accept: mediaJSON,
		},
		{
			name: "Status with stats", answer: jsonStep(batchCompleted),
			call: func(ctx context.Context, c *bouncer.Client) error {
				return noValue(c.Batches().Status(ctx, bouncer.BatchStatusRequest{BatchID: testBatchID, WithStats: true}))
			},
			method: http.MethodGet, path: pathBatchID, rawQuery: "with-stats=true", accept: mediaJSON,
		},
		{
			name: "Wait", answer: jsonStep(batchCompleted),
			call: func(ctx context.Context, c *bouncer.Client) error {
				return noValue(c.Batches().Wait(ctx, bouncer.WaitBatchRequest{
					BatchID: testBatchID, MaxWait: time.Minute, WithStats: true,
				}))
			},
			method: http.MethodGet, path: pathBatchID, rawQuery: "with-stats=true", accept: mediaJSON,
		},
		{
			name: "Results", answer: jsonStep("[" + verifyOK + "]"),
			call:   results(bouncer.BatchResultsRequest{BatchID: testBatchID}),
			method: http.MethodGet, path: pathDownload, rawQuery: "download=all", accept: mediaJSON,
		},
		{
			name: "Results risky", answer: jsonStep("[]"),
			call:   results(bouncer.BatchResultsRequest{BatchID: testBatchID, Filter: bouncer.FilterRisky}),
			method: http.MethodGet, path: pathDownload, rawQuery: "download=risky", accept: mediaJSON,
		},
		{
			name: "Download CSV", answer: csvStep(csvFile),
			call:   downloadCall(bouncer.DownloadBatchRequest{BatchID: testBatchID, Format: bouncer.FormatCSV}, io.Discard),
			method: http.MethodGet, path: pathDownload, rawQuery: "download=all", accept: mediaCSV,
		},
		{
			name: "Download JSON undeliverable", answer: jsonStep("[]"),
			call: downloadCall(bouncer.DownloadBatchRequest{
				BatchID: testBatchID, Filter: bouncer.FilterUndeliverable, Format: bouncer.FormatJSON,
			}, io.Discard),
			method: http.MethodGet, path: pathDownload, rawQuery: "download=undeliverable", accept: mediaJSON,
		},
		{
			name: "Download CSV deliverable", answer: csvStep(csvFile),
			call: downloadCall(bouncer.DownloadBatchRequest{
				BatchID: testBatchID, Filter: bouncer.FilterDeliverable, Format: bouncer.FormatCSV,
			}, io.Discard),
			method: http.MethodGet, path: pathDownload, rawQuery: "download=deliverable", accept: mediaCSV,
		},
		{
			name: "Download CSV unknown", answer: csvStep(csvFile),
			call: downloadCall(bouncer.DownloadBatchRequest{
				BatchID: testBatchID, Filter: bouncer.FilterUnknown, Format: bouncer.FormatCSV,
			}, io.Discard),
			method: http.MethodGet, path: pathDownload, rawQuery: "download=unknown", accept: mediaCSV,
		},
		{
			name: "Finish", answer: statusStep(http.StatusAccepted, `{}`),
			call: func(ctx context.Context, c *bouncer.Client) error {
				return c.Batches().Finish(ctx, bouncer.FinishBatchRequest{BatchID: testBatchID})
			},
			method: http.MethodPost, path: pathFinish, accept: mediaJSON,
		},
		{
			name: "Delete", answer: jsonStep(`{}`),
			call: func(ctx context.Context, c *bouncer.Client) error {
				return c.Batches().Delete(ctx, bouncer.DeleteBatchRequest{BatchID: testBatchID})
			},
			method: http.MethodDelete, path: pathBatchID, accept: mediaJSON,
		},
	}
}

func TestWire(t *testing.T) {
	t.Parallel()
	for _, proto := range testutil.Protocols() {
		for _, wc := range wireCases() {
			t.Run(proto.Name()+"/"+wc.name, func(t *testing.T) {
				t.Parallel()
				c, seen := wireServer(t, proto, wireStatic(wc.answer))
				require.NoError(t, wc.call(t.Context(), c))
				got := wireOnly(t, seen)

				assert.Equal(t, string(proto), got.proto)
				assert.Equal(t, wc.method, got.method)
				assert.Equal(t, wc.path, got.path)
				escaped := wc.escapedPath
				if escaped == "" {
					escaped = wc.path
				}
				assert.Equal(t, escaped, got.escapedPath)
				assert.Equal(t, wc.rawQuery, got.rawQuery)

				wireAssertHeaders(t, got, wc.accept, wc.body != "")
				wireAssertBody(t, proto, got, wc.method, wc.body)
			})
		}
	}
}

// wireAssertHeaders checks the headers the server saw: the SDK's own, plus
// only what the transport manages.
func wireAssertHeaders(t *testing.T, got wireSeen, accept string, withBody bool) {
	t.Helper()
	sdk := got.header.Clone()
	if ae := sdk.Values("Accept-Encoding"); len(ae) > 0 {
		assert.Equal(t, []string{"gzip"}, ae, "only the transport's own gzip negotiation")
	}
	sdk.Del("Accept-Encoding")
	sdk.Del("Content-Length")
	want := []string{"Accept", "User-Agent", "X-Api-Key"}
	if withBody {
		want = []string{"Accept", "Content-Type", "User-Agent", "X-Api-Key"}
	}
	assert.Equal(t, want, slices.Sorted(maps.Keys(sdk)), "exactly the SDK's headers")
	assert.Equal(t, []string{testKey}, got.header.Values("X-Api-Key"))
	assert.Equal(t, []string{accept}, got.header.Values("Accept"))
	assert.Equal(t, []string{"go-bouncer"}, got.header.Values("User-Agent"))
	if withBody {
		assert.Equal(t, []string{mediaJSON}, got.header.Values("Content-Type"))
	}
	for _, name := range []string{"Authorization", "Cookie", "Referer", "Idempotency-Key", "X-Idempotency-Key", "Expect"} {
		assert.Empty(t, got.header.Values(name), name)
	}
}

// wireAssertBody checks the body bytes and framing the server saw.
func wireAssertBody(t *testing.T, proto testutil.Protocol, got wireSeen, method, body string) {
	t.Helper()
	assert.Empty(t, got.transferEncoding, "never chunked")
	switch {
	case body != "":
		assert.Equal(t, body, string(got.body), "the exact body bytes: no HTML escaping, nothing substituted")
		assert.JSONEq(t, body, string(got.body))
		assert.Equal(t, int64(len(body)), got.contentLength)
		assert.Equal(t, []string{strconv.Itoa(len(body))}, got.header.Values("Content-Length"))
	case method == http.MethodPost:
		// Finish: a bodyless POST carries "Content-Length: 0", as servers
		// expect.
		assert.Empty(t, got.body)
		assert.Zero(t, got.contentLength)
		assert.Equal(t, []string{"0"}, got.header.Values("Content-Length"))
	default:
		assert.Empty(t, got.body)
		assert.Empty(t, got.header.Values("Content-Length"), "a GET or DELETE declares no length")
		if proto == testutil.HTTP1 {
			// On HTTP/1 the transport probes the SDK's empty body and drops it,
			// so the request is framed as bodyless.
			assert.Zero(t, got.contentLength)
		} else {
			// On HTTP/2 (an injected transport only) the empty body ends the
			// stream with an empty DATA frame instead of on the HEADERS frame,
			// so the server sees an unknown length, then no bytes.
			assert.Equal(t, int64(-1), got.contentLength)
		}
	}
}

func TestWireServerDecodesTheQuery(t *testing.T) {
	t.Parallel()
	emails := []string{testEmail, "a+b c@example.com", "x&email=y@example.org", "zoë@example.com", "%41@example.net"}
	for _, proto := range testutil.Protocols() {
		for _, email := range emails {
			t.Run(proto.Name()+"/"+email, func(t *testing.T) {
				t.Parallel()
				var decoded string
				c, _ := wireServer(t, proto, func(r *http.Request) testutil.Step {
					q := r.URL.Query()
					decoded = q.Get("email")
					if len(q) != 1 || len(q["email"]) != 1 {
						decoded = "unexpected query"
					}
					return jsonStep(verifyOK)
				})
				_, err := c.Verify(t.Context(), bouncer.VerifyRequest{Email: email})
				require.NoError(t, err)
				assert.Equal(t, email, decoded, "the server reads back exactly the address sent")
			})
		}
	}

	t.Run("callback", func(t *testing.T) {
		t.Parallel()
		var decoded string
		c, _ := wireServer(t, testutil.HTTP1, func(r *http.Request) testutil.Step {
			decoded = r.URL.Query().Get("callback")
			return jsonStep(batchQueued)
		})
		callback := "https://hooks.example.org/a+b?x=1&y=%20#"
		callback = callback[:len(callback)-1] // no fragment
		_, err := c.Batches().Create(t.Context(), bouncer.CreateBatchRequest{
			Entries: []bouncer.BatchEntry{{Email: testEmail}}, CallbackURL: callback,
		})
		require.NoError(t, err)
		assert.Equal(t, callback, decoded)
	})
}

func TestWireEscapedBatchIDs(t *testing.T) {
	t.Parallel()
	tests := []struct {
		id      bouncer.BatchID
		escaped string
	}{
		{`a"b`, "a%22b"},
		{"a[b]", "a%5Bb%5D"},
		{"a{b}", "a%7Bb%7D"},
		{"a<b>", "a%3Cb%3E"},
		{"a|b", "a%7Cb"},
		{"a^b", "a%5Eb"},
		{"a`b", "a%60b"},
		{"a;b", "a%3Bb"},
		{"a,b", "a%2Cb"},
		{"a:b", "a:b"},
		{"a@b", "a@b"},
		{"a+b", "a+b"},
		{"a=b&c", "a=b&c"},
		{"a~b_c.d-e", "a~b_c.d-e"},
		{"...", "..."},
		{"sync2", "sync2"},
	}
	for _, proto := range testutil.Protocols() {
		for _, tt := range tests {
			t.Run(proto.Name()+"/"+string(tt.id), func(t *testing.T) {
				t.Parallel()
				answer, err := json.Marshal(map[string]string{"batchId": string(tt.id), "status": "completed"})
				require.NoError(t, err)
				c, seen := wireServer(t, proto, wireStatic(jsonStep(string(answer))))
				ctx := t.Context()
				st, err := c.Batches().Status(ctx, bouncer.BatchStatusRequest{BatchID: tt.id})
				require.NoError(t, err)
				assert.Equal(t, tt.id, st.ID)
				require.NoError(t, c.Batches().Finish(ctx, bouncer.FinishBatchRequest{BatchID: tt.id}))
				_, err = c.Batches().Download(ctx, bouncer.DownloadBatchRequest{BatchID: tt.id, Format: bouncer.FormatJSON},
					io.Discard)
				require.Error(t, err, "the answer is an object, not an array")

				all := seen()
				require.Len(t, all, 3)
				for i, suffix := range []string{"", "/finish", "/download"} {
					assert.Equal(t, pathBatch+"/"+string(tt.id)+suffix, all[i].path, "the server decodes one segment")
					assert.Equal(t, pathBatch+"/"+tt.escaped+suffix, all[i].escapedPath)
				}
			})
		}
	}
}
