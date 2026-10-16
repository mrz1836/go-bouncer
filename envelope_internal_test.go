package bouncer

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"testing/iotest"
	"time"
	"unicode/utf8"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/mrz1836/go-bouncer/internal/testutil"
)

// errEnvelopeBoom is a read failure.
var errEnvelopeBoom = errors.New("boom")

func TestEnvelopeStatusShapes(t *testing.T) {
	t.Parallel()
	tests := []struct {
		raw  string
		want int
	}{
		{`400`, 400},
		{`"400"`, 400},
		{`100`, 100},
		{`"599"`, 599},
		{`599`, 599},
		{`99`, 0},
		{`"099"`, 0},
		{`600`, 0},
		{`"600"`, 0},
		{`4000`, 0},
		{`"4000"`, 0},
		{`"40"`, 0},
		{`"4xx"`, 0},
		{`400.0`, 0},
		{`4e2`, 0},
		{`-400`, 0},
		{`" 400"`, 0},
		{`"400 "`, 0},
		{`"queued"`, 0},
		{`"deliverable"`, 0},
		{`true`, 0},
		{`null`, 0},
		{`["400"]`, 0},
		{``, 0},
		{`"`, 0},
		{`"４00"`, 0},
	}
	for _, tt := range tests {
		t.Run(tt.raw, func(t *testing.T) {
			t.Parallel()
			var raw json.RawMessage
			if tt.raw != "" {
				raw = json.RawMessage(tt.raw)
			}
			assert.Equal(t, tt.want, envelopeStatus(raw))
		})
	}
}

func TestReadEnvelopeShapes(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		body     string
		ok       bool
		status   int
		hasError bool
		message  string
	}{
		{"full", `{"status":"402","error":"Payment Required","message":"m"}`, true, 402, true, `"m"`},
		{"numeric", `{"status":400,"error":"x"}`, true, 400, true, ""},
		{"whitespace", " \r\n\t{\"status\":404}\n", true, 404, false, ""},
		{"null error", `{"status":500,"error":null}`, true, 500, false, ""},
		{"error object", `{"error":{"code":7}}`, true, 0, true, ""},
		{"word status", `{"status":"queued"}`, true, 0, false, ""},
		{"empty object", `{}`, true, 0, false, ""},
		{"message number", `{"message":5}`, true, 0, false, `5`},
		{"array", `[{"status":400}]`, false, 0, false, ""},
		{"string", `"x"`, false, 0, false, ""},
		{"empty", ``, false, 0, false, ""},
		{"whitespace only", "  ", false, 0, false, ""},
		{"unclosed", `{"status":400`, false, 0, false, ""},
		{"trailing data", `{"status":400} {}`, false, 0, false, ""},
		{"invalid UTF-8", "{\"status\":400,\"message\":\"\xff\"}", false, 0, false, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			env, ok := readEnvelope([]byte(tt.body))
			assert.Equal(t, tt.ok, ok)
			assert.Equal(t, tt.status, env.status)
			assert.Equal(t, tt.hasError, env.hasError)
			assert.Equal(t, tt.message, string(env.message))
		})
	}
}

func TestRetryAfterHeaderParsing(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 3, 4, 5, 6, 7, 0, time.UTC)
	date := func(d time.Duration) string { return now.Add(d).Format(http.TimeFormat) }
	tests := []struct {
		name   string
		values []string
		want   time.Duration
		ok     bool
	}{
		{"seconds", []string{"120"}, 120 * time.Second, true},
		{"zero", []string{"0"}, 0, true},
		{"spaces trimmed", []string{" \t7\t "}, 7 * time.Second, true},
		{"exactly 24h", []string{"86400"}, 24 * time.Hour, true},
		{"over 24h", []string{"86401"}, 24 * time.Hour, true},
		{"six digits", []string{"100000"}, 24 * time.Hour, true},
		{"overflow", []string{"99999999999999999999999999"}, 24 * time.Hour, true},
		{"leading zeros", []string{"000001"}, time.Second, true},
		{"date ahead", []string{date(90 * time.Second)}, 90 * time.Second, true},
		{"date far ahead", []string{date(72 * time.Hour)}, 24 * time.Hour, true},
		{"date now", []string{date(0)}, 0, true},
		{"date behind", []string{date(-time.Hour)}, 0, true},
		{"RFC 850 date", []string{now.Add(time.Minute).Format(time.RFC850)}, time.Minute, true},
		{"asctime date", []string{now.Add(2 * time.Minute).Format(time.ANSIC)}, 2 * time.Minute, true},
		{"absent", nil, 0, false},
		{"two values", []string{"5", "6"}, 0, false},
		{"empty", []string{""}, 0, false},
		{"negative", []string{"-5"}, 0, false},
		{"fraction", []string{"1.5"}, 0, false},
		{"plus sign", []string{"+5"}, 0, false},
		{"word", []string{"soon"}, 0, false},
		{"seconds with unit", []string{"5s"}, 0, false},
		{"list", []string{"5, 6"}, 0, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			h := http.Header{}
			for _, v := range tt.values {
				h.Add("Retry-After", v)
			}
			got, ok := retryAfter(h, now)
			assert.Equal(t, tt.ok, ok, "ok")
			assert.Equal(t, tt.want, got, "duration")
		})
	}
}

func TestTruncateUTF8Boundaries(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		s    string
		n    int
		want string
	}{
		{"short", "abc", 5, "abc"},
		{"exact", "abcde", 5, "abcde"},
		{"ascii cut", "abcdef", 5, "abcde"},
		{"before a two-byte rune", "abcdé", 5, "abcd"},
		{"after a two-byte rune", "abcé", 5, "abcé"},
		{"inside a four-byte rune", "ab😀", 4, "ab"},
		{"all multibyte", "ééé", 3, "é"},
		{"zero", "abc", 0, ""},
		{"empty", "", 3, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := truncateUTF8(tt.s, tt.n)
			assert.Equal(t, tt.want, got)
			assert.LessOrEqual(t, len(got), max(tt.n, 0))
			assert.True(t, utf8.ValidString(got))
		})
	}
}

// envelopeAllOps returns every Operation.
func envelopeAllOps() []Operation {
	return []Operation{
		OpVerify, OpBatchSync, OpCredits, OpBatchCreate, OpBatchStatus, OpBatchResults, OpBatchDownload,
		OpBatchFinish, OpBatchDelete,
	}
}

func TestStatusKindPerOperation(t *testing.T) {
	t.Parallel()
	batch := map[Operation]bool{
		OpBatchStatus: true, OpBatchResults: true, OpBatchDownload: true, OpBatchFinish: true, OpBatchDelete: true,
	}
	for _, op := range envelopeAllOps() {
		assert.Equal(t, batch[op], namesBatch(op), "namesBatch(%s)", op)
		tests := []struct {
			code int
			want FailureKind
		}{
			{400, FailureRejected},
			{401, FailureUnauthorized},
			{402, FailurePaymentRequired},
			{403, FailureForbidden},
			{404, FailureNotFound},
			{409, FailureRejected},
			{413, FailureRejected},
			{418, FailureRejected},
			{429, FailureRateLimited},
			{499, FailureRejected},
			{500, FailureUpstream},
			{502, FailureUpstream},
			{503, FailureUnavailable},
			{504, FailureUpstream},
			{599, FailureUpstream},
			{600, FailureUnexpectedResponse},
			{399, FailureUnexpectedResponse},
			{200, FailureUnexpectedResponse},
			{0, FailureUnexpectedResponse},
		}
		for _, tt := range tests {
			assert.Equal(t, tt.want, statusKind(tt.code, op), "statusKind(%d, %s)", tt.code, op)
		}
		want405 := FailureRejected
		if batch[op] {
			want405 = FailureBatchState
		}
		assert.Equal(t, want405, statusKind(http.StatusMethodNotAllowed, op), "405 on %s", op)
	}
}

func TestAcceptedSuccessStatuses(t *testing.T) {
	t.Parallel()
	want := map[Operation][]int{
		OpBatchCreate: {200, 201, 202},
		OpBatchFinish: {200, 202, 204},
		OpBatchDelete: {200, 202, 204},
	}
	for _, op := range envelopeAllOps() {
		ok, special := want[op]
		if !special {
			ok = []int{200}
		}
		for code := 200; code < 300; code++ {
			expect := false
			for _, c := range ok {
				expect = expect || c == code
			}
			assert.Equal(t, expect, accepted(op, code), "accepted(%s, %d)", op, code)
		}
	}
	assert.True(t, isAck(OpBatchFinish))
	assert.True(t, isAck(OpBatchDelete))
	assert.False(t, isAck(OpBatchStatus))
}

func TestContentTypeHeaderParsing(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		values []string
		media  string
		ok     bool
		json   bool
	}{
		{"none", nil, "", true, true},
		{"json", []string{"application/json"}, "application/json", true, true},
		{"charset", []string{"application/json; charset=UTF-8"}, "application/json", true, true},
		{"uppercase", []string{"APPLICATION/JSON"}, "application/json", true, true},
		{"problem+json", []string{"application/problem+json"}, "application/problem+json", true, true},
		{"vendor+json", []string{"application/vnd.example+json"}, "application/vnd.example+json", true, true},
		{"csv", []string{"text/csv"}, "text/csv", true, false},
		{"html", []string{"text/html; charset=utf-8"}, "text/html", true, false},
		{"jsonp lookalike", []string{"application/jsonp"}, "application/jsonp", true, false},
		{"two", []string{"application/json", "application/json"}, "", false, false},
		{"empty value", []string{""}, "", false, false},
		{"bad parameter", []string{"application/json; charset"}, "", false, false},
		{"no subtype", []string{"/json"}, "", false, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			h := http.Header{}
			for _, v := range tt.values {
				h.Add("Content-Type", v)
			}
			media, ok := contentType(h)
			assert.Equal(t, tt.media, media)
			assert.Equal(t, tt.ok, ok)
			assert.Equal(t, tt.json, hasJSONType(h))
		})
	}
}

func TestEncodedHeaderCodings(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		values []string
		want   bool
	}{
		{"none", nil, false},
		{"identity", []string{"identity"}, false},
		{"Identity", []string{"Identity"}, false},
		{"empty", []string{""}, false},
		{"empty elements", []string{" , identity ,\t"}, false},
		{"gzip", []string{"gzip"}, true},
		{"br", []string{"br"}, true},
		{"zstd", []string{"zstd"}, true},
		{"identity then gzip", []string{"identity, gzip"}, true},
		{"second header", []string{"identity", "gzip"}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			h := http.Header{}
			for _, v := range tt.values {
				h.Add("Content-Encoding", v)
			}
			assert.Equal(t, tt.want, encoded(h))
		})
	}
}

func TestCapReaderLimit(t *testing.T) {
	t.Parallel()
	t.Run("exactly the limit", func(t *testing.T) {
		t.Parallel()
		r := &capReader{r: strings.NewReader("abcde"), limit: 5}
		data, err := io.ReadAll(r)
		require.NoError(t, err)
		assert.Equal(t, "abcde", string(data))
		assert.False(t, r.exceeded)
		assert.Equal(t, int64(5), r.read)
	})
	t.Run("one byte over", func(t *testing.T) {
		t.Parallel()
		r := &capReader{r: strings.NewReader("abcdef"), limit: 5}
		data, err := io.ReadAll(r)
		require.ErrorIs(t, err, errResponseTooLarge)
		assert.Equal(t, "abcde", string(data), "the bytes within the limit are passed on")
		assert.True(t, r.exceeded)
		n, err := r.Read(make([]byte, 4))
		assert.Zero(t, n)
		require.ErrorIs(t, err, errResponseTooLarge, "every read after the overflow fails")
	})
	t.Run("one byte at a time", func(t *testing.T) {
		t.Parallel()
		r := &capReader{r: iotest.OneByteReader(strings.NewReader("abcdef")), limit: 5}
		data, err := io.ReadAll(r)
		require.ErrorIs(t, err, errResponseTooLarge)
		assert.Equal(t, "abcde", string(data))
	})
	t.Run("limit of one", func(t *testing.T) {
		t.Parallel()
		r := &capReader{r: strings.NewReader("ab"), limit: 1}
		data, err := io.ReadAll(r)
		require.ErrorIs(t, err, errResponseTooLarge)
		assert.Equal(t, "a", string(data))
	})
	t.Run("data with EOF", func(t *testing.T) {
		t.Parallel()
		r := &capReader{r: iotest.DataErrReader(strings.NewReader("abc")), limit: 3}
		data, err := io.ReadAll(r)
		require.NoError(t, err)
		assert.Equal(t, "abc", string(data))
	})
	t.Run("read errors pass through", func(t *testing.T) {
		t.Parallel()
		r := &capReader{r: iotest.ErrReader(io.ErrUnexpectedEOF), limit: 3}
		_, err := r.Read(make([]byte, 8))
		require.ErrorIs(t, err, io.ErrUnexpectedEOF)
	})
	t.Run("never asks for more than limit plus one", func(t *testing.T) {
		t.Parallel()
		var asked int
		src := testutil.NewBody(strings.Repeat("x", 100))
		r := &capReader{r: readerFunc(func(p []byte) (int, error) {
			asked = max(asked, len(p))
			return src.Read(p)
		}), limit: 10}
		_, _ = io.ReadAll(r)
		assert.LessOrEqual(t, asked, 11)
	})
}

// readerFunc adapts a function to io.Reader.
type readerFunc func([]byte) (int, error)

// Read returns f(p).
func (f readerFunc) Read(p []byte) (int, error) { return f(p) }

func TestProgressReaderStall(t *testing.T) {
	t.Parallel()
	t.Run("stalls after 100 empty reads", func(t *testing.T) {
		t.Parallel()
		body := testutil.NewBody("")
		body.Stall = true
		p := &progressReader{r: body}
		buf := make([]byte, 4)
		for range maxEmptyReads - 1 {
			n, err := p.Read(buf)
			require.Zero(t, n)
			require.NoError(t, err)
		}
		_, err := p.Read(buf)
		require.ErrorIs(t, err, errTransportStalled)
	})
	t.Run("progress resets the count", func(t *testing.T) {
		t.Parallel()
		body := testutil.NewBody("abc")
		body.Step = 1
		body.Empties = maxEmptyReads - 1
		data, err := io.ReadAll(&progressReader{r: body})
		require.NoError(t, err)
		assert.Equal(t, "abc", string(data))
	})
	t.Run("empty buffers do not count", func(t *testing.T) {
		t.Parallel()
		p := &progressReader{r: strings.NewReader("a")}
		for range maxEmptyReads * 2 {
			n, err := p.Read(nil)
			require.Zero(t, n)
			require.NoError(t, err)
		}
		data, err := io.ReadAll(p)
		require.NoError(t, err)
		assert.Equal(t, "a", string(data))
	})
}

func TestReadBodyLimits(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		body     string
		declared int64
		limit    int64
		want     string
		err      error
	}{
		{"declared exact", "abcde", 5, 10, "abcde", nil},
		{"unknown length", "abcde", -1, 10, "abcde", nil},
		{"declared longer than sent", "abc", 5, 10, "abc", nil},
		{"declared shorter than sent", "abcdef", 3, 10, "abcdef", nil},
		{"over the limit, unknown length", "abcdefghijk", -1, 10, "abcdefghij", errResponseTooLarge},
		{"over the limit, short declaration", "abcdefghijk", 2, 10, "abcdefghij", errResponseTooLarge},
		{"at the limit", "abcdefghij", 10, 10, "abcdefghij", nil},
		{"empty", "", 0, 10, "", nil},
		{
			"large declaration reads by growth", strings.Repeat("y", 2048), maxPrealloc + 1, maxPrealloc + 10,
			strings.Repeat("y", 2048), nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			data, err := readBody(strings.NewReader(tt.body), tt.declared, tt.limit)
			if tt.err != nil {
				require.ErrorIs(t, err, tt.err)
			} else {
				require.NoError(t, err)
			}
			assert.Equal(t, tt.want, string(data))
		})
	}
	t.Run("stalled", func(t *testing.T) {
		t.Parallel()
		body := testutil.NewBody("ab")
		body.Stall = true
		_, err := readBody(body, -1, 10)
		require.ErrorIs(t, err, errTransportStalled)
	})
	t.Run("truncated", func(t *testing.T) {
		t.Parallel()
		assert.True(t, truncated(3, 5))
		assert.True(t, truncated(6, 5))
		assert.False(t, truncated(5, 5))
		assert.False(t, truncated(5, -1))
	})
	t.Run("excerpt", func(t *testing.T) {
		t.Parallel()
		assert.Nil(t, excerpt(strings.NewReader("x"), maxErrorBodyBytes+1), "declared too long")
		assert.Nil(t, excerpt(strings.NewReader(strings.Repeat("x", maxErrorBodyBytes+1)), -1), "found too long")
		assert.Nil(t, excerpt(iotest.ErrReader(errEnvelopeBoom), -1), "failed read")
		exact := strings.Repeat("x", maxErrorBodyBytes)
		assert.Equal(t, exact, string(excerpt(strings.NewReader(exact), int64(len(exact)))))
	})
}

func TestBlankAndSkipSpace(t *testing.T) {
	t.Parallel()
	assert.True(t, blank(nil))
	assert.True(t, blank([]byte(" \t\r\n")))
	assert.False(t, blank([]byte(" x")))
	assert.False(t, blank([]byte("\v")), "only JSON whitespace counts")
	assert.False(t, blank([]byte(" ")), "only JSON whitespace counts")
	assert.Equal(t, 2, skipSpace([]byte("\n {")))
	assert.Equal(t, 3, skipSpace([]byte("   ")))
	assert.Zero(t, skipSpace(bytes.Repeat([]byte("x"), 3)))
}

func TestDiagnosticsFromRaw(t *testing.T) {
	t.Parallel()
	c := &Client{diagnostics: true, scrub: func(s string) string { return strings.ReplaceAll(s, testKey, "[redacted]") }}
	assert.Equal(t, "m", c.diagnosticsFrom(json.RawMessage(`"m"`)).Message)
	assert.Equal(t, "a [redacted] b", c.diagnosticsFrom(json.RawMessage(strconv.Quote("a "+testKey+" b"))).Message)
	assert.Empty(t, c.diagnosticsFrom(nil).Message)
	assert.Empty(t, c.diagnosticsFrom(json.RawMessage(`5`)).Message)
	assert.Empty(t, c.diagnosticsFrom(json.RawMessage(`"unterminated`)).Message)
	off := &Client{scrub: c.scrub}
	assert.Empty(t, off.diagnosticsFrom(json.RawMessage(`"m"`)).Message)
}
