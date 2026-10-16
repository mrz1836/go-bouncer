package bouncer

import (
	"encoding/json"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/mrz1836/go-bouncer/internal/testutil"
)

func TestDecodeVerificationRules(t *testing.T) {
	t.Parallel()
	const head = `{"email":"avery.example@example.com","status":"risky","reason":"low_quality"`
	record := func(members string) []byte { return []byte(head + members + "}") }
	for _, tc := range []struct {
		name    string
		raw     []byte
		prefix  string
		kind    FailureKind
		cause   error
		field   string
		wantErr bool
	}{
		{name: "baseline", raw: record("")},
		{
			name: "missing email", raw: []byte(`{"status":"risky","reason":"low_quality"}`), prefix: "[4]",
			wantErr: true, kind: FailureMalformedResponse, cause: errMissingField, field: "[4].email",
		},
		{
			name: "null status", raw: []byte(`{"email":"a@example.com","status":null,"reason":"x"}`),
			wantErr: true, kind: FailureMalformedResponse, cause: errMissingField, field: "status",
		},
		{
			name: "empty reason", raw: []byte(`{"email":"a@example.com","status":"x","reason":""}`),
			wantErr: true, kind: FailureMalformedResponse, cause: errMissingField, field: "reason",
		},
		{
			name: "reason of the wrong type", raw: []byte(`{"email":"a@example.com","status":"x","reason":1}`),
			wantErr: true, kind: FailureMalformedResponse, cause: errWrongType, field: "reason",
		},
		{
			name: "score fraction", raw: record(`,"score":1.5`), prefix: "[2]",
			wantErr: true, kind: FailureMalformedResponse, cause: errWrongType, field: "[2].score",
		},
		{
			name: "toxicity numeric string", raw: record(`,"toxicity":"3"`),
			wantErr: true, kind: FailureMalformedResponse, cause: errWrongType, field: "toxicity",
		},
		{
			name: "domain array", raw: record(`,"domain":[]`),
			wantErr: true, kind: FailureMalformedResponse, cause: errWrongType, field: "domain",
		},
		{
			name: "account flag object", raw: record(`,"account":{"role":{}}`), prefix: "[0]",
			wantErr: true, kind: FailureMalformedResponse, cause: errWrongType, field: "[0].account.role",
		},
		{
			name: "dns type number", raw: record(`,"dns":{"type":1}`),
			wantErr: true, kind: FailureMalformedResponse, cause: errWrongType, field: "dns.type",
		},
		{
			name: "invalid UTF-8", raw: record(`,"provider":"` + "\xff" + `"`), prefix: "[9]",
			wantErr: true, kind: FailureMalformedResponse, cause: errInvalidUTF8, field: "[9]",
		},
		{
			name: "not an object", raw: []byte(`[1]`), prefix: "[1]",
			wantErr: true, kind: FailureMalformedResponse, cause: errWrongKind, field: "[1]",
		},
		{
			name: "invalid JSON", raw: []byte(`{"email":`),
			wantErr: true, kind: FailureMalformedResponse, cause: errInvalidJSON, field: "",
		},
		{
			name: "text over the bound", raw: record(`,"name":"` + strings.Repeat("n", maxTextBytes+1) + `"`),
			prefix: "[3]", wantErr: true, kind: FailureResponseTooLarge, cause: errFieldTooLarge, field: "[3].name",
		},
		{
			name: "nested text over the bound", raw: record(`,"domain":{"name":"` + strings.Repeat("d", maxTextBytes+1) + `"}`),
			wantErr: true, kind: FailureResponseTooLarge, cause: errFieldTooLarge, field: "domain.name",
		},
		{
			name: "record over the bound", raw: []byte(head + `,"x":"` + strings.Repeat("x", maxRecordBytes) + `"}`),
			prefix: "[5]", wantErr: true, kind: FailureResponseTooLarge, cause: errFieldTooLarge, field: "[5]",
		},
		{
			name: "first failure in member order", raw: record(`,"dns":7,"toxic":1,"score":"s"`),
			wantErr: true, kind: FailureMalformedResponse, cause: errWrongType, field: "score",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			v, derr := decodeVerification(tc.raw, tc.prefix)
			if !tc.wantErr {
				require.Nil(t, derr)
				assert.Equal(t, Verification{
					Email: "avery.example@example.com", Status: StatusRisky,
					Reason: ReasonLowQuality,
				}, v)
				return
			}
			assert.Equal(t, Verification{}, v, "a failure returns no partial value")
			requireDecodeError(t, derr, tc.kind, tc.cause, tc.field)
		})
	}
}

func TestDecodeVerificationFixture(t *testing.T) {
	t.Parallel()
	v, derr := decodeVerification(testutil.Fixture(t, "synthetic/verification_full.json"), "")
	require.Nil(t, derr)
	assert.Equal(t, Verification{
		Email:      "avery.example@example.com",
		Status:     StatusDeliverable,
		Reason:     ReasonAcceptedEmail,
		Domain:     &Domain{Name: "example.com", AcceptAll: FlagNo, Disposable: FlagNo, Free: FlagYes},
		Account:    &Account{Role: FlagNo, Disabled: FlagNo, FullMailbox: FlagNo},
		DNS:        &DNS{Type: "MX", Record: "mx1.example.com"},
		Provider:   "example-mail",
		Score:      new(94),
		Toxic:      FlagUnknown,
		Toxicity:   new(0),
		RetryAfter: "2026-01-02T03:04:05.678Z",
		DidYouMean: "avery.example@example.org",
	}, v)
}

func TestDecodeVerificationRecordBound(t *testing.T) {
	t.Parallel()
	const head = `{"email":"avery.example@example.com","status":"risky","reason":"low_quality","x":"`
	exact := head + strings.Repeat("x", maxRecordBytes-len(head)-2) + `"}`
	require.Len(t, exact, maxRecordBytes)
	_, derr := decodeVerification([]byte(exact), "")
	require.Nil(t, derr, "a record of exactly 64 KiB decodes")

	over := head + strings.Repeat("x", maxRecordBytes-len(head)-1) + `"}`
	require.Len(t, over, maxRecordBytes+1)
	_, derr = decodeVerification([]byte(over), "[0]")
	requireDecodeError(t, derr, FailureResponseTooLarge, errFieldTooLarge, "[0]")
}

func TestDecodeErrorCallError(t *testing.T) {
	t.Parallel()
	ce := malformed("[3].score", errWrongType).callError(OpBatchResults, 200)
	assert.Equal(t, FailureMalformedResponse, ce.Kind)
	assert.Equal(t, OpBatchResults, ce.Op)
	assert.Equal(t, 200, ce.StatusCode)
	assert.Equal(t, "[3].score", ce.Field)
	require.ErrorIs(t, ce, ErrMalformedResponse)
	require.ErrorIs(t, ce, errWrongType)
	assert.Equal(t, "bouncer: batch_results: malformed_response (HTTP 200): [3].score", ce.Error())
	assert.Equal(t, errWrongType.Error(), malformed("f", errWrongType).Error())

	big := tooLarge("provider")
	assert.Equal(t, FailureResponseTooLarge, big.kind)
	require.ErrorIs(t, big.callError(OpVerify, 200), ErrResponseTooLarge)
}

func TestJSONString(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		raw  string
		want string
		ok   bool
	}{
		{`"abc"`, "abc", true},
		{`""`, "", true},
		{`"a\"b"`, `a"b`, true},
		{`"a\\b"`, `a\b`, true},
		{`"été"`, "été", true},
		{`"tab\tnew\nline"`, "tab\tnew\nline", true},
		{`"\u00e9t\u00e9"`, "été", true},
		{`"😀"`, "😀", true},
		{`"a\x"`, "", false}, // an invalid escape
		{`"\u00zz"`, "", false},
		{`abc`, "", false},
		{`1`, "", false},
		{`null`, "", false},
		{`true`, "", false},
		{`{}`, "", false},
		{`["x"]`, "", false},
		{`"`, "", false},
		{``, "", false},
	} {
		t.Run(tc.raw, func(t *testing.T) {
			t.Parallel()
			got, ok := jsonString(json.RawMessage(tc.raw))
			assert.Equal(t, tc.ok, ok)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestJSONInteger(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		raw     string
		bitSize int
		want    int64
		ok      bool
	}{
		{"0", 64, 0, true},
		{"-0", 64, 0, true},
		{"7", 64, 7, true},
		{"-45", 64, -45, true},
		{"9223372036854775807", 64, 9223372036854775807, true},
		{"-9223372036854775808", 64, -9223372036854775808, true},
		{"9223372036854775808", 64, 0, false},
		{"-9223372036854775809", 64, 0, false},
		{"2147483647", 32, 2147483647, true},
		{"2147483648", 32, 0, false},
		{strconv.Itoa(int(^uint(0) >> 1)), strconv.IntSize, int64(^uint(0) >> 1), true},
		{"007", 64, 0, false},
		{"01", 64, 0, false},
		{"-01", 64, 0, false},
		{"00", 64, 0, false},
		{"1.0", 64, 0, false},
		{"1.5", 64, 0, false},
		{"1e2", 64, 0, false},
		{"1E2", 64, 0, false},
		{"+1", 64, 0, false},
		{"-", 64, 0, false},
		{"", 64, 0, false},
		{`"1"`, 64, 0, false},
		{" 1", 64, 0, false},
		{"0x10", 64, 0, false},
		{"null", 64, 0, false},
		{"true", 64, 0, false},
	} {
		t.Run(tc.raw+"/"+strconv.Itoa(tc.bitSize), func(t *testing.T) {
			t.Parallel()
			got, ok := jsonInteger(json.RawMessage(tc.raw), tc.bitSize)
			assert.Equal(t, tc.ok, ok)
			if tc.ok {
				assert.Equal(t, tc.want, got)
			}
		})
	}
}

func TestFieldDecoderFirstFailureWins(t *testing.T) {
	t.Parallel()
	d := &fieldDecoder{prefix: "[3]"}
	assert.Equal(t, "ok", d.text(json.RawMessage(`"ok"`), "a"))
	assert.Empty(t, d.text(json.RawMessage(`5`), "b"))
	requireDecodeError(t, d.err, FailureMalformedResponse, errWrongType, "[3].b")

	// Every later call is a no-op that returns the zero value.
	assert.Empty(t, d.text(json.RawMessage(`"fine"`), "c"))
	assert.Empty(t, d.required(json.RawMessage(`"fine"`), "d"))
	assert.Empty(t, d.required(nil, "e"))
	assert.Nil(t, d.count(json.RawMessage(`9`), "f"))
	assert.Nil(t, d.lenientInt(json.RawMessage(`9`), "g"))
	var w domainWire
	assert.False(t, d.object(json.RawMessage(`{"name":"x"}`), "h", &w))
	assert.Nil(t, w.Name, "a no-op never decodes")
	requireDecodeError(t, d.err, FailureMalformedResponse, errWrongType, "[3].b")

	n := d.nested("domain")
	assert.Equal(t, "[3].domain", n.prefix)
	assert.Same(t, d.err, n.err, "a nested decoder inherits the failure")
	assert.Empty(t, n.text(json.RawMessage(`"x"`), "name"))

	t.Run("adopt keeps the first failure", func(t *testing.T) {
		t.Parallel()
		parent := &fieldDecoder{}
		child := parent.nested("dns")
		child.fail("type", errWrongType)
		parent.adopt(child)
		requireDecodeError(t, parent.err, FailureMalformedResponse, errWrongType, "dns.type")
		other := parent.nested("account")
		other.err = malformed("account.role", errMissingField)
		parent.adopt(other)
		requireDecodeError(t, parent.err, FailureMalformedResponse, errWrongType, "dns.type")
	})
	t.Run("invalid raw input", func(t *testing.T) {
		t.Parallel()
		// A RawMessage member is always valid JSON; these guard the decoder
		// against raw input that is not.
		d := &fieldDecoder{}
		assert.Empty(t, d.text(json.RawMessage(`"a\x"`), "provider"))
		requireDecodeError(t, d.err, FailureMalformedResponse, errWrongType, "provider")
		d = &fieldDecoder{}
		var w domainWire
		assert.False(t, d.object(json.RawMessage(`{"name":`), "domain", &w))
		requireDecodeError(t, d.err, FailureMalformedResponse, errInvalidJSON, "domain")
	})
	t.Run("too large text", func(t *testing.T) {
		t.Parallel()
		d := &fieldDecoder{}
		assert.Empty(t, d.text(json.RawMessage(`"`+strings.Repeat("t", maxTextBytes+1)+`"`), "provider"))
		requireDecodeError(t, d.err, FailureResponseTooLarge, errFieldTooLarge, "provider")
		assert.Equal(t, strings.Repeat("t", maxTextBytes),
			(&fieldDecoder{}).text(json.RawMessage(`"`+strings.Repeat("t", maxTextBytes)+`"`), "provider"))
	})
	t.Run("required", func(t *testing.T) {
		t.Parallel()
		for _, tc := range []struct {
			raw   json.RawMessage
			cause error
		}{
			{nil, errMissingField},
			{json.RawMessage(`null`), errMissingField},
			{json.RawMessage(`""`), errMissingField},
			{json.RawMessage(`0`), errWrongType},
			{json.RawMessage(`[]`), errWrongType},
		} {
			d := &fieldDecoder{prefix: "p"}
			assert.Empty(t, d.required(tc.raw, "email"))
			requireDecodeError(t, d.err, FailureMalformedResponse, tc.cause, "p.email")
		}
	})
	t.Run("lenient integers", func(t *testing.T) {
		t.Parallel()
		d := &fieldDecoder{}
		assert.Nil(t, d.lenientInt(nil, "score"))
		assert.Nil(t, d.lenientInt(json.RawMessage(`null`), "score"))
		assert.Nil(t, d.lenientInt(json.RawMessage(`""`), "score"))
		assert.Equal(t, new(0), d.lenientInt(json.RawMessage(`0`), "score"))
		assert.Nil(t, d.err)
		assert.Nil(t, d.lenientInt(json.RawMessage(`" "`), "score"))
		requireDecodeError(t, d.err, FailureMalformedResponse, errWrongType, "score")
	})
	t.Run("counts are strict", func(t *testing.T) {
		t.Parallel()
		d := &fieldDecoder{}
		assert.Nil(t, d.count(nil, "quantity"))
		assert.Nil(t, d.count(json.RawMessage(`null`), "quantity"))
		assert.Equal(t, new(int64(0)), d.count(json.RawMessage(`0`), "quantity"))
		assert.Nil(t, d.err)
		assert.Nil(t, d.count(json.RawMessage(`""`), "quantity"), `"" is not a count`)
		requireDecodeError(t, d.err, FailureMalformedResponse, errWrongType, "quantity")
	})
}

func TestUnmarshalRecordKinds(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name  string
		raw   string
		cause error
	}{
		{"object", `{"a":1}`, nil},
		{"object with whitespace", " \n{}\t", nil},
		{"invalid UTF-8", "{\"a\":\"\xff\"}", errInvalidUTF8},
		{"empty", ``, errInvalidJSON},
		{"whitespace", " \r\n", errInvalidJSON},
		{"array", `[1]`, errWrongKind},
		{"string", `"x"`, errWrongKind},
		{"null", `null`, errWrongKind},
		{"number", `12`, errWrongKind},
		{"broken literal", `nul`, errInvalidJSON},
		{"broken array", `[1`, errInvalidJSON},
		{"unterminated object", `{"a":`, errInvalidJSON},
		{"trailing data", `{"a":1} x`, errInvalidJSON},
		{"two objects", `{}{}`, errInvalidJSON},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var w struct {
				A json.RawMessage `json:"a"`
			}
			derr := unmarshalRecord([]byte(tc.raw), "[7]", &w)
			if tc.cause == nil {
				require.Nil(t, derr)
				return
			}
			requireDecodeError(t, derr, FailureMalformedResponse, tc.cause, "[7]")
		})
	}
}

func TestDecodeBatchFixtures(t *testing.T) {
	t.Parallel()
	t.Run("created", func(t *testing.T) {
		t.Parallel()
		b, derr := decodeBatch(testutil.Fixture(t, "synthetic/batch_created.json"))
		require.Nil(t, derr)
		assert.Equal(t, &Batch{
			ID: "5f0c2b9e8d7a6b5c4d3e2f1a", State: BatchStateQueued, Created: "2026-01-02T03:04:05.678Z",
			Quantity: new(int64(2)), Duplicates: new(int64(0)),
		}, b)
	})
	t.Run("completed with stats", func(t *testing.T) {
		t.Parallel()
		b, derr := decodeBatch(testutil.Fixture(t, "synthetic/batch_status_completed.json"))
		require.Nil(t, derr)
		assert.Equal(t, &Batch{
			ID: "5f0c2b9e8d7a6b5c4d3e2f1a", State: BatchStateCompleted,
			Created: "2026-01-02T03:04:05.678Z", Started: "2026-01-02T03:04:06.789Z",
			Completed: "2026-01-02T03:09:10.111Z", Quantity: new(int64(2)), Duplicates: new(int64(0)),
			CreditsUsed: new(int64(2)), Processed: new(int64(2)),
			Stats: &BatchStats{
				Deliverable: new(int64(1)), Risky: new(int64(1)), Undeliverable: new(int64(0)), Unknown: new(int64(0)),
			},
		}, b)
	})
}

func TestDecodeBatchRules(t *testing.T) {
	t.Parallel()
	const id = `"batchId":"5f0c2b9e8d7a6b5c4d3e2f1a"`
	for _, tc := range []struct {
		name  string
		raw   string
		cause error
		field string
		kind  FailureKind
	}{
		{"missing batchId", `{"status":"queued"}`, errMissingField, "batchId", FailureMalformedResponse},
		{"null batchId", `{"batchId":null,"status":"queued"}`, errMissingField, "batchId", FailureMalformedResponse},
		{"empty batchId", `{"batchId":"","status":"queued"}`, errMissingField, "batchId", FailureMalformedResponse},
		{"numeric batchId", `{"batchId":12,"status":"queued"}`, errWrongType, "batchId", FailureMalformedResponse},
		{"missing status", `{` + id + `}`, errMissingField, "status", FailureMalformedResponse},
		{"boolean status", `{` + id + `,"status":true}`, errWrongType, "status", FailureMalformedResponse},
		{
			"string counter", `{` + id + `,"status":"queued","quantity":"2"}`, errWrongType, "quantity",
			FailureMalformedResponse,
		},
		{
			"fractional counter", `{` + id + `,"status":"queued","duplicates":2.0}`, errWrongType, "duplicates",
			FailureMalformedResponse,
		},
		{
			"empty-string counter", `{` + id + `,"status":"completed","credits":""}`, errWrongType, "credits",
			FailureMalformedResponse,
		},
		{
			"boolean counter", `{` + id + `,"status":"queued","processed":false}`, errWrongType, "processed",
			FailureMalformedResponse,
		},
		{
			"completed flag", `{` + id + `,"status":"completed","completed":true}`, errWrongType, "completed",
			FailureMalformedResponse,
		},
		{
			"numeric timestamp", `{` + id + `,"status":"queued","created":1700000000}`, errWrongType, "created",
			FailureMalformedResponse,
		},
		{"stats array", `{` + id + `,"status":"queued","stats":[]}`, errWrongType, "stats", FailureMalformedResponse},
		{
			"stats counter string", `{` + id + `,"status":"queued","stats":{"risky":"1"}}`, errWrongType, "stats.risky",
			FailureMalformedResponse,
		},
		{
			"long timestamp", `{` + id + `,"status":"queued","started":"` + strings.Repeat("9", maxTextBytes+1) + `"}`,
			errFieldTooLarge, "started", FailureResponseTooLarge,
		},
		{
			"a counter failure comes before the ID check", `{"batchId":"a/b","status":"queued","quantity":"x"}`,
			errWrongType, "quantity", FailureMalformedResponse,
		},
		{"not an object", `[{` + id + `,"status":"queued"}]`, errWrongKind, "", FailureMalformedResponse},
		{"null", `null`, errWrongKind, "", FailureMalformedResponse},
		{"invalid UTF-8", `{` + id + `,"status":"` + "\xff" + `"}`, errInvalidUTF8, "", FailureMalformedResponse},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			b, derr := decodeBatch([]byte(tc.raw))
			assert.Nil(t, b)
			requireDecodeError(t, derr, tc.kind, tc.cause, tc.field)
		})
	}

	t.Run("absent, null and zero counters", func(t *testing.T) {
		t.Parallel()
		b, derr := decodeBatch([]byte(`{` + id + `,"status":"processing","quantity":0,"duplicates":null,` +
			`"stats":{"deliverable":0,"risky":null}}`))
		require.Nil(t, derr)
		assert.Equal(t, new(int64(0)), b.Quantity, "a reported zero")
		assert.Nil(t, b.Duplicates, "null is not reported")
		assert.Nil(t, b.CreditsUsed, "absent is not reported")
		assert.Nil(t, b.Processed)
		assert.Equal(t, &BatchStats{Deliverable: new(int64(0))}, b.Stats)
	})
	t.Run("stats absent, null and empty", func(t *testing.T) {
		t.Parallel()
		for raw, want := range map[string]*BatchStats{
			``:              nil,
			`,"stats":null`: nil,
			`,"stats":{}`:   {},
		} {
			b, derr := decodeBatch([]byte(`{` + id + `,"status":"queued"` + raw + `}`))
			require.Nil(t, derr)
			assert.Equal(t, want, b.Stats, "stats%s", raw)
		}
	})
	t.Run("timestamps and states are kept verbatim", func(t *testing.T) {
		t.Parallel()
		b, derr := decodeBatch([]byte(`{` + id + `,"status":"paused","created":"not a time",` +
			`"started":"2026-01-02 03:04:05","completed":""}`))
		require.Nil(t, derr)
		assert.Equal(t, BatchState("paused"), b.State)
		assert.False(t, b.State.Known())
		assert.Equal(t, Timestamp("not a time"), b.Created)
		assert.Equal(t, Timestamp("2026-01-02 03:04:05"), b.Started)
		assert.Equal(t, Timestamp(""), b.Completed)
	})
	t.Run("negative and large counters are not range-checked", func(t *testing.T) {
		t.Parallel()
		b, derr := decodeBatch([]byte(`{` + id + `,"status":"queued","quantity":-1,"credits":9007199254740993}`))
		require.Nil(t, derr)
		assert.Equal(t, new(int64(-1)), b.Quantity)
		assert.Equal(t, new(int64(9007199254740993)), b.CreditsUsed, "kept exactly, beyond float64 precision")
	})
}

func TestBatchIDHint(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		raw  string
		want BatchID
	}{
		{`{"batchId":"5f0c2b9e8d7a6b5c4d3e2f1a"}`, "5f0c2b9e8d7a6b5c4d3e2f1a"},
		{`{"batchId":"5f0c2b9e8d7a6b5c4d3e2f1a","status":7}`, "5f0c2b9e8d7a6b5c4d3e2f1a"},
		{`{"batchId":"a/b"}`, ""},
		{`{"batchId":12}`, ""},
		{`{"batchId":""}`, ""},
		{`{"id":"5f0c2b9e8d7a6b5c4d3e2f1a"}`, ""},
		{`["5f0c2b9e8d7a6b5c4d3e2f1a"]`, ""},
		{`{"batchId":"5f0c`, ""},
		{``, ""},
	} {
		assert.Equal(t, tc.want, batchIDHint([]byte(tc.raw)), tc.raw)
	}
}

func TestDecodeCredits(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name  string
		raw   string
		want  int64
		cause error
		field string
	}{
		{name: "fixture", raw: `{"credits":12345}`, want: 12345},
		{name: "zero", raw: `{"credits":0}`, want: 0},
		{name: "negative", raw: `{"credits":-3}`, want: -3},
		{name: "extra members", raw: `{"credits":5,"plan":"x"}`, want: 5},
		{name: "missing", raw: `{}`, cause: errMissingField, field: "credits"},
		{name: "null", raw: `{"credits":null}`, cause: errMissingField, field: "credits"},
		{name: "string", raw: `{"credits":"5"}`, cause: errWrongType, field: "credits"},
		{name: "fraction", raw: `{"credits":1.5}`, cause: errWrongType, field: "credits"},
		{name: "exponent", raw: `{"credits":1e3}`, cause: errWrongType, field: "credits"},
		{name: "overflow", raw: `{"credits":99999999999999999999}`, cause: errWrongType, field: "credits"},
		{name: "array", raw: `[{"credits":5}]`, cause: errWrongKind, field: ""},
		{name: "number", raw: `5`, cause: errWrongKind, field: ""},
		{name: "invalid JSON", raw: `{"credits":`, cause: errInvalidJSON, field: ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, derr := decodeCredits([]byte(tc.raw))
			if tc.cause == nil {
				require.Nil(t, derr)
				assert.Equal(t, &CreditBalance{Credits: tc.want}, got)
				return
			}
			assert.Nil(t, got)
			requireDecodeError(t, derr, FailureMalformedResponse, tc.cause, tc.field)
		})
	}
	t.Run("fixture file", func(t *testing.T) {
		t.Parallel()
		got, derr := decodeCredits(testutil.Fixture(t, "synthetic/credits.json"))
		require.Nil(t, derr)
		assert.Equal(t, &CreditBalance{Credits: 12345}, got)
	})
}

func TestBatchStateKnownAndTerminal(t *testing.T) {
	t.Parallel()
	for _, s := range []BatchState{BatchStateQueued, BatchStateProcessing, BatchStateCompleted} {
		assert.True(t, s.Known(), "state %q", s)
		assert.Equal(t, s == BatchStateCompleted, s.Terminal(), "state %q", s)
	}
	for _, s := range []BatchState{"", "Completed", "failed", "finished", "deleted"} {
		assert.False(t, s.Known(), "state %q", s)
		assert.False(t, s.Terminal(), "state %q", s)
	}
}

// TestDecodeBatchKeepsAnyBatchID checks that decodeBatch keeps a batchId that
// is not a usable handle as it is: Create refuses it as malformed, and Status
// as another batch's answer.
func TestDecodeBatchKeepsAnyBatchID(t *testing.T) {
	t.Parallel()
	for _, id := range []string{"a/b", "Sync", "..", "a b", strings.Repeat("f", 129)} {
		t.Run(id[:min(len(id), 8)], func(t *testing.T) {
			t.Parallel()
			raw, err := json.Marshal(map[string]string{"batchId": id, "status": "queued"})
			require.NoError(t, err)
			b, derr := decodeBatch(raw)
			require.Nil(t, derr)
			assert.Equal(t, BatchID(id), b.ID)
			assert.NotEmpty(t, batchIDProblem(b.ID))
		})
	}
}

// TestDecodeRejectsLoneSurrogates checks that a \u escape of a UTF-16
// surrogate outside a valid pair fails as invalid UTF-8, rather than being
// rewritten to U+FFFD, while valid pairs and escaped backslashes decode.
func TestDecodeRejectsLoneSurrogates(t *testing.T) {
	t.Parallel()
	record := func(email string) []byte {
		return []byte(`{"email":"` + email + `","status":"deliverable","reason":"accepted_email"}`)
	}
	for _, tc := range []struct {
		name  string
		email string
		want  string // the decoded email, or "" when it must fail
	}{
		{"lone low surrogate", `a\udc00@example.com`, ""},
		{"lone high surrogate", `a\ud83d@example.com`, ""},
		{"high surrogate at the end", `a@example.com\ud83d`, ""},
		{"high surrogate then a non-surrogate escape", `a\ud83dA@example.com`, ""},
		{"high surrogate then another high", `a\ud83d\ud83d@example.com`, ""},
		{"valid pair", `a\ud83d\ude00@example.com`, "a\U0001F600@example.com"},
		{"uppercase hex pair", `a\uD83D\uDE00@example.com`, "a\U0001F600@example.com"},
		{"escaped backslash before u", `a\\udc00@example.com`, `a\udc00@example.com`},
		{"plain escape", `a\u0041@example.com`, "aA@example.com"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			v, derr := decodeVerification(record(tc.email), "[2]")
			if tc.want == "" {
				require.NotNil(t, derr)
				assert.Equal(t, FailureMalformedResponse, derr.kind)
				assert.Equal(t, errInvalidUTF8, derr.cause)
				assert.Equal(t, "[2].email", derr.field)
				return
			}
			require.Nil(t, derr)
			assert.Equal(t, tc.want, v.Email)
		})
	}
}

func TestHex4(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		in   string
		want rune
		ok   bool
	}{
		{"0000", 0, true},
		{"d83D", 0xd83d, true},
		{"FfFf", 0xffff, true},
		{"00g0", 0, false},
		{"12 4", 0, false},
	} {
		got, ok := hex4([]byte(tc.in))
		assert.Equal(t, tc.ok, ok, tc.in)
		assert.Equal(t, tc.want, got, tc.in)
	}
	assert.False(t, loneSurrogate([]byte(`"a\uzzzz"`)), "an escape that is not hexadecimal is no surrogate")
	assert.True(t, loneSurrogate([]byte(`"\ud83d\uzzzz"`)), "a high surrogate before a non-hex escape is lone")
}

// TestScrubberNeverLeavesTheKey checks the diagnostics scrubber, including
// keys that share characters with its own replacement text.
func TestScrubberNeverLeavesTheKey(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct{ key, in, want string }{
		{testKey, "bad key " + testKey + " sent", "bad key [redacted] sent"},
		{"]abc123", "]abc123abc123", ""},
		{"act", "react", ""},
		{"[redacted]", "key [redacted]", ""},
		{"zz", "no key here", "no key here"},
	} {
		t.Run(tc.key, func(t *testing.T) {
			t.Parallel()
			out := scrubber(tc.key)(tc.in)
			assert.Equal(t, tc.want, out)
			assert.NotContains(t, out, tc.key)
		})
	}
}
