package bouncer_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/mrz1836/go-bouncer"
	"github.com/mrz1836/go-bouncer/internal/testutil"
)

// verifyBody calls Verify against one scripted 200 answer with body.
func verifyBody(t *testing.T, body string) (*bouncer.Verification, error) {
	t.Helper()
	c, _ := newScriptClient(t, jsonStep(body))
	return c.Verify(t.Context(), bouncer.VerifyRequest{Email: testEmail})
}

// verifyRecord wraps members after the three required ones into a record.
func verifyRecord(members string) string {
	head := `{"email":"avery.example@example.com","status":"risky","reason":"low_quality"`
	if members == "" {
		return head + "}"
	}
	return head + "," + members + "}"
}

// requireVerifyFailure checks that Verify failed on body with kind at field.
func requireVerifyFailure(t *testing.T, body string, kind bouncer.FailureKind, field string) {
	t.Helper()
	v, err := verifyBody(t, body)
	assert.Nil(t, v)
	requireCallError(t, err, wantCall{Kind: kind, Op: bouncer.OpVerify, StatusCode: 200, Field: field})
}

func TestVerificationEnumsKnown(t *testing.T) {
	t.Parallel()
	statuses := []bouncer.Status{
		bouncer.StatusDeliverable, bouncer.StatusRisky, bouncer.StatusUndeliverable, bouncer.StatusUnknown,
	}
	assert.Equal(t, []string{"deliverable", "risky", "undeliverable", "unknown"},
		[]string{string(statuses[0]), string(statuses[1]), string(statuses[2]), string(statuses[3])})
	for _, s := range statuses {
		assert.True(t, s.Known(), "status %q", s)
	}
	for _, s := range []bouncer.Status{"", "Deliverable", "valid", "accept_all"} {
		assert.False(t, s.Known(), "status %q", s)
	}

	reasons := map[bouncer.Reason]string{
		bouncer.ReasonAcceptedEmail:     "accepted_email",
		bouncer.ReasonLowDeliverability: "low_deliverability",
		bouncer.ReasonLowQuality:        "low_quality",
		bouncer.ReasonInvalidEmail:      "invalid_email",
		bouncer.ReasonInvalidDomain:     "invalid_domain",
		bouncer.ReasonRejectedEmail:     "rejected_email",
		bouncer.ReasonDNSError:          "dns_error",
		bouncer.ReasonUnavailableSMTP:   "unavailable_smtp",
		bouncer.ReasonUnsupported:       "unsupported",
		bouncer.ReasonTimeout:           "timeout",
		bouncer.ReasonUnknown:           "unknown",
	}
	assert.Len(t, reasons, 11)
	for r, text := range reasons {
		assert.Equal(t, text, string(r))
		assert.True(t, r.Known(), "reason %q", r)
	}
	for _, r := range []bouncer.Reason{"", "Accepted_Email", "smtp_error", "accepted email"} {
		assert.False(t, r.Known(), "reason %q", r)
	}

	flags := map[bouncer.Flag]string{bouncer.FlagYes: "yes", bouncer.FlagNo: "no", bouncer.FlagUnknown: "unknown"}
	for f, text := range flags {
		assert.Equal(t, text, string(f))
		assert.True(t, f.Known(), "flag %q", f)
	}
	for _, f := range []bouncer.Flag{"", "Yes", "true", "1", "partial"} {
		assert.False(t, f.Known(), "flag %q", f)
	}
}

func TestVerifyDecodesEveryDocumentedValue(t *testing.T) {
	t.Parallel()
	for _, s := range []bouncer.Status{
		bouncer.StatusDeliverable, bouncer.StatusRisky, bouncer.StatusUndeliverable, bouncer.StatusUnknown,
	} {
		for _, r := range []bouncer.Reason{
			bouncer.ReasonAcceptedEmail, bouncer.ReasonLowDeliverability, bouncer.ReasonLowQuality,
			bouncer.ReasonInvalidEmail, bouncer.ReasonInvalidDomain, bouncer.ReasonRejectedEmail,
			bouncer.ReasonDNSError, bouncer.ReasonUnavailableSMTP, bouncer.ReasonUnsupported,
			bouncer.ReasonTimeout, bouncer.ReasonUnknown,
		} {
			t.Run(string(s)+"/"+string(r), func(t *testing.T) {
				t.Parallel()
				v, err := verifyBody(t, `{"email":"avery.example@example.com","status":"`+string(s)+
					`","reason":"`+string(r)+`"}`)
				require.NoError(t, err)
				assert.Equal(t, s, v.Status)
				assert.Equal(t, r, v.Reason)
			})
		}
	}
	for _, f := range []bouncer.Flag{bouncer.FlagYes, bouncer.FlagNo, bouncer.FlagUnknown} {
		t.Run("flag/"+string(f), func(t *testing.T) {
			t.Parallel()
			v, err := verifyBody(t, verifyRecord(`"domain":{"name":"example.com","acceptAll":"`+string(f)+
				`","disposable":"`+string(f)+`","free":"`+string(f)+`"},"account":{"role":"`+string(f)+
				`","disabled":"`+string(f)+`","fullMailbox":"`+string(f)+`"},"toxic":"`+string(f)+`"`))
			require.NoError(t, err)
			assert.Equal(t, &bouncer.Domain{Name: "example.com", AcceptAll: f, Disposable: f, Free: f}, v.Domain)
			assert.Equal(t, &bouncer.Account{Role: f, Disabled: f, FullMailbox: f}, v.Account)
			assert.Equal(t, f, v.Toxic)
		})
	}
}

func TestVerifyKeepsUnknownValues(t *testing.T) {
	t.Parallel()
	v, err := verifyBody(t, `{"email":"avery.example@example.com","status":"quarantined","reason":"greylisted",`+
		`"domain":{"name":"example.com","acceptAll":"partial","disposable":"YES","free":"no"},"toxic":"maybe"}`)
	require.NoError(t, err)
	assert.Equal(t, bouncer.Status("quarantined"), v.Status)
	assert.False(t, v.Status.Known())
	assert.Equal(t, bouncer.Reason("greylisted"), v.Reason)
	assert.False(t, v.Reason.Known())
	assert.Equal(t, bouncer.Flag("partial"), v.Domain.AcceptAll)
	assert.False(t, v.Domain.AcceptAll.Known())
	assert.Equal(t, bouncer.Flag("YES"), v.Domain.Disposable, "kept verbatim, never case-folded")
	assert.False(t, v.Domain.Disposable.Known())
	assert.Equal(t, bouncer.Flag("maybe"), v.Toxic)
}

// fullVerification is testdata/synthetic/verification_full.json, decoded.
func fullVerification() bouncer.Verification {
	return bouncer.Verification{
		Email:  "avery.example@example.com",
		Status: bouncer.StatusDeliverable,
		Reason: bouncer.ReasonAcceptedEmail,
		Domain: &bouncer.Domain{
			Name: "example.com", AcceptAll: bouncer.FlagNo, Disposable: bouncer.FlagNo, Free: bouncer.FlagYes,
		},
		Account:    &bouncer.Account{Role: bouncer.FlagNo, Disabled: bouncer.FlagNo, FullMailbox: bouncer.FlagNo},
		DNS:        &bouncer.DNS{Type: "MX", Record: "mx1.example.com"},
		Provider:   "example-mail",
		Score:      new(94),
		Toxic:      bouncer.FlagUnknown,
		Toxicity:   new(0),
		RetryAfter: "2026-01-02T03:04:05.678Z",
		DidYouMean: "avery.example@example.org",
	}
}

func TestVerifyDecodesFixtures(t *testing.T) {
	t.Parallel()
	t.Run("full", func(t *testing.T) {
		t.Parallel()
		v, err := verifyBody(t, string(testutil.Fixture(t, "synthetic/verification_full.json")))
		require.NoError(t, err)
		assert.Equal(t, fullVerification(), *v)
	})
	t.Run("minimal", func(t *testing.T) {
		t.Parallel()
		v, err := verifyBody(t, string(testutil.Fixture(t, "synthetic/verification_minimal.json")))
		require.NoError(t, err)
		assert.Equal(t, bouncer.Verification{
			Email: "blake.example@example.net", Status: bouncer.StatusUnknown, Reason: bouncer.ReasonTimeout,
		}, *v)
	})
	t.Run("email echoed verbatim", func(t *testing.T) {
		t.Parallel()
		v, err := verifyBody(t, `{"email":" Avery.Example@Example.com. ","status":"risky","reason":"low_quality"}`)
		require.NoError(t, err)
		assert.Equal(t, " Avery.Example@Example.com. ", v.Email, "the echo is never trimmed or lowercased")
	})
	t.Run("escaped strings", func(t *testing.T) {
		t.Parallel()
		v, err := verifyBody(t, verifyRecord(`"provider":"example \"mail\"","didYouMean":"tab\there"`))
		require.NoError(t, err)
		assert.Equal(t, `example "mail"`, v.Provider)
		assert.Equal(t, "tab\there", v.DidYouMean)
	})
}

func TestVerifyRequiredFields(t *testing.T) {
	t.Parallel()
	members := map[string]string{
		"email":  `"email":"avery.example@example.com"`,
		"status": `"status":"risky"`,
		"reason": `"reason":"low_quality"`,
	}
	record := func(name, replacement string) string {
		parts := make([]string, 0, 3)
		for _, n := range []string{"email", "status", "reason"} {
			switch {
			case n != name:
				parts = append(parts, members[n])
			case replacement != "":
				parts = append(parts, `"`+n+`":`+replacement)
			}
		}
		return "{" + strings.Join(parts, ",") + "}"
	}
	for _, name := range []string{"email", "status", "reason"} {
		for _, tc := range []struct {
			name        string
			replacement string
		}{
			{"absent", ""},
			{"null", "null"},
			{"empty", `""`},
			{"number", "7"},
			{"boolean", "true"},
			{"object", `{}`},
			{"array", `["x"]`},
		} {
			t.Run(name+"/"+tc.name, func(t *testing.T) {
				t.Parallel()
				requireVerifyFailure(t, record(name, tc.replacement), bouncer.FailureMalformedResponse, name)
			})
		}
	}
	t.Run("whitespace is a value", func(t *testing.T) {
		t.Parallel()
		v, err := verifyBody(t, `{"email":" ","status":" ","reason":" "}`)
		require.NoError(t, err)
		assert.Equal(t, " ", v.Email)
		assert.Equal(t, bouncer.Status(" "), v.Status)
	})
}

func TestVerifyLenientIntegers(t *testing.T) {
	t.Parallel()
	for _, field := range []string{"score", "toxicity"} {
		get := func(v *bouncer.Verification) *int {
			if field == "score" {
				return v.Score
			}
			return v.Toxicity
		}
		for _, tc := range []struct {
			name  string
			raw   string // "" means absent
			want  *int
			fails bool
		}{
			{name: "absent", raw: ""},
			{name: "null", raw: "null"},
			{name: "empty string", raw: `""`},
			{name: "zero", raw: "0", want: new(0)},
			{name: "value", raw: "87", want: new(87)},
			{name: "negative", raw: "-3", want: new(-3)},
			{name: "beyond the documented range", raw: "150", want: new(150)},
			{name: "numeric string", raw: `"87"`, fails: true},
			{name: "blank string", raw: `" "`, fails: true},
			{name: "fraction", raw: "1.5", fails: true},
			{name: "integral fraction", raw: "87.0", fails: true},
			{name: "exponent", raw: "1e2", fails: true},
			{name: "boolean", raw: "true", fails: true},
			{name: "object", raw: "{}", fails: true},
			{name: "array", raw: "[]", fails: true},
			{name: "overflow", raw: "99999999999999999999", fails: true},
		} {
			t.Run(field+"/"+tc.name, func(t *testing.T) {
				t.Parallel()
				members := ""
				if tc.raw != "" {
					members = `"` + field + `":` + tc.raw
				}
				if tc.fails {
					requireVerifyFailure(t, verifyRecord(members), bouncer.FailureMalformedResponse, field)
					return
				}
				v, err := verifyBody(t, verifyRecord(members))
				require.NoError(t, err)
				assert.Equal(t, tc.want, get(v))
			})
		}
	}
}

func TestVerifyOptionalObjects(t *testing.T) {
	t.Parallel()
	t.Run("absent and null", func(t *testing.T) {
		t.Parallel()
		for _, raw := range []string{"", `"domain":null,"account":null,"dns":null`} {
			v, err := verifyBody(t, verifyRecord(raw))
			require.NoError(t, err)
			assert.Nil(t, v.Domain)
			assert.Nil(t, v.Account)
			assert.Nil(t, v.DNS)
		}
	})
	t.Run("empty objects", func(t *testing.T) {
		t.Parallel()
		v, err := verifyBody(t, verifyRecord(`"domain":{},"account":{},"dns":{}`))
		require.NoError(t, err)
		assert.Equal(t, &bouncer.Domain{}, v.Domain)
		assert.Equal(t, &bouncer.Account{}, v.Account)
		assert.Equal(t, &bouncer.DNS{}, v.DNS)
	})
	t.Run("null members", func(t *testing.T) {
		t.Parallel()
		v, err := verifyBody(t, verifyRecord(`"domain":{"name":null,"acceptAll":null},"dns":{"type":null}`))
		require.NoError(t, err)
		assert.Equal(t, &bouncer.Domain{}, v.Domain)
		assert.Equal(t, &bouncer.DNS{}, v.DNS)
	})
	for _, name := range []string{"domain", "account", "dns"} {
		for _, raw := range []string{`"x"`, `1`, `true`, `[]`, `[{}]`} {
			t.Run(name+"/wrong type "+raw, func(t *testing.T) {
				t.Parallel()
				requireVerifyFailure(t, verifyRecord(`"`+name+`":`+raw), bouncer.FailureMalformedResponse, name)
			})
		}
	}
	for _, tc := range []struct{ members, field string }{
		{`"domain":{"acceptAll":true}`, "domain.acceptAll"},
		{`"domain":{"name":5}`, "domain.name"},
		{`"domain":{"disposable":{}}`, "domain.disposable"},
		{`"domain":{"free":["yes"]}`, "domain.free"},
		{`"account":{"role":false}`, "account.role"},
		{`"account":{"disabled":0}`, "account.disabled"},
		{`"account":{"fullMailbox":1}`, "account.fullMailbox"},
		{`"dns":{"type":15}`, "dns.type"},
		{`"dns":{"record":["mx1.example.com"]}`, "dns.record"},
	} {
		t.Run("nested "+tc.field, func(t *testing.T) {
			t.Parallel()
			requireVerifyFailure(t, verifyRecord(tc.members), bouncer.FailureMalformedResponse, tc.field)
		})
	}
}

func TestVerifyOptionalStrings(t *testing.T) {
	t.Parallel()
	for _, name := range []string{"provider", "toxic", "retryAfter", "didYouMean", "name"} {
		t.Run(name+"/null", func(t *testing.T) {
			t.Parallel()
			v, err := verifyBody(t, verifyRecord(`"`+name+`":null`))
			require.NoError(t, err)
			assert.Equal(t, verifyBaseline(), *v)
		})
		for _, raw := range []string{"1", "true", "{}", `["x"]`} {
			t.Run(name+"/wrong type "+raw, func(t *testing.T) {
				t.Parallel()
				requireVerifyFailure(t, verifyRecord(`"`+name+`":`+raw), bouncer.FailureMalformedResponse, name)
			})
		}
	}
	t.Run("retryAfter is opaque", func(t *testing.T) {
		t.Parallel()
		v, err := verifyBody(t, verifyRecord(`"retryAfter":"in a while, perhaps"`))
		require.NoError(t, err)
		assert.Equal(t, "in a while, perhaps", v.RetryAfter)
	})
}

// verifyBaseline is verifyRecord(""), decoded.
func verifyBaseline() bouncer.Verification {
	return bouncer.Verification{Email: testEmail, Status: bouncer.StatusRisky, Reason: bouncer.ReasonLowQuality}
}

func TestVerifyMemberRules(t *testing.T) {
	t.Parallel()
	t.Run("unknown members are ignored", func(t *testing.T) {
		t.Parallel()
		v, err := verifyBody(t, verifyRecord(`"futureField":{"nested":[1,{"x":null}]},"another":5,"domain2":"x"`))
		require.NoError(t, err)
		assert.Equal(t, verifyBaseline(), *v)
	})
	t.Run("a repeated member keeps its last value", func(t *testing.T) {
		t.Parallel()
		v, err := verifyBody(t, `{"email":"avery.example@example.com","status":"risky","reason":"low_quality",`+
			`"status":"deliverable","score":1,"score":2}`)
		require.NoError(t, err)
		assert.Equal(t, bouncer.StatusDeliverable, v.Status)
		assert.Equal(t, new(2), v.Score)
	})
	t.Run("a repeated member is judged by its last value", func(t *testing.T) {
		t.Parallel()
		v, err := verifyBody(t, verifyRecord(`"score":"bad","score":3`))
		require.NoError(t, err)
		assert.Equal(t, new(3), v.Score)
		requireVerifyFailure(t, verifyRecord(`"score":3,"score":"bad"`), bouncer.FailureMalformedResponse, "score")
	})
	t.Run("member names match without regard to case", func(t *testing.T) {
		t.Parallel()
		// encoding/json matches a member case-insensitively when no exact
		// match exists; the package documents this.
		v, err := verifyBody(t, `{"EMAIL":"avery.example@example.com","Status":"risky","reason":"low_quality"}`)
		require.NoError(t, err)
		assert.Equal(t, verifyBaseline(), *v)
	})
	t.Run("first failure wins, in member order", func(t *testing.T) {
		t.Parallel()
		requireVerifyFailure(t, verifyRecord(`"dns":5,"score":"x"`), bouncer.FailureMalformedResponse, "score")
		requireVerifyFailure(t, `{"reason":1,"status":2}`, bouncer.FailureMalformedResponse, "email")
	})
}

func TestVerifyRejectsWrongShapes(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct{ name, body string }{
		{"array", `[` + verifyOK + `]`},
		{"null", `null`},
		{"string", `"avery.example@example.com"`},
		{"number", `7`},
		{"empty body", ``},
		{"whitespace", " \n\t "},
		{"invalid JSON", `{"email":`},
		{"trailing data", verifyOK + ` {}`},
		{"invalid UTF-8", `{"email":"avery.example@example.com","status":"risky","reason":"low_quality","provider":"` +
			"\xff\xfe" + `"}`},
		{"invalid UTF-8 in a member name", `{"email":"avery.example@example.com","status":"risky","reason":"low_quality","` +
			"\xc3" + `":1}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			requireVerifyFailure(t, tc.body, bouncer.FailureMalformedResponse, "")
		})
	}
}

func TestVerifySizeBounds(t *testing.T) {
	t.Parallel()
	const maxText = 4 << 10
	const maxRecord = 64 << 10
	for _, name := range []string{"email", "provider", "retryAfter", "didYouMean", "name"} {
		t.Run(name+" at the bound", func(t *testing.T) {
			t.Parallel()
			text := strings.Repeat("p", maxText)
			body := verifyRecord(`"` + name + `":"` + text + `"`)
			if name == "email" {
				body = `{"email":"` + text + `","status":"risky","reason":"low_quality"}`
			}
			_, err := verifyBody(t, body)
			require.NoError(t, err)
		})
		t.Run(name+" over the bound", func(t *testing.T) {
			t.Parallel()
			text := strings.Repeat("p", maxText+1)
			body := verifyRecord(`"` + name + `":"` + text + `"`)
			if name == "email" {
				body = `{"email":"` + text + `","status":"risky","reason":"low_quality"}`
			}
			requireVerifyFailure(t, body, bouncer.FailureResponseTooLarge, name)
		})
	}
	t.Run("nested text over the bound", func(t *testing.T) {
		t.Parallel()
		body := verifyRecord(`"dns":{"record":"` + strings.Repeat("r", maxText+1) + `"}`)
		requireVerifyFailure(t, body, bouncer.FailureResponseTooLarge, "dns.record")
	})
	t.Run("the bound counts decoded bytes", func(t *testing.T) {
		t.Parallel()
		// Six bytes on the wire per decoded byte: far over 4 KiB raw, exactly
		// 4 KiB decoded.
		body := verifyRecord(`"provider":"` + strings.Repeat(`\u0070`, maxText) + `"`)
		v, err := verifyBody(t, body)
		require.NoError(t, err)
		assert.Equal(t, strings.Repeat("p", maxText), v.Provider)
		requireVerifyFailure(t, verifyRecord(`"provider":"`+strings.Repeat(`\u0070`, maxText+1)+`"`),
			bouncer.FailureResponseTooLarge, "provider")
	})
	pad := func(total int) string {
		head := verifyRecord(`"padding":"`)
		head = strings.TrimSuffix(head, "}")
		n := total - len(head) - len(`"}`)
		return head + strings.Repeat("x", n) + `"}`
	}
	t.Run("record at the bound", func(t *testing.T) {
		t.Parallel()
		body := pad(maxRecord)
		require.Len(t, body, maxRecord)
		_, err := verifyBody(t, body)
		require.NoError(t, err)
	})
	t.Run("record over the bound", func(t *testing.T) {
		t.Parallel()
		body := pad(maxRecord + 1)
		require.Len(t, body, maxRecord+1)
		requireVerifyFailure(t, body, bouncer.FailureResponseTooLarge, "")
	})
}

func TestStreamedRecordsCarryTheirPath(t *testing.T) {
	t.Parallel()
	results := func(t *testing.T, body string) ([]bouncer.Verification, error) {
		t.Helper()
		c, _ := newScriptClient(t, jsonStep(body))
		return collect(c.Batches().Results(t.Context(), bouncer.BatchResultsRequest{BatchID: testBatchID}))
	}
	t.Run("mixed fixture", func(t *testing.T) {
		t.Parallel()
		got, err := results(t, string(testutil.Fixture(t, "synthetic/results_mixed.json")))
		require.NoError(t, err)
		require.Len(t, got, 3)
		assert.Equal(t, "row-1", got[0].Name)
		assert.Equal(t, new(91), got[0].Score)
		assert.Equal(t, new(0), got[1].Score, "a score of 0 is a real score")
		assert.Equal(t, bouncer.FlagYes, got[1].Domain.AcceptAll)
		assert.Nil(t, got[2].Score, `"" means not evaluated`)
		assert.Equal(t, bouncer.StatusUndeliverable, got[2].Status)
	})
	t.Run("Results", func(t *testing.T) {
		t.Parallel()
		got, err := results(t, `[`+verifyOK+`,`+verifyRecord(`"score":1.5`)+`]`)
		assert.Len(t, got, 1, "the record before the failure is yielded")
		requireCallError(t, err, wantCall{
			Kind: bouncer.FailureMalformedResponse, Op: bouncer.OpBatchResults, StatusCode: 200,
			BatchID: testBatchID, Field: "[1].score", Records: 1, checkCounts: true,
		})
	})
	t.Run("Results nested", func(t *testing.T) {
		t.Parallel()
		_, err := results(t, `[`+verifyOK+`,`+verifyOK+`,`+verifyRecord(`"domain":{"free":true}`)+`]`)
		requireCallError(t, err, wantCall{
			Kind: bouncer.FailureMalformedResponse, Op: bouncer.OpBatchResults, StatusCode: 200,
			BatchID: testBatchID, Field: "[2].domain.free",
		})
	})
	t.Run("an element with a numeric status is a malformed record, not an envelope", func(t *testing.T) {
		t.Parallel()
		_, err := results(t, `[{"email":"avery.example@example.com","status":400,"reason":"low_quality"}]`)
		requireCallError(t, err, wantCall{
			Kind: bouncer.FailureMalformedResponse, Op: bouncer.OpBatchResults, StatusCode: 200,
			BatchID: testBatchID, Field: "[0].status",
		})
	})
	t.Run("invalid UTF-8 in a record", func(t *testing.T) {
		t.Parallel()
		_, err := results(t, `[`+verifyRecord(`"provider":"`+"\xff"+`"`)+`]`)
		requireCallError(t, err, wantCall{
			Kind: bouncer.FailureMalformedResponse, Op: bouncer.OpBatchResults, StatusCode: 200,
			BatchID: testBatchID, Field: "[0]",
		})
	})
	t.Run("VerifyBatchSync", func(t *testing.T) {
		t.Parallel()
		c, _ := newScriptClient(t, jsonStep(`[`+verifyOK+`,{"email":"blake.example@example.net","reason":"timeout"}]`))
		res, err := c.VerifyBatchSync(t.Context(), bouncer.BatchSyncRequest{Emails: []string{testEmail, testEmail2}})
		assert.Nil(t, res)
		requireCallError(t, err, wantCall{
			Kind: bouncer.FailureMalformedResponse, Op: bouncer.OpBatchSync, StatusCode: 200, Field: "[1].status",
		})
	})
	t.Run("VerifyBatchSync fixture", func(t *testing.T) {
		t.Parallel()
		c, _ := newScriptClient(t, jsonStep(string(testutil.Fixture(t, "synthetic/sync_partial.json"))))
		res, err := c.VerifyBatchSync(t.Context(), bouncer.BatchSyncRequest{Emails: []string{testEmail, testEmail2}})
		require.NoError(t, err)
		assert.Equal(t, 2, res.Requested)
		require.Len(t, res.Available, 1)
		assert.Equal(t, bouncer.Verification{
			Email: testEmail, Status: bouncer.StatusDeliverable, Reason: bouncer.ReasonAcceptedEmail, Score: new(88),
		}, res.Available[0])
	})
}

func TestVerificationJSONRoundTrip(t *testing.T) {
	t.Parallel()
	t.Run("full", func(t *testing.T) {
		t.Parallel()
		v := fullVerification()
		data, err := json.Marshal(v)
		require.NoError(t, err)
		for _, member := range []string{
			`"email":"avery.example@example.com"`, `"acceptAll":"no"`, `"fullMailbox":"no"`, `"dns":{"type":"MX"`,
			`"score":94`, `"toxicity":0`, `"retryAfter":"2026-01-02T03:04:05.678Z"`, `"didYouMean":`,
		} {
			assert.Contains(t, string(data), member, "the provider's camelCase shape")
		}
		var back bouncer.Verification
		require.NoError(t, json.Unmarshal(data, &back))
		assert.Equal(t, v, back)
	})
	t.Run("nil and zero stay apart", func(t *testing.T) {
		t.Parallel()
		v := bouncer.Verification{
			Email: testEmail, Status: bouncer.StatusRisky, Reason: bouncer.ReasonLowQuality,
			Score: new(0),
		}
		data, err := json.Marshal(v)
		require.NoError(t, err)
		assert.JSONEq(t, `{"email":"avery.example@example.com","status":"risky","reason":"low_quality","score":0}`,
			string(data))
		var back bouncer.Verification
		require.NoError(t, json.Unmarshal(data, &back))
		assert.Equal(t, v, back)
		assert.Nil(t, back.Toxicity)
		assert.Nil(t, back.Domain)
	})
	t.Run("decoded answer survives", func(t *testing.T) {
		t.Parallel()
		v, err := verifyBody(t, string(testutil.Fixture(t, "synthetic/verification_full.json")))
		require.NoError(t, err)
		data, err := json.Marshal(v)
		require.NoError(t, err)
		again, err := verifyBody(t, string(data))
		require.NoError(t, err)
		assert.Equal(t, *v, *again, "marshaled output decodes through the SDK to the same value")
	})
}

func TestBatchJSONRoundTrip(t *testing.T) {
	t.Parallel()
	c, _ := newScriptClient(t, jsonStep(string(testutil.Fixture(t, "synthetic/batch_status_completed.json"))))
	b, err := c.Batches().Status(t.Context(), bouncer.BatchStatusRequest{BatchID: testBatchID, WithStats: true})
	require.NoError(t, err)
	assert.Equal(t, bouncer.Batch{
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
	}, *b)

	data, err := json.Marshal(b)
	require.NoError(t, err)
	for _, member := range []string{
		`"batchId":"5f0c2b9e8d7a6b5c4d3e2f1a"`, `"status":"completed"`, `"duplicates":0`, `"credits":2`,
		`"undeliverable":0`, `"completed":"2026-01-02T03:09:10.111Z"`,
	} {
		assert.Contains(t, string(data), member)
	}
	var back bouncer.Batch
	require.NoError(t, json.Unmarshal(data, &back))
	assert.Equal(t, *b, back)

	t.Run("unreported counters stay nil", func(t *testing.T) {
		t.Parallel()
		data, err := json.Marshal(bouncer.Batch{ID: testBatchID, State: bouncer.BatchStateQueued})
		require.NoError(t, err)
		assert.JSONEq(t, `{"batchId":"5f0c2b9e8d7a6b5c4d3e2f1a","status":"queued"}`, string(data))
	})
}
