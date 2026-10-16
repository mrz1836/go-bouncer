package bouncer

import (
	"encoding/json"
	"strconv"
	"strings"
	"unicode/utf8"
)

// Decoding bounds.
const (
	// maxRecordBytes bounds one verification record, and the object a
	// streamed answer holds instead of its array.
	maxRecordBytes = 64 << 10

	// maxTextBytes bounds every decoded text field of an answer.
	maxTextBytes = 4 << 10
)

// Verification is the provider's verdict on one address, as Verify,
// VerifyBatchSync and BatchService.Results return it. It holds contact data
// (the address, its domain and mailbox traits): treat it as personal data.
//
// Status and Reason are separate axes: Status is the verdict, and Reason the
// main cause behind it. StatusUnknown is a successful (and billed) answer,
// never an error. Every enumeration is open: a value newer than this SDK is
// kept as received, and its Known method reports false.
//
// It survives a JSON round trip through encoding/json under the provider's
// camelCase names, with nil kept apart from zero. Unmarshaling a raw provider
// body into it skips every check the SDK makes.
type Verification struct {
	// Email is the address as the provider echoed it, never normalized: it may
	// differ from the address sent, such as by stray spaces.
	Email string `json:"email"`

	// Status is the verdict.
	Status Status `json:"status"`

	// Reason is the main cause behind Status.
	Reason Reason `json:"reason"`

	// Domain describes the address's domain, or nil when not reported.
	Domain *Domain `json:"domain,omitempty"`

	// Account describes the mailbox, or nil when not reported.
	Account *Account `json:"account,omitempty"`

	// DNS is the domain's mail-routing record, or nil when not reported.
	DNS *DNS `json:"dns,omitempty"`

	// Provider names the mailbox provider, such as a hosted mail service, or
	// "" when not reported.
	Provider string `json:"provider,omitempty"`

	// Score is the provider's deliverability score, documented as an integer
	// from 0 to 100 (the SDK does not range-check it). nil means it was not
	// evaluated: absent, null or "". A pointer to 0 is a real score of 0.
	Score *int `json:"score,omitempty"`

	// Toxic is the provider's toxicity flag, or "" when not reported.
	Toxic Flag `json:"toxic,omitempty"`

	// Toxicity is the provider's toxicity level, documented as an integer from
	// 0 to 5 (the SDK does not range-check it), or nil when not reported.
	Toxicity *int `json:"toxicity,omitempty"`

	// RetryAfter is the provider's undocumented retryAfter member, kept as
	// opaque text. It is not the HTTP Retry-After header: the SDK never parses
	// it or acts on it.
	RetryAfter string `json:"retryAfter,omitempty"`

	// DidYouMean is the provider's suggestion for a likely typo, or "". The
	// provider describes it as not fully verified: the SDK never applies or
	// verifies it.
	DidYouMean string `json:"didYouMean,omitempty"`

	// Name is the BatchEntry.Name the provider echoed for a batch record, or
	// "". The echo is not a documented correlation key.
	Name string `json:"name,omitempty"`
}

// Domain describes the domain of a verified address.
type Domain struct {
	// Name is the domain name.
	Name string `json:"name,omitempty"`

	// AcceptAll reports a domain that accepts mail for any mailbox, so that a
	// single mailbox cannot be confirmed.
	AcceptAll Flag `json:"acceptAll,omitempty"`

	// Disposable reports a disposable-address domain.
	Disposable Flag `json:"disposable,omitempty"`

	// Free reports a free mail provider's domain.
	Free Flag `json:"free,omitempty"`
}

// Account describes the mailbox of a verified address.
type Account struct {
	// Role reports a role address, such as one for a team rather than a
	// person.
	Role Flag `json:"role,omitempty"`

	// Disabled reports a disabled mailbox.
	Disabled Flag `json:"disabled,omitempty"`

	// FullMailbox reports a mailbox that is full.
	FullMailbox Flag `json:"fullMailbox,omitempty"`
}

// DNS is the record mail for a verified address's domain is routed by.
type DNS struct {
	// Type is the record type, such as "MX" or "A".
	Type string `json:"type,omitempty"`

	// Record is the record's value, such as a mail host name.
	Record string `json:"record,omitempty"`
}

// Status is a verification verdict. It is an open set: see Known.
type Status string

// Documented verdicts.
const (
	// StatusDeliverable means the address accepts mail.
	StatusDeliverable Status = "deliverable"

	// StatusRisky means the address may accept mail, with a risk the Reason
	// and flags describe.
	StatusRisky Status = "risky"

	// StatusUndeliverable means the address does not accept mail.
	StatusUndeliverable Status = "undeliverable"

	// StatusUnknown means the provider could not decide. It is a successful
	// answer.
	StatusUnknown Status = "unknown"
)

// Known reports whether s is one of the four documented verdicts.
func (s Status) Known() bool {
	switch s {
	case StatusDeliverable, StatusRisky, StatusUndeliverable, StatusUnknown:
		return true
	}
	return false
}

// Reason is the main cause behind a verdict. It is an open set: see Known.
type Reason string

// Documented reasons.
const (
	ReasonAcceptedEmail     Reason = "accepted_email"
	ReasonLowDeliverability Reason = "low_deliverability"
	ReasonLowQuality        Reason = "low_quality"
	ReasonInvalidEmail      Reason = "invalid_email"
	ReasonInvalidDomain     Reason = "invalid_domain"
	ReasonRejectedEmail     Reason = "rejected_email"
	ReasonDNSError          Reason = "dns_error"
	ReasonUnavailableSMTP   Reason = "unavailable_smtp"
	ReasonUnsupported       Reason = "unsupported"
	ReasonTimeout           Reason = "timeout"
	ReasonUnknown           Reason = "unknown"
)

// Known reports whether r is one of the eleven documented reasons.
func (r Reason) Known() bool {
	switch r {
	case ReasonAcceptedEmail, ReasonLowDeliverability, ReasonLowQuality, ReasonInvalidEmail,
		ReasonInvalidDomain, ReasonRejectedEmail, ReasonDNSError, ReasonUnavailableSMTP,
		ReasonUnsupported, ReasonTimeout, ReasonUnknown:
		return true
	}
	return false
}

// Flag is a three-valued trait the provider reports as text. It is an open
// set: see Known. "" means not reported.
type Flag string

// Documented flag values.
const (
	FlagYes     Flag = "yes"
	FlagNo      Flag = "no"
	FlagUnknown Flag = "unknown"
)

// Known reports whether f is "yes", "no" or "unknown".
func (f Flag) Known() bool {
	switch f {
	case FlagYes, FlagNo, FlagUnknown:
		return true
	}
	return false
}

// verificationWire is the decoding shape of a verification record. Each
// member is kept raw, so that absent (nil), null and every JSON type stay
// apart until the field rules decide.
type verificationWire struct {
	Email      json.RawMessage `json:"email"`
	Status     json.RawMessage `json:"status"`
	Reason     json.RawMessage `json:"reason"`
	Domain     json.RawMessage `json:"domain"`
	Account    json.RawMessage `json:"account"`
	DNS        json.RawMessage `json:"dns"`
	Provider   json.RawMessage `json:"provider"`
	Score      json.RawMessage `json:"score"`
	Toxic      json.RawMessage `json:"toxic"`
	Toxicity   json.RawMessage `json:"toxicity"`
	RetryAfter json.RawMessage `json:"retryAfter"`
	DidYouMean json.RawMessage `json:"didYouMean"`
	Name       json.RawMessage `json:"name"`
}

// domainWire is the decoding shape of Domain.
type domainWire struct {
	Name       json.RawMessage `json:"name"`
	AcceptAll  json.RawMessage `json:"acceptAll"`
	Disposable json.RawMessage `json:"disposable"`
	Free       json.RawMessage `json:"free"`
}

// accountWire is the decoding shape of Account.
type accountWire struct {
	Role        json.RawMessage `json:"role"`
	Disabled    json.RawMessage `json:"disabled"`
	FullMailbox json.RawMessage `json:"fullMailbox"`
}

// dnsWire is the decoding shape of DNS.
type dnsWire struct {
	Type   json.RawMessage `json:"type"`
	Record json.RawMessage `json:"record"`
}

// decodeVerification decodes one verification record. prefix is the record's
// JSON path in its answer ("" for Verify, "[17]" in an array), which every
// failure's Field starts with. The rules:
//   - email, status and reason must be non-empty JSON strings;
//   - optional strings and flags may be absent or null (""), else strings;
//   - optional objects may be absent or null (nil), else objects; {} is an
//     empty, non-nil value;
//   - score and toxicity may be absent, null or "" (nil), else JSON integers,
//     not range-checked;
//   - unknown members are ignored, and a repeated member keeps its last value,
//     as encoding/json does (which also matches member names without regard
//     to case when no exact match exists);
//   - the record must be valid UTF-8 and at most 64 KiB, and each text field
//     at most 4 KiB.
func decodeVerification(raw []byte, prefix string) (Verification, *decodeError) {
	if len(raw) > maxRecordBytes {
		return Verification{}, tooLarge(prefix)
	}
	var w verificationWire
	if derr := unmarshalRecord(raw, prefix, &w); derr != nil {
		return Verification{}, derr
	}
	var v Verification
	d := &fieldDecoder{prefix: prefix}
	v.Email = d.required(w.Email, "email")
	v.Status = Status(d.required(w.Status, "status"))
	v.Reason = Reason(d.required(w.Reason, "reason"))
	v.Provider = d.text(w.Provider, "provider")
	v.Score = d.lenientInt(w.Score, "score")
	v.Toxic = Flag(d.text(w.Toxic, "toxic"))
	v.Toxicity = d.lenientInt(w.Toxicity, "toxicity")
	v.RetryAfter = d.text(w.RetryAfter, "retryAfter")
	v.DidYouMean = d.text(w.DidYouMean, "didYouMean")
	v.Name = d.text(w.Name, "name")
	var dw domainWire
	if d.object(w.Domain, "domain", &dw) {
		dd := d.nested("domain")
		v.Domain = &Domain{
			Name:       dd.text(dw.Name, "name"),
			AcceptAll:  Flag(dd.text(dw.AcceptAll, "acceptAll")),
			Disposable: Flag(dd.text(dw.Disposable, "disposable")),
			Free:       Flag(dd.text(dw.Free, "free")),
		}
		d.adopt(dd)
	}
	var aw accountWire
	if d.object(w.Account, "account", &aw) {
		ad := d.nested("account")
		v.Account = &Account{
			Role:        Flag(ad.text(aw.Role, "role")),
			Disabled:    Flag(ad.text(aw.Disabled, "disabled")),
			FullMailbox: Flag(ad.text(aw.FullMailbox, "fullMailbox")),
		}
		d.adopt(ad)
	}
	var nw dnsWire
	if d.object(w.DNS, "dns", &nw) {
		nd := d.nested("dns")
		v.DNS = &DNS{Type: nd.text(nw.Type, "type"), Record: nd.text(nw.Record, "record")}
		d.adopt(nd)
	}
	if d.err != nil {
		return Verification{}, d.err
	}
	return v, nil
}

// decodeError is a decoding or size failure of an answer that arrived: a
// kind, a fixed cause and the JSON path of the value concerned.
type decodeError struct {
	kind  FailureKind
	cause error
	field string
}

// Error returns the cause's fixed message. A decodeError never leaves the
// package: callError turns it into a CallError.
func (d *decodeError) Error() string { return d.cause.Error() }

// callError returns the CallError for d on op, with the response's status.
func (d *decodeError) callError(op Operation, status int) *CallError {
	ce := newCallError(op, d.kind, status, d.cause)
	ce.Field = d.field
	return ce
}

// malformed returns a malformed_response failure at field.
func malformed(field string, cause error) *decodeError {
	return &decodeError{kind: FailureMalformedResponse, cause: cause, field: field}
}

// tooLarge returns a response_too_large failure at field.
func tooLarge(field string) *decodeError {
	return &decodeError{kind: FailureResponseTooLarge, cause: errFieldTooLarge, field: field}
}

// joinPath returns the JSON path of member name under prefix.
func joinPath(prefix, name string) string {
	if prefix == "" {
		return name
	}
	return prefix + "." + name
}

// unmarshalRecord decodes raw, a whole JSON value, into the wire struct v:
// raw must be valid UTF-8 and a JSON object. path names it in failures.
func unmarshalRecord(raw []byte, path string, v any) *decodeError {
	if !utf8.Valid(raw) {
		return malformed(path, errInvalidUTF8)
	}
	i := skipSpace(raw)
	if i == len(raw) {
		return malformed(path, errInvalidJSON)
	}
	if raw[i] != '{' {
		if !json.Valid(raw) {
			return malformed(path, errInvalidJSON)
		}
		return malformed(path, errWrongKind)
	}
	if err := json.Unmarshal(raw, v); err != nil {
		return malformed(path, errInvalidJSON)
	}
	return nil
}

// fieldDecoder applies the field rules to the members of one object,
// keeping the first failure: once it has one, every later call is a no-op
// that returns the zero value.
type fieldDecoder struct {
	prefix string
	err    *decodeError
}

// nested returns a decoder for the members of the object at name.
func (d *fieldDecoder) nested(name string) *fieldDecoder {
	return &fieldDecoder{prefix: joinPath(d.prefix, name), err: d.err}
}

// adopt keeps n's failure when d has none yet.
func (d *fieldDecoder) adopt(n *fieldDecoder) {
	if d.err == nil {
		d.err = n.err
	}
}

// fail records a failure at member name.
func (d *fieldDecoder) fail(name string, cause error) {
	if d.err == nil {
		d.err = malformed(joinPath(d.prefix, name), cause)
	}
}

// required decodes a member that must be a non-empty JSON string.
func (d *fieldDecoder) required(raw json.RawMessage, name string) string {
	if d.err != nil {
		return ""
	}
	if !present(raw) {
		d.fail(name, errMissingField)
		return ""
	}
	s := d.text(raw, name)
	if s == "" && d.err == nil {
		d.fail(name, errMissingField)
	}
	return s
}

// text decodes an optional string member: absent or null is "".
func (d *fieldDecoder) text(raw json.RawMessage, name string) string {
	if d.err != nil || !present(raw) {
		return ""
	}
	if len(raw) < 2 || raw[0] != '"' {
		d.fail(name, errWrongType)
		return ""
	}
	if loneSurrogate(raw) {
		// encoding/json would substitute U+FFFD, rewriting the provider's text.
		d.fail(name, errInvalidUTF8)
		return ""
	}
	s, ok := jsonString(raw)
	switch {
	case !ok:
		d.fail(name, errWrongType)
		return ""
	case len(s) > maxTextBytes:
		if d.err == nil {
			d.err = tooLarge(joinPath(d.prefix, name))
		}
		return ""
	}
	return s
}

// lenientInt decodes an optional integer member: absent, null and "" are
// nil, a JSON integer is its value, and anything else (a fraction, an
// exponent, a numeric string) is malformed.
func (d *fieldDecoder) lenientInt(raw json.RawMessage, name string) *int {
	if d.err != nil || !present(raw) || string(raw) == `""` {
		return nil
	}
	n, ok := jsonInteger(raw, strconv.IntSize)
	if !ok {
		d.fail(name, errWrongType)
		return nil
	}
	return new(int(n))
}

// count decodes an optional counter: absent or null is nil, else it must be
// a JSON integer.
func (d *fieldDecoder) count(raw json.RawMessage, name string) *int64 {
	if d.err != nil || !present(raw) {
		return nil
	}
	n, ok := jsonInteger(raw, 64)
	if !ok {
		d.fail(name, errWrongType)
		return nil
	}
	return &n
}

// object decodes an optional object member into the wire struct v, and
// reports whether there was one: absent or null is false, any other JSON
// type is malformed.
func (d *fieldDecoder) object(raw json.RawMessage, name string, v any) bool {
	if d.err != nil || !present(raw) {
		return false
	}
	if raw[0] != '{' {
		d.fail(name, errWrongType)
		return false
	}
	if err := json.Unmarshal(raw, v); err != nil {
		d.fail(name, errInvalidJSON)
		return false
	}
	return true
}

// jsonString returns the string a raw JSON value holds, and false when it is
// not a string. A string without escapes is its own content.
func jsonString(raw json.RawMessage) (string, bool) {
	if len(raw) < 2 || raw[0] != '"' {
		return "", false
	}
	if inner := raw[1 : len(raw)-1]; !strings.ContainsRune(string(inner), '\\') {
		return string(inner), true
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return "", false
	}
	return s, true
}

// loneSurrogate reports whether a raw JSON string holds a \u escape of a
// UTF-16 surrogate that is not part of a valid pair, which has no UTF-8 form.
func loneSurrogate(raw []byte) bool {
	for i := 0; i+5 < len(raw); i++ {
		if raw[i] != '\\' {
			continue
		}
		if raw[i+1] != 'u' {
			i++ // skip the escaped character, which may be a backslash
			continue
		}
		r, ok := hex4(raw[i+2 : i+6])
		switch {
		case !ok || r < 0xd800 || r > 0xdfff:
		case r >= 0xdc00:
			return true
		default:
			if i+11 >= len(raw) || raw[i+6] != '\\' || raw[i+7] != 'u' {
				return true
			}
			low, ok := hex4(raw[i+8 : i+12])
			if !ok || low < 0xdc00 || low > 0xdfff {
				return true
			}
			i += 6
		}
		i += 5
	}
	return false
}

// hex4 parses b, four bytes, as hexadecimal digits.
func hex4(b []byte) (rune, bool) {
	var r rune
	for _, c := range b {
		switch {
		case '0' <= c && c <= '9':
			r = r<<4 | rune(c-'0')
		case 'a' <= c && c <= 'f':
			r = r<<4 | rune(c-'a'+10)
		case 'A' <= c && c <= 'F':
			r = r<<4 | rune(c-'A'+10)
		default:
			return 0, false
		}
	}
	return r, true
}

// jsonInteger returns the integer a raw JSON value holds, when it is written
// as one (an optional minus and digits without leading zeros: no fraction or
// exponent) and fits bitSize bits.
func jsonInteger(raw json.RawMessage, bitSize int) (int64, bool) {
	s := string(raw)
	digits := strings.TrimPrefix(s, "-")
	if digits == "" || !asciiRange(digits, '0', '9') || (len(digits) > 1 && digits[0] == '0') {
		return 0, false
	}
	n, err := strconv.ParseInt(s, 10, bitSize)
	return n, err == nil
}
