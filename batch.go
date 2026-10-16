package bouncer

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// BatchID is the provider's handle for an asynchronous batch. It is opaque:
// the provider's IDs look like 24 hexadecimal digits, which the SDK does not
// enforce. A request's BatchID must be 1 to 128 bytes of visible ASCII
// without '/', '\', '?', '#' or '%', and not ".", ".." or "sync".
type BatchID string

// BatchService holds the asynchronous batch calls. Get it from
// (*Client).Batches; the zero BatchService returns ErrInvalidConfig without
// any I/O. It is a small value, safe to copy and to use concurrently.
type BatchService struct {
	c *Client
}

// BatchEntry is one address of a batch.
type BatchEntry struct {
	// Email is the address to verify, sent verbatim. It must be 1 to 1024
	// bytes of valid UTF-8.
	Email string

	// Name is an optional label, such as an internal ID, sent as "name" only
	// when not empty: at most 256 bytes of valid UTF-8. The provider's older
	// reference and its official Java SDK describe it as returned with the
	// results; the current reference does not mention it, and it is
	// unverified. The echo, in Verification.Name, is not a guaranteed
	// correlation key, and the SDK never matches rows itself.
	Name string
}

// CreateBatchRequest is one batch creation. It is read only while Create
// validates and encodes it, before any I/O, and is never kept or modified.
type CreateBatchRequest struct {
	// Entries are the addresses: 1 to MaxBatchEntries (100,000), sent in
	// order, duplicates included. The provider recommends 1,000 to 10,000 per
	// batch. The whole encoded body must be at most 64 MiB.
	Entries []BatchEntry

	// CallbackURL is optional: an absolute https URL with a host and no
	// fragment, at most 2048 bytes, sent as the "callback" query parameter.
	// The provider will POST to it when the batch completes; the payload,
	// signing and retries are undocumented, so treat a callback as a hint and
	// confirm with Status. The SDK never prints, logs or fetches it.
	CallbackURL string
}

// String describes the request's shape only, such as
// "{entries: 2, names: 1, callbackURL: set}": never an address, a name or the
// callback URL.
func (r CreateBatchRequest) String() string {
	names := 0
	for i := range r.Entries {
		if r.Entries[i].Name != "" {
			names++
		}
	}
	callback := "unset"
	if r.CallbackURL != "" {
		callback = "set"
	}
	return "{entries: " + strconv.Itoa(len(r.Entries)) + ", names: " + strconv.Itoa(names) +
		", callbackURL: " + callback + "}"
}

// GoString returns the same text as String.
func (r CreateBatchRequest) GoString() string { return r.String() }

// Format writes the same text as String for every verb, so that fmt prints
// neither the entries nor the callback URL. fmt does not call it for %p on a
// value, or for a request held in an unexported struct field, and
// reflection-based dumpers see every field: keep requests out of such output.
func (r CreateBatchRequest) Format(f fmt.State, _ rune) { _, _ = f.Write([]byte(r.String())) }

// BatchStatusRequest is one status call.
type BatchStatusRequest struct {
	// BatchID is the batch to read.
	BatchID BatchID

	// WithStats asks for Batch.Processed and Batch.Stats. It is always sent,
	// false included.
	WithStats bool
}

// Batch is the provider's view of a batch, as Create and Status return it.
// A nil counter means the provider did not report it, and a pointer to 0 a
// reported zero; the SDK keeps every counter exactly as received and never
// estimates charges.
type Batch struct {
	// ID is the batch's handle. Save it: there is no call that lists batches.
	ID BatchID `json:"batchId"`

	// State is the batch's processing state, not a verification Status.
	State BatchState `json:"status"`

	// Created, Started and Completed are the provider's timestamps, kept as
	// received ("" when not reported). Completed is a time, not a flag.
	Created   Timestamp `json:"created,omitempty"`
	Started   Timestamp `json:"started,omitempty"`
	Completed Timestamp `json:"completed,omitempty"`

	// Quantity is the number of entries the provider accepted.
	Quantity *int64 `json:"quantity,omitempty"`

	// Duplicates is the number of duplicate entries the provider found.
	Duplicates *int64 `json:"duplicates,omitempty"`

	// CreditsUsed is the provider's "credits", reported once the batch is
	// completed.
	CreditsUsed *int64 `json:"credits,omitempty"`

	// Processed is the number of entries verified so far, reported when
	// WithStats was asked for.
	Processed *int64 `json:"processed,omitempty"`

	// Stats counts the results by verdict, reported when WithStats was asked
	// for.
	Stats *BatchStats `json:"stats,omitempty"`
}

// BatchStats counts a batch's results by verdict. A nil count was not
// reported.
type BatchStats struct {
	Deliverable   *int64 `json:"deliverable,omitempty"`
	Risky         *int64 `json:"risky,omitempty"`
	Undeliverable *int64 `json:"undeliverable,omitempty"`
	Unknown       *int64 `json:"unknown,omitempty"`
}

// BatchState is a batch's processing state. It is an open set: see Known.
type BatchState string

// Documented batch states. The provider does not say that the list is
// complete.
const (
	// BatchStateQueued means the batch waits to be processed.
	BatchStateQueued BatchState = "queued"

	// BatchStateProcessing means the batch is being verified.
	BatchStateProcessing BatchState = "processing"

	// BatchStateCompleted means the provider has finished the batch: Results
	// and Download can read its results. After Finish, entries it never
	// verified may have no result.
	BatchStateCompleted BatchState = "completed"
)

// Known reports whether s is one of the three documented states.
func (s BatchState) Known() bool {
	switch s {
	case BatchStateQueued, BatchStateProcessing, BatchStateCompleted:
		return true
	}
	return false
}

// Terminal reports whether s is BatchStateCompleted, the one state Wait ends
// at successfully.
func (s BatchState) Terminal() bool { return s == BatchStateCompleted }

// Timestamp is a provider timestamp, kept as the text received, documented as
// "YYYY-MM-DDTHH:MM:SS.mmmZ". "" means not reported.
type Timestamp string

// Time parses t as RFC 3339, and reports false when t is empty or does not
// parse. The SDK never calls it: the text stays the record.
func (t Timestamp) Time() (time.Time, bool) {
	if t == "" {
		return time.Time{}, false
	}
	parsed, err := time.Parse(time.RFC3339Nano, string(t))
	if err != nil {
		return time.Time{}, false
	}
	return parsed, true
}

// batchEntryWire is the encoding shape of a BatchEntry.
type batchEntryWire struct {
	Email string `json:"email"`
	Name  string `json:"name,omitempty"`
}

// batchWire is the decoding shape of Batch.
type batchWire struct {
	BatchID    json.RawMessage `json:"batchId"`
	Status     json.RawMessage `json:"status"`
	Created    json.RawMessage `json:"created"`
	Started    json.RawMessage `json:"started"`
	Completed  json.RawMessage `json:"completed"`
	Quantity   json.RawMessage `json:"quantity"`
	Duplicates json.RawMessage `json:"duplicates"`
	Credits    json.RawMessage `json:"credits"`
	Processed  json.RawMessage `json:"processed"`
	Stats      json.RawMessage `json:"stats"`
}

// batchStatsWire is the decoding shape of BatchStats.
type batchStatsWire struct {
	Deliverable   json.RawMessage `json:"deliverable"`
	Risky         json.RawMessage `json:"risky"`
	Undeliverable json.RawMessage `json:"undeliverable"`
	Unknown       json.RawMessage `json:"unknown"`
}

// Create creates a batch, which starts verifying at once: POST
// https://api.usebouncer.com/v1.1/email/verify/batch. There is no separate
// start step.
//
// PAID and DURABLE: the provider bills the batch's entries and keeps the
// batch. It makes exactly one attempt and never resubmits, after any failure.
// When the answer carried a valid batchId but was otherwise unusable, the
// *CallError's BatchID holds it: the batch exists, so save the ID rather than
// create it again. When no ID is known (a timeout, a transport failure), the
// batch may still exist, and no call lists batches: check the provider's
// dashboard before creating it again.
//
// Errors are a *ValidationError (nothing sent) or a *CallError.
func (s BatchService) Create(ctx context.Context, req CreateBatchRequest) (*Batch, error) {
	c := s.c
	if err := c.prepare(ctx); err != nil {
		return nil, err
	}
	out, err := req.outgoing()
	if err != nil {
		return nil, err
	}
	rep, cerr := c.exchange(ctx, out)
	if cerr != nil {
		if rep != nil {
			cerr.BatchID = batchIDHint(rep.body)
		}
		return nil, cerr
	}
	b, derr := decodeBatch(rep.body)
	if derr == nil && batchIDProblem(b.ID) != "" {
		// The SDK could not address this batch later: the answer is unusable.
		derr = malformed("batchId", errInvalidBatchID)
	}
	if derr != nil {
		return nil, derr.callError(OpBatchCreate, rep.status).forBatch(batchIDHint(rep.body))
	}
	return b, nil
}

// outgoing validates the request and describes its call, whose body is a JSON
// array of {"email": …[, "name": …]} objects.
func (r CreateBatchRequest) outgoing() (*outgoing, error) {
	switch {
	case len(r.Entries) == 0:
		return nil, invalidRequest("Entries", reasonRequired)
	case len(r.Entries) > MaxBatchEntries:
		return nil, invalidRequest("Entries", reasonTooMany)
	}
	for i := range r.Entries {
		e := &r.Entries[i]
		if reason := emailProblem(e.Email); reason != "" {
			return nil, invalidRequest(indexed("Entries", i, "Email"), reason)
		}
		if reason := nameProblem(e.Name); reason != "" {
			return nil, invalidRequest(indexed("Entries", i, "Name"), reason)
		}
	}
	if err := checkCallbackURL(r.CallbackURL); err != nil {
		return nil, err
	}
	wire := make([]batchEntryWire, len(r.Entries))
	for i, e := range r.Entries {
		wire[i] = batchEntryWire(e)
	}
	body, err := encodeJSON(wire)
	if err != nil {
		return nil, invalidRequest("Entries", reasonInvalidValue)
	}
	if len(body) > maxBatchBodyBytes {
		return nil, invalidRequest("Entries", reasonTooLarge)
	}
	var q strings.Builder
	if r.CallbackURL != "" {
		queryParam(&q, "callback", r.CallbackURL)
	}
	return &outgoing{
		op: OpBatchCreate, method: http.MethodPost, path: pathBatch, query: q.String(), accept: mediaJSON, body: body,
	}, nil
}

// Status reads a batch's state: GET
// https://api.usebouncer.com/v1.1/email/verify/batch/{batchId}.
//
// Free and read-only. It makes exactly one attempt and never retries. An
// answer for another batch than req.BatchID fails with ErrUnexpectedResponse.
//
// Errors are a *ValidationError (nothing sent) or a *CallError whose BatchID
// is req.BatchID.
func (s BatchService) Status(ctx context.Context, req BatchStatusRequest) (*Batch, error) {
	c := s.c
	if err := c.prepare(ctx); err != nil {
		return nil, err
	}
	if err := checkBatchID(req.BatchID); err != nil {
		return nil, err
	}
	path, rawPath := batchPath(req.BatchID, "")
	var q strings.Builder
	queryParam(&q, "with-stats", strconv.FormatBool(req.WithStats))
	out := &outgoing{
		op: OpBatchStatus, method: http.MethodGet, path: path, rawPath: rawPath, query: q.String(), accept: mediaJSON,
	}
	rep, cerr := c.exchange(ctx, out)
	if cerr != nil {
		return nil, cerr.forBatch(req.BatchID)
	}
	b, derr := decodeBatch(rep.body)
	if derr != nil {
		return nil, derr.callError(OpBatchStatus, rep.status).forBatch(req.BatchID)
	}
	if b.ID != req.BatchID {
		ce := newCallError(OpBatchStatus, FailureUnexpectedResponse, rep.status, errIDMismatch).forBatch(req.BatchID)
		ce.Field = "batchId"
		return nil, ce
	}
	return b, nil
}

// decodeBatch decodes a batch answer: batchId and status are required
// strings, timestamps optional strings, counters optional JSON integers, and
// stats an optional object of counters. Create then requires a valid batch
// ID, and Status the one it asked for.
func decodeBatch(raw []byte) (*Batch, *decodeError) {
	var w batchWire
	if derr := unmarshalRecord(raw, "", &w); derr != nil {
		return nil, derr
	}
	d := &fieldDecoder{}
	b := &Batch{
		ID:          BatchID(d.required(w.BatchID, "batchId")),
		State:       BatchState(d.required(w.Status, "status")),
		Created:     Timestamp(d.text(w.Created, "created")),
		Started:     Timestamp(d.text(w.Started, "started")),
		Completed:   Timestamp(d.text(w.Completed, "completed")),
		Quantity:    d.count(w.Quantity, "quantity"),
		Duplicates:  d.count(w.Duplicates, "duplicates"),
		CreditsUsed: d.count(w.Credits, "credits"),
		Processed:   d.count(w.Processed, "processed"),
	}
	var sw batchStatsWire
	if d.object(w.Stats, "stats", &sw) {
		sd := d.nested("stats")
		b.Stats = &BatchStats{
			Deliverable:   sd.count(sw.Deliverable, "deliverable"),
			Risky:         sd.count(sw.Risky, "risky"),
			Undeliverable: sd.count(sw.Undeliverable, "undeliverable"),
			Unknown:       sd.count(sw.Unknown, "unknown"),
		}
		d.adopt(sd)
	}
	if d.err != nil {
		return nil, d.err
	}
	return b, nil
}

// batchIDHint returns the batchId of an answer whose first JSON value is an
// object holding a valid one, and "" otherwise; data after that object, which
// makes the answer unusable, does not hide it. Create reports it on a
// failure, so that a batch the provider did create is not lost.
func batchIDHint(raw []byte) BatchID {
	var w struct {
		BatchID json.RawMessage `json:"batchId"`
	}
	if i := skipSpace(raw); i == len(raw) || raw[i] != '{' {
		return ""
	}
	if json.NewDecoder(bytes.NewReader(raw)).Decode(&w) != nil {
		return ""
	}
	s, ok := jsonString(w.BatchID)
	if !ok || batchIDProblem(BatchID(s)) != "" {
		return ""
	}
	return BatchID(s)
}
