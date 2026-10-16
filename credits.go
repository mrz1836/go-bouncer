package bouncer

import (
	"context"
	"encoding/json"
	"net/http"
)

// CreditBalance is the account's credit balance.
type CreditBalance struct {
	// Credits is the number of verification credits available.
	Credits int64 `json:"credits"`
}

// creditsWire is the decoding shape of CreditBalance.
type creditsWire struct {
	Credits json.RawMessage `json:"credits"`
}

// Credits returns the account's credit balance: GET
// https://api.usebouncer.com/v1.1/credits.
//
// Free and read-only. It makes exactly one attempt and never retries. The
// provider documents a limit of 10 calls a minute.
//
// Errors are a *ValidationError (nothing sent) or a *CallError.
func (c *Client) Credits(ctx context.Context) (*CreditBalance, error) {
	if err := c.prepare(ctx); err != nil {
		return nil, err
	}
	rep, cerr := c.exchange(ctx, &outgoing{op: OpCredits, method: http.MethodGet, path: pathCredits, accept: mediaJSON})
	if cerr != nil {
		return nil, cerr
	}
	balance, derr := decodeCredits(rep.body)
	if derr != nil {
		return nil, derr.callError(OpCredits, rep.status)
	}
	return balance, nil
}

// decodeCredits decodes a credits answer: an object whose "credits" member is
// a required JSON integer.
func decodeCredits(raw []byte) (*CreditBalance, *decodeError) {
	var w creditsWire
	if derr := unmarshalRecord(raw, "", &w); derr != nil {
		return nil, derr
	}
	d := fieldDecoder{}
	if !present(w.Credits) {
		return nil, malformed("credits", errMissingField)
	}
	n := d.count(w.Credits, "credits")
	if d.err != nil {
		return nil, d.err
	}
	return &CreditBalance{Credits: *n}, nil
}
