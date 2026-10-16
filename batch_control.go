package bouncer

import (
	"context"
	"encoding/json"
	"net/http"
	"unicode/utf8"
)

// FinishBatchRequest is one finish call.
type FinishBatchRequest struct {
	// BatchID is the batch to finish.
	BatchID BatchID
}

// DeleteBatchRequest is one delete call.
type DeleteBatchRequest struct {
	// BatchID is the batch to delete.
	BatchID BatchID
}

// Finish asks the provider to stop verifying a batch and return the credits
// for the entries it has not verified: POST
// https://api.usebouncer.com/v1.1/email/verify/batch/{batchId}/finish.
//
// STATE-CHANGING, and asynchronous on the provider's side. It is not a
// cancellation, not a deletion and not a refund guarantee: success means only
// that the provider accepted the request. Confirm the outcome with Status or
// Wait. The SDK calls it only when the caller does, never on cancellation,
// timeout or cleanup, and makes exactly one attempt.
//
// Success is HTTP 200, 202 or 204 with an empty body or a JSON object whose
// "error" member is absent or null. An error envelope fails even inside a
// 2xx: the provider documents a 200 whose body reports status 400, which
// fails with ErrRejected, StatusCode 200 and APIStatus 400.
//
// Errors are a *ValidationError (nothing sent) or a *CallError whose BatchID
// is req.BatchID.
func (s BatchService) Finish(ctx context.Context, req FinishBatchRequest) error {
	return s.control(ctx, OpBatchFinish, http.MethodPost, req.BatchID, "/finish")
}

// Delete deletes a batch and its results: DELETE
// https://api.usebouncer.com/v1.1/email/verify/batch/{batchId}.
//
// DESTRUCTIVE: the provider says the results will be lost, and the SDK cannot
// recover them. Download them first if you need them. HTTP 405 (ErrBatchState)
// means the batch cannot be deleted in its current state. The SDK calls it
// only when the caller does, never on cancellation, timeout or cleanup, and
// makes exactly one attempt. Success is judged as for Finish.
//
// Errors are a *ValidationError (nothing sent) or a *CallError whose BatchID
// is req.BatchID.
func (s BatchService) Delete(ctx context.Context, req DeleteBatchRequest) error {
	return s.control(ctx, OpBatchDelete, http.MethodDelete, req.BatchID, "")
}

// control makes the one attempt of Finish or Delete and checks the
// acknowledgement.
func (s BatchService) control(ctx context.Context, op Operation, method string, id BatchID, suffix string) error {
	c := s.c
	if err := c.prepare(ctx); err != nil {
		return err
	}
	if err := checkBatchID(id); err != nil {
		return err
	}
	path, rawPath := batchPath(id, suffix)
	rep, cerr := c.exchange(ctx, &outgoing{op: op, method: method, path: path, rawPath: rawPath, accept: mediaJSON})
	if cerr != nil {
		return cerr.forBatch(id)
	}
	if cerr := c.checkAck(op, rep); cerr != nil {
		return cerr.forBatch(id)
	}
	return nil
}

// checkAck accepts an acknowledgement that is empty or a JSON object whose
// "error" member is absent or null. exchange has already failed an error
// envelope; an object that still names an error is a refusal, and any other
// body (another kind of JSON value, or not JSON) is malformed.
func (c *Client) checkAck(op Operation, rep *reply) *CallError {
	if blank(rep.body) {
		return nil
	}
	env, ok := readEnvelope(rep.body)
	switch {
	case ok && env.hasError:
		return newCallErrorWithDiagnostics(op, FailureRejected, rep.status, errEnvelope, c.diagnosticsFrom(env.message))
	case ok:
		return nil
	case !utf8.Valid(rep.body):
		return newCallError(op, FailureMalformedResponse, rep.status, errInvalidUTF8)
	case json.Valid(rep.body):
		return newCallError(op, FailureMalformedResponse, rep.status, errWrongKind)
	}
	return newCallError(op, FailureMalformedResponse, rep.status, errInvalidJSON)
}
