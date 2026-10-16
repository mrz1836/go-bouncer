// Package bouncer is a small client for the Bouncer email-verification API,
// version 1.1: real-time verification of one address, the asynchronous batch
// workflow, batch-sync and the credit balance.
//
// Create one Client with NewClient at startup and share it: it is immutable
// and safe for concurrent use. The application supplies the API key; the
// package reads no environment variables or files, keeps no mutable global
// state and never logs.
//
// # Operations, effects and billing
//
//	Call                          HTTP                                   Effect
//	(*Client).Verify              GET  /v1.1/email/verify                PAID
//	(*Client).VerifyBatchSync     POST /v1.1/email/verify/batch/sync     PAID, partial results
//	(*Client).Credits             GET  /v1.1/credits                     read-only
//	BatchService.Create           POST /v1.1/email/verify/batch          PAID, creates and starts a batch
//	BatchService.Status           GET  /v1.1/email/verify/batch/{id}     read-only
//	BatchService.Wait             polls Status only                      read-only
//	BatchService.Results          GET  …/batch/{id}/download (JSON)      read-only, streamed
//	BatchService.Download         GET  …/batch/{id}/download             read-only, streamed to a writer
//	BatchService.Finish           POST …/batch/{id}/finish               STATE-CHANGING
//	BatchService.Delete           DELETE …/batch/{id}                    DESTRUCTIVE: results are lost
//
// # Guarantees
//
//   - Exactly one HTTP attempt per call. The SDK never retries, follows a
//     redirect, paginates, polls (except Wait, which polls Status only),
//     resubmits or falls back to another call, and it builds every request so
//     that the standard library does not resend it either. The one exception
//     is Finish, a free POST without a body, which an injected HTTP/2
//     transport may resend after some connection faults. Nothing paid,
//     state-changing or destructive happens unless the caller calls that
//     method.
//   - The API key travels only in the x-api-key header, to the provider or to
//     a loopback test server. There is no option for any other base URL.
//   - Every input is validated before any I/O; a *ValidationError means
//     nothing was sent.
//   - Every response is bounded in time and size, and classified strictly:
//     an error envelope inside a 2xx is an error, a missing required field
//     is never a zero-valued success, and a truncated stream never looks
//     complete.
//   - Errors never contain the API key, addresses, names, URLs, header values,
//     bodies or provider messages. Provider messages are opt-in
//     (WithProviderDiagnostics).
//
// A failed call may still have been processed and billed by the provider: a
// timeout, cancellation or transport failure says nothing about what the
// provider did. Do not resend paid calls blindly.
//
// # Contract ambiguities
//
// The provider's documentation contradicts itself in places, and the SDK
// chooses the strict or safe reading: it always sends the download filter
// and with-stats, never assumes the order of results matches the entries,
// keeps undocumented states, reasons and flags as received (their Known
// methods report false), treats a score that is absent, null or "" as not
// evaluated, keeps retryAfter as opaque text, uses the 100,000-entry batch
// limit of the technical documentation, and judges Finish and Delete by
// their body as well as their status. See the README for the full list.
//
// # Personal data
//
// Verification results are contact data: the caller is responsible for their
// access, storage, retention, logging and lawful use. Verify necessarily puts
// the address in the URL query, where the provider, its CDN and access logs
// can see it.
package bouncer
