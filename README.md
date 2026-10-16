<div align="center">

# 📮&nbsp;&nbsp;go-bouncer

**A small, typed Go SDK for the Bouncer email-verification API v1.1: real-time, batch-sync and asynchronous batches.**

<br/>

<a href="https://github.com/mrz1836/go-bouncer/releases"><img src="https://img.shields.io/github/release-pre/mrz1836/go-bouncer?style=flat-square&logo=github&color=black" alt="Release"></a>
<a href="https://golang.org/"><img src="https://img.shields.io/github/go-mod/go-version/mrz1836/go-bouncer?style=flat-square&logo=go&color=00ADD8" alt="Go Version"></a>
<a href="https://pkg.go.dev/github.com/mrz1836/go-bouncer"><img src="https://img.shields.io/badge/go.dev-reference-007d9c?style=flat-square&logo=go&logoColor=white" alt="Go Reference"></a>
<a href="https://github.com/mrz1836/go-bouncer/blob/master/LICENSE"><img src="https://img.shields.io/github/license/mrz1836/go-bouncer?style=flat-square&color=blue" alt="License"></a>

<br/>

<table align="center" border="0">
  <tr>
    <td align="right">
       <code>CI / CD</code> &nbsp;&nbsp;
    </td>
    <td align="left">
       <a href="https://github.com/mrz1836/go-bouncer/actions"><img src="https://img.shields.io/github/actions/workflow/status/mrz1836/go-bouncer/fortress.yml?branch=master&label=build&logo=github&style=flat-square" alt="Build"></a>
       <a href="https://github.com/mrz1836/go-bouncer/actions"><img src="https://img.shields.io/github/last-commit/mrz1836/go-bouncer?style=flat-square&logo=git&logoColor=white&label=last%20update" alt="Last Commit"></a>
    </td>
    <td align="right">
       &nbsp;&nbsp;&nbsp;&nbsp; <code>Quality</code> &nbsp;&nbsp;
    </td>
    <td align="left">
       <a href="https://codecov.io/gh/mrz1836/go-bouncer"><img src="https://codecov.io/gh/mrz1836/go-bouncer/branch/master/graph/badge.svg?style=flat-square" alt="Coverage"></a>
    </td>
  </tr>

  <tr>
    <td align="right">
       <code>Security</code> &nbsp;&nbsp;
    </td>
    <td align="left">
       <a href="https://scorecard.dev/viewer/?uri=github.com/mrz1836/go-bouncer"><img src="https://api.scorecard.dev/projects/github.com/mrz1836/go-bouncer/badge?style=flat-square" alt="Scorecard"></a>
       <a href=".github/SECURITY.md"><img src="https://img.shields.io/badge/policy-active-success?style=flat-square&logo=security&logoColor=white" alt="Security"></a>
    </td>
    <td align="right">
       &nbsp;&nbsp;&nbsp;&nbsp; <code>Community</code> &nbsp;&nbsp;
    </td>
    <td align="left">
       <a href="https://github.com/mrz1836/go-bouncer/graphs/contributors"><img src="https://img.shields.io/github/contributors/mrz1836/go-bouncer?style=flat-square&color=orange" alt="Contributors"></a>
       <a href="https://mrz1818.com/"><img src="https://img.shields.io/badge/donate-bitcoin-ff9900?style=flat-square&logo=bitcoin" alt="Bitcoin"></a>
    </td>
  </tr>
</table>

</div>

<br/>
<br/>

<div align="center">

### <code>Project Navigation</code>

</div>

<table align="center">
  <tr>
    <td align="center" width="25%">
       🚀&nbsp;<a href="#-installation"><code>Installation</code></a>
    </td>
    <td align="center" width="25%">
       🏁&nbsp;<a href="#-quick-start"><code>Quick&nbsp;Start</code></a>
    </td>
    <td align="center" width="25%">
       💡&nbsp;<a href="#-usage"><code>Usage</code></a>
    </td>
    <td align="center" width="25%">
       ⚙️&nbsp;<a href="#%EF%B8%8F-behavior"><code>Behavior</code></a>
    </td>
  </tr>
  <tr>
    <td align="center">
       🧪&nbsp;<a href="#-examples--tests"><code>Examples&nbsp;&&nbsp;Tests</code></a>
    </td>
    <td align="center">
       ⚡&nbsp;<a href="#-benchmarks"><code>Benchmarks</code></a>
    </td>
    <td align="center">
       🧰&nbsp;<a href="#-development"><code>Development</code></a>
    </td>
    <td align="center">
       🛠️&nbsp;<a href="#%EF%B8%8F-code-standards"><code>Code&nbsp;Standards</code></a>
    </td>
  </tr>
  <tr>
    <td align="center">
       🤖&nbsp;<a href="#-ai-usage--assistant-guidelines"><code>AI&nbsp;Usage</code></a>
    </td>
    <td align="center">
       👥&nbsp;<a href="#-maintainers"><code>Maintainers</code></a>
    </td>
    <td align="center">
       🤝&nbsp;<a href="#-contributing"><code>Contributing</code></a>
    </td>
    <td align="center">
       📝&nbsp;<a href="#-license"><code>License</code></a>
    </td>
  </tr>
</table>
<br/>

go-bouncer calls [Bouncer](https://www.usebouncer.com)'s API v1.1 to verify email addresses: one at a
time in real time, up to 10,000 at once with batch-sync (only the results Bouncer already has), or whole
lists through Bouncer's asynchronous batches (create, status, results, finish, delete). Use it when a Go
service needs to know whether an address is deliverable and has to stay in control of every billable
call.

- **One attempt per call.** No retries, redirects, replays, hedging, polling or fallbacks: the SDK never
  repeats a request on its own, and builds each one so that Go's HTTP client cannot resend it either. The
  one exception is the free `Finish`, which an injected HTTP/2 transport may resend; see
  [one attempt per call](#one-attempt-per-call).
- **Typed results that keep Bouncer's meaning.** `unknown` is an answer, not an error; a score that was not
  evaluated is `nil`, not `0`; undocumented statuses, reasons, flags and batch states are kept as sent.
- **Nothing paid or destructive happens implicitly.** Verifying, creating a batch, finishing it and deleting
  it are methods you call. The one helper, `Wait`, only polls `Status`, within a budget you must set.
- **Bounded and streaming.** Every call has a timeout and a size limit. `Results` streams a batch record by
  record with bounded memory; `Download` streams the raw file to your `io.Writer`, byte for byte.
- **Private by construction.** Errors and printed clients never contain the API key, addresses, names,
  URLs, bodies or Bouncer's messages; see the [security model](#security-model).
- **Zero runtime dependencies:** the standard library only. `testify` is used by the tests alone.

It covers the email endpoints of API v1.1; see [what is not covered](#what-is-not-covered).

> go-bouncer is an independent, unofficial SDK. It is not affiliated with, endorsed by or supported by
> Bouncer; "Bouncer" is used only to name the API it calls.

<br/>

## 🚀 Installation

**go-bouncer** requires Go 1.26 or later.
```shell script
go get github.com/mrz1836/go-bouncer
```

<br/>

### Credentials

You need a Bouncer **API key** from the Bouncer dashboard. go-bouncer never reads an environment variable
or a configuration file for it: your code passes the key to `bouncer.NewClient`, from wherever it keeps
secrets. The key travels only in the `x-api-key` header of each request, to Bouncer (or to a loopback test
server), never in a URL or a body.

Bouncer documents free **sandbox addresses** on its `sandbox.usebouncer.com` domain (such as `deliverable@`
and `unknown@` there, each also with a `+suffix`), verified by the same API host. Every other address you
verify may be billed.

<br/>

## 🏁 Quick Start

This is [examples/quickstart](examples/quickstart/main.go), which does nothing unless you pass `-live`:

```go
	// The application chooses where the key comes from; the SDK reads no environment.
	client, err := bouncer.NewClient(os.Getenv("BOUNCER_API_KEY"))
	if err != nil {
		log.Fatal(err) // ErrInvalidConfig: no call was made
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	// One billable call, whatever the result.
	v, err := client.Verify(ctx, bouncer.VerifyRequest{Email: *email})
	if err != nil {
		log.Fatal(err) // the check may already be billed: do not resend blindly
	}
	fmt.Println(v.Status, v.Reason)
```

```bash
BOUNCER_API_KEY=… go run ./examples/quickstart -live -email you@example.com
```

Illustrative output (the values are Bouncer's):

```text
deliverable accepted_email
```

<br/>

### Next steps

- [Set up a client once](#set-up-once) and [check one email](#check-one-email).
- Get what Bouncer already knows with [batch-sync](#batch-sync-partial-results).
- Verify a list with an [asynchronous batch](#asynchronous-batches), then [stream](#read-results) or
  [download](#download-the-raw-file) its results.
- Handle [errors](#errors) without resending billed calls.

<br/>

## 💡 Usage

### Set up once

```go
	// Build one client at startup. The key comes from the app's secret store: the SDK never reads the environment.
	client, err := bouncer.NewClient(secretKey(),
		bouncer.WithTimeout(40*time.Second), // must be ≥ VerifyRequest.Timeout + 10s
		bouncer.WithDownloadTimeout(20*time.Minute),
		bouncer.WithUserAgent("acme-signup/1.4"))
	if err != nil {
		log.Fatal(err) // ErrInvalidConfig: nothing was sent
	}
	fmt.Println(client) // settings only, never the key
```

A `Client` is immutable and safe for concurrent use: build one and share it. `NewClient` performs no I/O
and validates everything up front: an invalid key or option is a `*ValidationError` matching
`ErrInvalidConfig`, which names the option, never its value. A nil option is skipped; when an option is
given twice the last one wins; an explicit zero is invalid, never "the default" or "unlimited".

| Option | Default | Accepted |
|---|---|---|
| `WithTimeout` | 60s (`DefaultTimeout`) | more than 0, at most 10 minutes |
| `WithMaxResponseBytes` | 16 MiB (`DefaultMaxResponseBytes`) | 1 byte to 64 MiB |
| `WithDownloadTimeout` | 30 minutes (`DefaultDownloadTimeout`) | more than 0, at most 12 hours |
| `WithMaxDownloadBytes` | 1 GiB (`DefaultMaxDownloadBytes`) | 1 byte to 64 GiB |
| `WithUserAgent` | `go-bouncer` | 1 to 256 bytes of visible ASCII and spaces, starting and ending with a visible character |
| `WithHTTPClient` | the SDK's own transport | a non-nil `*http.Client`; see [the transport](#the-transport) |
| `WithTestBaseURL` | `https://api.usebouncer.com` | `https` on `127.0.0.0/8` or `[::1]` only |
| `WithProviderDiagnostics` | off | keeps Bouncer's error message, cut to 1 KiB |

`WithTimeout` bounds each buffered call, reading the response included; every buffered call except
`VerifyBatchSync` is also capped at 1 MiB. `WithDownloadTimeout` and `WithMaxDownloadBytes` bound `Results`
and `Download` instead. Your context's deadline and cancellation apply as well.

<br/>

### Operations

| Method | HTTP | Effect | `CallError.Op` |
|---|---|---|---|
| `(*Client).Verify` | `GET /v1.1/email/verify` | **paid** | `OpVerify` (`verify`) |
| `(*Client).VerifyBatchSync` | `POST /v1.1/email/verify/batch/sync` | **paid**, partial results | `OpBatchSync` (`batch_sync`) |
| `(*Client).Credits` | `GET /v1.1/credits` | free, read-only | `OpCredits` (`credits`) |
| `BatchService.Create` | `POST /v1.1/email/verify/batch` | **paid**, creates and starts a batch | `OpBatchCreate` (`batch_create`) |
| `BatchService.Status` | `GET /v1.1/email/verify/batch/{id}` | free, read-only | `OpBatchStatus` (`batch_status`) |
| `BatchService.Wait` | polls `Status` only | free, read-only | `OpBatchStatus` (`batch_status`) |
| `BatchService.Results` | `GET …/batch/{id}/download` as JSON | free, read-only, streamed | `OpBatchResults` (`batch_results`) |
| `BatchService.Download` | `GET …/batch/{id}/download` | free, read-only, streamed to a writer | `OpBatchDownload` (`batch_download`) |
| `BatchService.Finish` | `POST …/batch/{id}/finish` | **state-changing** | `OpBatchFinish` (`batch_finish`) |
| `BatchService.Delete` | `DELETE …/batch/{id}` | **destructive**: the results are lost | `OpBatchDelete` (`batch_delete`) |

`client.Batches()` returns the `BatchService`, a small value that is safe to copy and share.

<br/>

### Check one email

```go
	// Single check. Status and Reason are separate axes, and "unknown" is a successful, billed answer.
	v, err := client.Verify(ctx, bouncer.VerifyRequest{Email: "avery.example@example.com", Timeout: 20 * time.Second})
	if err != nil {
		log.Fatal(err) // the call may already be billed: never resend blindly
	}
	fmt.Println(v.Status, v.Reason)
	if d := v.Domain; d != nil {
		fmt.Println(d.Name, d.AcceptAll == bouncer.FlagYes, d.Free)
	}
	if v.Score != nil {
		fmt.Println("score", *v.Score) // &0 is a real score; nil means not evaluated
	}
	if v.DidYouMean != "" {
		fmt.Println("suggestion only:", v.DidYouMean) // never verified automatically
	}
	if !v.Status.Known() {
		fmt.Println("a verdict newer than this SDK: apply your own policy")
	}
```

`Verify` is a `GET`, and **Bouncer may bill it**. The address is sent verbatim: never trimmed, lowercased or
checked against an RFC. It must be 1 to 1024 bytes of valid UTF-8; a malformed address is a legitimate input
for Bouncer to judge. `Timeout` is Bouncer's own verification budget, sent in whole seconds from 1s to 30s,
and must be at least 10 seconds shorter than `WithTimeout`, so that the SDK never gives up on a check Bouncer
will still bill. `0` leaves Bouncer's default of 10 seconds.

What a result means:

| Field | Meaning |
|---|---|
| `Status` | The verdict: `deliverable`, `risky`, `undeliverable` or `unknown`. |
| `Reason` | The main cause, such as `accepted_email`, `low_quality`, `invalid_domain` or `timeout` (eleven are documented). |
| `Domain`, `Account` | Traits as `Flag` values `yes`, `no` or `unknown`: accept-all, disposable, free; role, disabled, full mailbox. `nil` when not reported. |
| `DNS`, `Provider` | The mail record (`MX` or `A`) and the mailbox provider, when reported. |
| `Score` | 0 to 100 as documented (not range-checked). `nil` when Bouncer did not evaluate it: absent, `null` or `""`. |
| `Toxic`, `Toxicity` | The toxicity flag and level (0 to 5 as documented), when reported. |
| `DidYouMean` | A typo suggestion that Bouncer itself calls not fully verified. |
| `RetryAfter` | Undocumented provider text, kept opaque. It is not the HTTP `Retry-After` header. |
| `Name` | The batch entry's `Name`, when Bouncer echoes it. |
| `Email` | Bouncer's echo of the address, which may differ from what you sent. |

Every enumeration is open: a value newer than this SDK is kept as received and its `Known` method reports
false, so decide your own policy for it.

<br/>

### Batch-sync: partial results

```go
	// Batch-sync returns only the results Bouncer already has; the rest keep verifying, and are billed.
	res, err := client.VerifyBatchSync(ctx, bouncer.BatchSyncRequest{Emails: []string{
		"avery.example@example.com", "blake.example@example.net",
	}})
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("%d of %d available now\n", len(res.Available), res.Requested)
	for _, v := range res.Available {
		fmt.Println(v.Email, v.Status) // provider order; no correlation is promised
	}
```

`VerifyBatchSync` sends 1 to 10,000 addresses (an encoded body of at most 8 MiB) and returns **only the
results Bouncer already has**: `Available` may be shorter than `Requested`, even empty. The others keep
verifying in the background and are billed. Bouncer keeps results for about 24 hours, so submitting the same
addresses again within that window returns those verified since; after it, Bouncer verifies and charges them
again. Bouncer asks for calls one at a time, 5 seconds to 10 minutes apart. The SDK makes one call and
nothing more: it never polls, resubmits, works out which addresses are missing, or falls back to `Verify`
or a batch. Its answer is limited by `WithMaxResponseBytes`, not by the 1 MiB cap.

<br/>

### Check the credit balance

```go
	// Free and read-only; Bouncer allows 10 calls a minute.
	balance, err := client.Credits(ctx)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(balance.Credits, "credits left")
```

<br/>

### Asynchronous batches

```go
	// Async batch. Creating it queues verification immediately; there is no separate start step.
	b, err := client.Batches().Create(ctx, bouncer.CreateBatchRequest{Entries: []bouncer.BatchEntry{
		{Email: "avery.example@example.com"}, {Email: "blake.example@example.net", Name: "crm-1042"},
	}})
	if ce, ok := errors.AsType[*bouncer.CallError](err); ok && ce.BatchID != "" {
		save(ce.BatchID) // created, but the reply was unusable
	}
	if err == nil {
		save(b.ID)
	}
```

The batch lifecycle:

1. **`Create`** sends 1 to 100,000 entries (an encoded body of at most 64 MiB; Bouncer recommends 1,000 to
   10,000) and **starts verifying at once**: it is paid and durable, and there is no start step. Save the
   ID: no call lists batches. When Bouncer's answer carried a valid `batchId` but was otherwise unusable,
   the `*CallError` holds it in `BatchID`. When no ID is known (a timeout, a transport failure), the batch may
   still exist: check the dashboard before creating it again. The SDK never resubmits.
2. **`Status`** reads the state: `queued`, `processing` or `completed` (the list is not documented as
   complete).
3. **`Wait`** polls `Status` until `completed`.
4. **`Results`** streams the records; **`Download`** copies the raw file. Both read a completed batch;
   HTTP 405 (`ErrBatchState`) means it is not completed, or its results were removed.
5. **`Finish`** asks Bouncer to stop and return the credits of unverified entries.
6. **`Delete`** deletes the batch and **its results are lost**.

`Finish` and `Delete` happen only when you call them: never on cancellation, a timeout or cleanup.

**`BatchEntry.Name`** is an optional label (up to 256 bytes of UTF-8), sent as `name`, which Bouncer's older
reference and its Java SDK describe as returned with the results. The current reference does not mention
it and it is unverified: the echo in `Verification.Name` is not a guaranteed correlation key.

**Correlation is not promised.** Bouncer does not document the order of results or how they map to entries;
duplicates pass through as sent and `Duplicates` is reported as received. The SDK never matches rows itself.

**`CallbackURL`** (an absolute `https` URL with a host and no fragment, at most 2048 bytes, without whitespace
or control characters) is sent as `callback`; Bouncer will POST to it, with an undocumented payload, signing
and retry policy. Treat it as a hint and confirm with `Status`. The SDK never prints, logs or fetches it.

<br/>

### Read a batch's status

```go
	// Free and read-only. WithStats adds Processed and Stats; nil counters were not reported.
	st, err := client.Batches().Status(ctx, bouncer.BatchStatusRequest{BatchID: id, WithStats: true})
	if err != nil {
		log.Fatal(err)
	}
	if st.Processed != nil && st.Quantity != nil {
		fmt.Printf("%s: %d of %d verified\n", st.State, *st.Processed, *st.Quantity)
	}
	if created, ok := st.Created.Time(); ok { // timestamps stay text; Time parses them on demand
		fmt.Println("created", created.Format(time.RFC3339))
	}
	if st.State.Terminal() {
		fmt.Println("completed: read it with Results or Download")
	}
```

`Batch` keeps every counter (`Quantity`, `Duplicates`, `CreditsUsed`, `Processed`, `Stats`) exactly as
received: `nil` means not reported, a pointer to 0 a reported zero. `Created`, `Started` and `Completed` are
`Timestamp` text, kept as sent; `Timestamp.Time` parses one as RFC 3339 when you need a `time.Time`.
`BatchState.Known` reports a documented state, and `Terminal` the one `Wait` ends at. An answer about
another batch fails with `ErrUnexpectedResponse`.

<br/>

### Wait for a batch

```go
	st, err := client.Batches().Wait(ctx, bouncer.WaitBatchRequest{BatchID: id, Interval: 15 * time.Second, MaxWait: 30 * time.Minute})
	if errors.Is(err, bouncer.ErrBudgetExhausted) {
		fmt.Println("still", st.State) // st is the last status seen; nothing was finished or deleted
		return
	}
```

`Wait` polls `Status` only: first at once, then `Interval` after each poll ends (10 seconds by default;
`Interval` 1 second to 10 minutes; `MaxWait` up to 72 hours, and required). The default interval is
`DefaultWaitInterval`. Set `WithStats` to have each poll ask for `Processed` and `Stats`. It returns:

| Outcome | Returns |
|---|---|
| `completed` | `(status, nil)` |
| A state the SDK does not document | `(status, ErrUnknownBatchState)`: it never polls through it |
| `MaxWait` ran out | `(last, ErrBudgetExhausted)`, as soon as the next poll could not start before it ends, or when it cuts off a poll still running |
| Your context ended | `(last, context.Canceled or context.DeadlineExceeded)` |
| A poll failed | `(last, err)`: no retry |

`last` is the last status read, or `nil` when there was none. `Wait` runs in your goroutine, starts none, and
does nothing after it returns. Canceling stops the polling only: Bouncer keeps verifying, and billing, the
batch.

<br/>

### Read results

```go
	// Stream results with bounded memory: one GET per range. Breaking out closes the body immediately.
	for v, err := range client.Batches().Results(ctx, bouncer.BatchResultsRequest{BatchID: id, Filter: bouncer.FilterRisky}) {
		if err != nil {
			log.Fatal(err) // e.g. ErrBatchState: not completed; CallError.Records = how many were yielded
		}
		if handle(v) {
			break
		}
	}
```

Calling `Results` does nothing; each `range` makes exactly one `GET` (a second range makes another: nothing
is cached). Records arrive in Bouncer's order with memory bounded by one record (64 KiB at most). The sequence
yields at most one error, last; records that arrived before a failure (a truncated or oversized stream, data
after the array) are yielded first, and the error always ends it, so a stream cut short never looks complete.
An empty batch yields nothing. `Filter` is one of `FilterAll` (the default), `FilterDeliverable`,
`FilterRisky`, `FilterUndeliverable` or `FilterUnknown`, and is always sent, because Bouncer documents no
default. `WithDownloadTimeout` bounds the whole range, the time your loop body takes included.

<br/>

### Download the raw file

```go
	// Raw CSV to a caller-owned writer. The SDK never closes or flushes it.
	n, err := client.Batches().Download(ctx, bouncer.DownloadBatchRequest{BatchID: id, Format: bouncer.FormatCSV}, bw)
	if err != nil {
		log.Fatalf("partial file of %d bytes: %v", n, err) // discard it
	}
```

`Download` asks for `FormatCSV` (`Accept: text/csv`; the columns are undocumented) or `FormatJSON`, and copies
the bytes unchanged: quoting, line endings and any byte order mark included. Nothing is written until the
response is classified. These all write nothing:

- a status other than 200, or an encoding nobody decoded (`Content-Encoding`);
- a declared length over `WithMaxDownloadBytes`;
- a content type that does not match the format;
- a JSON download that does not start with `[`;
- a body that ends within its first 64 KiB and is wholly a JSON object: an error envelope fails by its status,
  any other object as unexpected. A longer CSV body that starts with `{` is the file.

It returns the bytes written, on error too (`CallError.BytesWritten`); after a failure mid-stream, discard the
partial file. A longer download than `WithMaxDownloadBytes` fails after exactly that many bytes. A JSON
download that does not end with `]` fails as malformed; a CSV body that the server ends by closing the
connection cannot be checked for truncation. Canceling stops the copy at its next read, but cannot interrupt
a `Write` to your writer that blocks.

<br/>

### Finish or delete a batch

```go
	// Ask Bouncer to stop and return the credits of unverified entries. Success means only "accepted".
	if err := client.Batches().Finish(ctx, bouncer.FinishBatchRequest{BatchID: id}); err != nil {
		log.Fatal(err) // ErrBatchState (405): the batch's state does not allow it
	}
	st, err := client.Batches().Wait(ctx, bouncer.WaitBatchRequest{BatchID: id, MaxWait: 10 * time.Minute})
```

`Finish` is asynchronous and state-changing. It is not a cancellation, a deletion or a refund guarantee:
success means only that Bouncer accepted the request, so confirm the outcome with `Status` or `Wait`. After
`Finish`, entries Bouncer never verified may have no result.

```go
	// Destructive: the batch and its results are gone for good. Download them first if you need them.
	err := client.Batches().Delete(ctx, bouncer.DeleteBatchRequest{BatchID: id})
	if errors.Is(err, bouncer.ErrBatchState) {
		fmt.Println("not deletable in its current state")
		return
	}
```

Both succeed on HTTP 200, 202 or 204 with an empty body or a JSON object whose `error` member is absent or
`null`. An error envelope fails even inside a 2xx: Bouncer documents a `Finish` answered 200 whose body
reports status 400, which fails with `ErrRejected`, `StatusCode` 200 and `APIStatus` 400.

<br/>

### Errors

```go
	// Classify outcomes.
	var ve *bouncer.ValidationError
	switch {
	case errors.As(err, &ve): // local only: nothing was sent
	case errors.Is(err, bouncer.ErrTimeout): // SDK deadline (also matches context.DeadlineExceeded)
	case errors.Is(err, context.Canceled): // caller canceled; remote work and billing may continue
	case errors.Is(err, bouncer.ErrRateLimited): // CallError.RetryAfter is data only; nothing retries
	case errors.Is(err, bouncer.ErrMalformedResponse): // the provider answered but the reply is unusable; may be billed
	case errors.Is(err, bouncer.ErrBatchState): // 405: not completed, results removed, or not deletable now
	}
```

Every error is either a `*ValidationError` (local: nothing was sent) or a `*CallError`. The
[error reference](#error-reference) lists every case.

A **`*CallError`** carries the operation (`Op`), a `FailureKind` (`Kind`) that is safe to use as a metric
label, the HTTP status, the error envelope's status (`APIStatus`, which may disagree with the HTTP status),
the batch ID, a JSON field path, `Records` (for `Results`), `BytesWritten` (for `Download`) and the
standard `Retry-After` of a 429 or 503 as `RetryAfter` and `HasRetryAfter` (clamped to 24
hours, data only). `Timeout` reports whether the call ran out of time, by the SDK's deadline or your own;
`Diagnostics` returns Bouncer's message, only with `WithProviderDiagnostics`:

```go
	// Every exported field is safe to log: none holds the key, an address, a URL or Bouncer's text.
	if ce, ok := errors.AsType[*bouncer.CallError](err); ok {
		log.Printf("bouncer: op=%s kind=%s http=%d api=%d timeout=%t", ce.Op, ce.Kind, ce.StatusCode, ce.APIStatus, ce.Timeout())
		if ce.HasRetryAfter {
			log.Printf("Bouncer asks to wait %s; the SDK never retries", ce.RetryAfter)
		}
		if msg := ce.Diagnostics().Message; msg != "" { // only with WithProviderDiagnostics
			fmt.Println("Bouncer says:", msg) // may echo the address: keep it out of shared logs
		}
	}
```

A **`*ValidationError`** matches `ErrInvalidConfig` (from `NewClient`, or a client that `NewClient` did not
build) or `ErrInvalidRequest` (a call's arguments). `Field` names the argument as a Go path, such as
`Entries[17].Email`, `Timeout` or `ctx`, and `Reason` is a fixed code; neither ever holds the value:

```go
	// A refused request names the field and a fixed reason, never the value. Nothing was sent.
	if ve, ok := errors.AsType[*bouncer.ValidationError](err); ok {
		fmt.Println(ve.Field, ve.Reason, errors.Is(err, bouncer.ErrInvalidRequest))
	}
```

| `Reason` | Meaning |
|---|---|
| `required` | Missing or empty: the key, an address, `Entries`, `Emails`, `Format`, `BatchID` or `MaxWait`. |
| `nil` | A nil context, `Download` writer or `WithHTTPClient` client. |
| `not_initialized` | A nil or zero `Client`, or the zero `BatchService`. |
| `out_of_range` | A duration or size outside its bounds, or a `User-Agent` that is empty or over 256 bytes. |
| `invalid_format` | Characters the field does not allow: the key, the `User-Agent` or a batch ID. |
| `invalid_utf8` | An address or a `Name` that is not valid UTF-8. |
| `too_long` | An address, `Name`, `CallbackURL` or batch ID over its byte limit. |
| `too_many` | More than 100,000 entries or 10,000 addresses. |
| `too_large` | An encoded body over 64 MiB (`Create`) or 8 MiB (`VerifyBatchSync`). |
| `invalid_value` | A `Filter` or `Format` outside its constants. |
| `invalid_url` | A `WithTestBaseURL` that is not a loopback `https` URL, or a `CallbackURL` that is not an absolute URL with a host and no fragment, whitespace or control characters. |
| `unsupported_scheme` | A `CallbackURL` whose scheme is not `https`. |
| `not_whole_seconds` | A `VerifyRequest.Timeout` that is not whole seconds. |
| `exceeds_client_timeout` | A `VerifyRequest.Timeout` that is not at least 10 seconds shorter than `WithTimeout`. |

<br/>

### Timeouts, billing and repeat calls

- **A failed call may still have been processed and billed.** A timeout, a cancellation, a transport
  failure or an unreadable answer says nothing about what Bouncer did. Do not resend `Verify`,
  `VerifyBatchSync` or `Create` blindly: after `Create`, look at `CallError.BatchID` and the dashboard.
- **Nothing retries.** Not on 429, not on the 503 Bouncer suggests retrying, not on a dropped connection.
  Retry policy, pacing and budgets are yours.
- **The SDK never estimates charges.** `Quantity`, `Duplicates`, `CreditsUsed` and `Processed` are kept
  exactly as received, `nil` when not reported. Bouncer documents a batch-create limit of 60 a minute, a
  real-time default of 1,000 a minute and 10 a minute for `Credits`; the SDK enforces none of them.
- `Credits`, `Status`, `Wait`, `Results` and `Download` are free and read-only.

<br/>

### In a net/http handler

```go
// Verifier is the one method a signup handler needs. *bouncer.Client
// satisfies it, and so does a fake in the application's tests.
type Verifier interface {
	Verify(ctx context.Context, req bouncer.VerifyRequest) (*bouncer.Verification, error)
}

// signupHandler rejects addresses Bouncer finds undeliverable, and lets
// every other outcome through: a verification failure must not block a
// signup.
func signupHandler(v Verifier) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
		defer cancel()
		res, err := v.Verify(ctx, bouncer.VerifyRequest{Email: r.FormValue("email")})
		if err == nil && res.Status == bouncer.StatusUndeliverable {
			http.Error(w, "please check your email address", http.StatusUnprocessableEntity)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}
```

<br/>

### Testing your application

The SDK exports no interfaces or mocks: declare the small interface your code needs, as above, and fake it.
A `CallError` built from its exported fields matches `errors.Is` like a real one:

```go
	// A CallError built from its exported fields matches errors.Is like a real one.
	rateLimited := fakeVerifier{err: &bouncer.CallError{Kind: bouncer.FailureRateLimited, Op: bouncer.OpVerify, StatusCode: 429}}
	_, err := rateLimited.Verify(context.Background(), bouncer.VerifyRequest{Email: "avery.example@example.com"})
	fmt.Println(errors.Is(err, bouncer.ErrRateLimited))
```

For tests that need the HTTP layer, point a client at an `httptest.NewTLSServer` with
`WithTestBaseURL(srv.URL)` and `WithHTTPClient(srv.Client())`.

<br/>

### Storing results

`Verification` and `Batch` survive a JSON round trip under Bouncer's camelCase names, `nil` kept apart from
zero:

```go
	// A score of zero is a real score: it survives a round trip, apart from "not evaluated" (nil).
	v := bouncer.Verification{
		Email: "avery.example@example.com", Status: bouncer.StatusRisky, Reason: bouncer.ReasonLowQuality, Score: new(0),
	}
	data, err := json.Marshal(v)
```

Unmarshaling a raw Bouncer body into these types skips every check the SDK makes: decode Bouncer's answers
through the SDK, and use JSON only for your own storage.

<br/>

## ⚙️ Behavior

### Security model

The SDK assumes that the network, Bouncer's answers and anything printed or logged may be hostile or
public, and that your code, your injected transport and your writer are trusted.

#### The API key

- It travels only in the `x-api-key` header, to `https://api.usebouncer.com` or, with `WithTestBaseURL`, to
  an `https` server on `127.0.0.0/8` or `[::1]`. There is no option for any other base URL, and host names
  such as `localhost` are refused because they resolve through the system resolver.
- Redirects are never followed, and every 3xx `Location` header is removed before Go's client sees it, so
  the key is never resent elsewhere.
- The key lives only inside function values the `Client` holds, which `fmt` and reflection-based dumpers
  cannot see into; `Client.String` and `GoString` print settings only.

#### One attempt per call

Go's HTTP client resends some requests on its own: HTTP/1 resends a `GET` with no body on a new connection
when a reused one fails before the first response byte, although the server may already have processed (and
billed) it, and HTTP/2 may resend requests after a refused stream, a GOAWAY or, depending on the Go version,
a protocol error. The SDK builds every request so that neither applies: `GetBody` stays nil, a body is sent
as a plain reader, and a `GET` or `DELETE` carries an empty body that is not `http.NoBody`, which HTTP/1
drops before sending, so the bytes on the wire are unchanged. Tests pin this against Go's actual behavior on
every supported toolchain, with a server that drops requests on reused connections and a raw HTTP/2 server
that refuses streams, resets them and sends GOAWAY.

What remains:

- `Finish`, a `POST` without a body, is sent with `http.NoBody` and `Content-Length: 0`, as servers expect.
  HTTP/1 resends it only when nothing was written; an **injected HTTP/2 transport may resend it** after a
  refused stream, a GOAWAY or, depending on the Go version, a protocol error (Go 1.27 and later no longer
  retry after a protocol error). `Finish` costs nothing.
- An injected transport other than Go's own, retry middleware, a service mesh or a proxy may retry on its own;
  the SDK cannot see that.
- On HTTP/1, if the transport's body probe is delayed past 200 ms by a scheduler stall, a `GET` may be sent
  with `Transfer-Encoding: chunked`: a different wire form, but still never resent.
- On an injected HTTP/2 transport, a `GET` or `DELETE` is sent as HEADERS followed by an empty DATA frame
  that ends the stream, rather than HEADERS that end it: valid HTTP/2, and still never resent.
- The SDK never claims exactly-once delivery: a call that fails may still have been processed.

#### The transport

Without `WithHTTPClient`, each `Client` builds its own transport from scratch, rather than cloning
`http.DefaultTransport`:

- **HTTP/1.1 only**, so that the HTTP/2 client's own retries never apply;
- TLS 1.2 or later, 10-second dial and TLS handshake timeouts;
- its own pool of up to 8 idle connections, closed after a 4-second idle timeout, so that a pooled
  connection the server is about to close is rarely picked (a call that picks one fails, and is not resent);
- a 64 KiB limit on response headers;
- **no proxy**: the proxy environment variables are never read.

The call's context is the one clock: there is no separate response-header timeout. `CloseIdleConnections`
releases idle connections. Every request carries exactly `X-Api-Key`, `Accept`, `User-Agent` and, with a
body, `Content-Type: application/json`; never an `Authorization`, cookie, `Referer`, `Expect` or idempotency
header. URLs are assembled from their parts and every query value is percent-encoded strictly (`+` as `%2B`,
a space as `%20`). Go's transport may ask for gzip and decompresses it; the limits apply to the decompressed
bytes.

With `WithHTTPClient(hc)`, the SDK uses a copy of `hc` taken at `NewClient`, with redirects refused, every
3xx `Location` header removed, and no cookie jar. `hc` and its transport are never modified, its `Timeout`
still applies (to downloads too), and its transport is shared. **An injected transport is trusted code:** it
sees the API key and every address, and one that retries on its own defeats the one-attempt guarantee. To use
a proxy, inject a client whose transport sets one, such as `http.ProxyFromEnvironment` (which reads
`HTTPS_PROXY` and `NO_PROXY` once per process) or `http.ProxyURL`:

```go
	// The SDK's own transport never reads the proxy environment variables: bring a transport that does.
	var protocols http.Protocols
	protocols.SetHTTP1(true) // HTTP/1.1 only, so the HTTP/2 client's own retries never apply
	transport := &http.Transport{
		Proxy:               http.ProxyFromEnvironment,
		Protocols:           &protocols,
		TLSHandshakeTimeout: 10 * time.Second,
		IdleConnTimeout:     4 * time.Second,
	}
	client, err := bouncer.NewClient(secretKey(), bouncer.WithHTTPClient(&http.Client{Transport: transport}))
```

#### Privacy and contact data

- Error strings, `GoString`, every `fmt` verb on a `Client` or an error, and every error in an `Unwrap`
  chain never contain the API key, addresses, names, URLs, header values, bodies or Bouncer's messages.
  `Unwrap` returns only a context error or one of the package's fixed causes: never the underlying
  transport error, a URL, a decoding error or your writer's error.
- **`Verify` necessarily puts the address in the URL query.** Bouncer, its CDN and access logs can see it,
  and so can any TLS-terminating middleware in an injected client. The SDK never puts a URL in an error.
- Bouncer's message is kept only with `WithProviderDiagnostics`, cut to 1 KiB, with the key replaced by
  `[redacted]`; it may still echo the address you checked.
- `CreateBatchRequest`'s `String`, `GoString` and `Format` print only its shape, such as
  `{entries: 2, names: 1, callbackURL: set}`, for every `fmt` verb. `fmt` cannot call them for `%p` on a
  value or for a request held in an unexported struct field, and reflection-based dumpers see every field:
  keep requests out of such output. `json.Marshal`, and loggers built on it such as `slog`'s JSON handler,
  print every field of any request, and `VerifyRequest`, `BatchSyncRequest` and `BatchEntry` print their
  addresses with any verb: log requests as you would the addresses they hold.
- The SDK has no logger, telemetry, cache or persistence, keeps no mutable global state and reads no
  environment variable. A `httptrace` hook you attach to a context can see
  the `X-Api-Key` header. One standard-library message escapes this: when a server sends bytes past the end
  of a response on a pooled connection, Go's transport logs them to the default `log` output ("Unsolicited
  response received on idle HTTP channel"), so a misbehaving server can put its bytes in your logs.
- **Results are contact data.** Access control, storage, retention, logging and lawful use are your
  responsibility. Serializing or hashing a result does not anonymize it, and Bouncer's observations
  establish neither consent nor future deliverability.

<br/>

### Limits

| Bound | Value |
|---|---|
| API key | 1 to 256 bytes of visible ASCII |
| Address (every call) | 1 to 1024 bytes of valid UTF-8 |
| `VerifyRequest.Timeout` | whole seconds from 1s to 30s, at least 10 seconds shorter than `WithTimeout` |
| `CreateBatchRequest` | 1 to 100,000 entries; names up to 256 bytes; body up to 64 MiB |
| `CallbackURL` | up to 2048 bytes |
| `BatchSyncRequest` | 1 to 10,000 addresses; body up to 8 MiB |
| Batch ID | 1 to 128 bytes of visible ASCII, without `/ \ ? # %`, not `.` or `..`, and not `sync` in any case |
| Buffered answer | 16 MiB by default, up to 64 MiB; also capped at 1 MiB except for `VerifyBatchSync` |
| One verification record / one text field | 64 KiB / 4 KiB |
| Error response body read, and a `Finish` or `Delete` answer | 4 KiB |
| Response headers (SDK-built transport) | 64 KiB |
| `Results` and `Download` | 1 GiB by default, up to 64 GiB; 30 minutes by default, up to 12 hours |
| `Wait` | `Interval` 1 second to 10 minutes; `MaxWait` up to 72 hours |
| `ProviderDiagnostics.Message` | cut to 1 KiB |

A record or field over its bound fails the call as `ErrResponseTooLarge` rather than arriving cut short; the
one text the SDK shortens is the opt-in diagnostic message.

<br/>

### Error reference

<details>
<summary><strong><code>Every error, and what it matches</code></strong></summary>
<br/>

| What happened | `Kind` (`FailureKind`) | `errors.Is` matches |
|---|---|---|
| Invalid key or option, or a nil or zero client or `BatchService` | (`*ValidationError`) | `ErrInvalidConfig` |
| Nil context or writer, or a request failing validation | (`*ValidationError`) | `ErrInvalidRequest` |
| Your context canceled or expired, before or during the call | `canceled` (`FailureCanceled`) / `deadline_exceeded` (`FailureDeadlineExceeded`) | `context.Canceled` / `context.DeadlineExceeded` |
| `WithTimeout`, `WithDownloadTimeout`, the `http.Client` timeout, or a network timeout | `timeout` (`FailureTimeout`) | `ErrTimeout` and `context.DeadlineExceeded` |
| DNS, connection, TLS or proxy failure, reset, truncated or stalled body | `transport` (`FailureTransport`) | `ErrTransport` |
| HTTP 401 | `unauthorized` (`FailureUnauthorized`) | `ErrUnauthorized` |
| HTTP 402 | `payment_required` (`FailurePaymentRequired`) | `ErrPaymentRequired` |
| HTTP 403 | `forbidden` (`FailureForbidden`) | `ErrForbidden` |
| HTTP 404 | `not_found` (`FailureNotFound`) | `ErrNotFound` |
| HTTP 405 on a call that names a batch | `batch_state` (`FailureBatchState`) | `ErrBatchState` |
| HTTP 429 | `rate_limited` (`FailureRateLimited`) | `ErrRateLimited` |
| HTTP 400, any other 4xx, or 405 on a call that names no batch; a `Finish` or `Delete` answer in a 2xx whose JSON object has an `error` member that is not `null` | `rejected` (`FailureRejected`) | `ErrRejected` |
| HTTP 503 | `unavailable` (`FailureUnavailable`) | `ErrUnavailable` |
| Any other HTTP 5xx | `upstream` (`FailureUpstream`) | `ErrUpstream` |
| An error envelope inside a 2xx | the kind of the envelope's status | as for that status |
| HTTP 1xx, 3xx (never followed), 600+ or a 2xx the call does not accept; an undecoded `Content-Encoding`; a content type that does not match; a JSON object (not an error envelope) where an array or a file was expected; another batch's status | `unexpected_response` (`FailureUnexpectedResponse`) | `ErrUnexpectedResponse` |
| Invalid UTF-8 or JSON (a lone surrogate escape included), a truncated array, trailing data, an array or scalar where an object was expected (a `Finish` or `Delete` answer included), a missing required field or a wrong type | `malformed_response` (`FailureMalformedResponse`) | `ErrMalformedResponse` |
| A body or download over its limit (a `Finish` or `Delete` answer over 4 KiB included), or a record or field over its bound | `response_too_large` (`FailureResponseTooLarge`) | `ErrResponseTooLarge` |
| `Download`'s writer failed or wrote short | `write_failed` (`FailureWriteFailed`) | `ErrWriteFailed` |
| `Wait` saw an undocumented state | `unknown_batch_state` (`FailureUnknownBatchState`) | `ErrUnknownBatchState` |
| `Wait`'s `MaxWait` ran out | `budget_exhausted` (`FailureBudgetExhausted`) | `ErrBudgetExhausted` |

The accepted success statuses are 200, 201 or 202 for `Create`; 200, 202 or 204 for `Finish` and `Delete`
(with an empty body, or a JSON object whose `error` member is absent or null); and 200 for everything else.
The body of an error response is read best-effort, up to 4 KiB, only for `APIStatus` and the opt-in message:
the HTTP status alone classifies it. An error envelope is a JSON object whose `status` is a three-digit JSON
integer or a string of three digits, from 400 to 599: inside a 2xx it fails the call by that status, while an
object with a lower status is judged as an ordinary answer (so a `Finish` acknowledgement such as
`{"status":200}` succeeds).

</details>

<br/>

### Where Bouncer's documentation is ambiguous

<details>
<summary><strong><code>What Bouncer's v1.1 documentation leaves open, and what the SDK does</code></strong></summary>
<br/>

| Question | SDK behavior |
|---|---|
| The batch-create body is declared as a string, while every example sends an array. | A JSON array of `{"email": …}` objects. |
| Batches hold 100,000 entries in the technical documentation and 500,000 on a marketing page. | 100,000 (`MaxBatchEntries`). |
| Create answers 200 in the reference, not 201. | 200, 201 or 202 with a valid `batchId`. |
| Error envelopes carry `status` as a string in some examples and a number in others, sometimes different from the HTTP status. | Both forms are read into `APIStatus`; the HTTP status decides a non-2xx answer, the envelope an answer inside a 2xx. |
| Finish's "200" example holds an error body with status 400; batch-sync's 400 example says 404; several 403 examples are mislabelled. | An error envelope (status 400 to 599) inside a 2xx is an error; the HTTP status decides otherwise; 403 is `ErrForbidden`, meaning undocumented. |
| Finish's real success status and body. | 200, 202 or 204 with an empty body or a JSON object without an `error` member (`null` counts as none). |
| The verification schema forbids extra members, yet examples carry `didYouMean`. | Unknown members are ignored; `didYouMean` is decoded. |
| A score is "empty" when evaluation makes no sense, without saying how. | Absent, `null` and `""` are all `nil`; values are not range-checked. |
| `retryAfter` appears in one example only, undescribed. | Kept as opaque text, never acted on. |
| Batch states beyond `queued`, `processing` and `completed`. | Kept; `Wait` stops on one it does not know. |
| The download filter's default and the CSV columns. | The filter is always sent; CSV bytes are copied, never parsed. |
| Result order, one result per entry, duplicates. | Bouncer's order is kept; nothing is correlated or deduplicated. |
| The optional batch-entry `name`, documented only in the older reference and the Java SDK. | Supported as `BatchEntry.Name`, unverified, never a correlation key. |
| The real-time `timeout` minimum and out-of-range behavior. | 1 to 30 whole seconds, checked locally. |
| How long results are kept, and which states block a delete (both 405). | `ErrBatchState`, whatever the cause. |
| The callback's payload, signing and retries. | Sent when set; a hint only. |
| Batch-sync's rate limit (100 or 10 a minute) and spacing (5 seconds to 10 minutes, or 15 seconds). | Documented, never enforced. |
| Whether real-time `unknown` results are charged (the reference is silent). | Nothing assumed. |
| Rate-limit, request-ID and idempotency headers. | None assumed; a standard `Retry-After` is read on 429 and 503 only. |

</details>

<br/>

### What is not covered

The plain-text batch upload (its `skip-header` parameter is undocumented), domain verification
(`/v1.1/domain`), the toxicity and sampling endpoints of API v1, receiving batch callbacks, and account
administration. Each would be added as one more method, without changing existing ones.

<br/>

## 🧪 Examples & Tests

All unit tests, fuzz tests and examples run via [GitHub Actions](https://github.com/mrz1836/go-bouncer/actions) on Go 1.26.x. View the [configuration file](.github/workflows/fortress.yml).

Run all tests (fast):

```bash script
magex test
```

Run all tests with race detector (slower):
```bash script
magex test:race
```

The package's `Example*` functions are compiled with the tests; those that send nothing (`NewClient`,
`ValidationError`, `WithHTTPClient`, the handler, the fake and the JSON round trip) also run and check their
output. Every Go block in this README is quoted from them or from
[examples/quickstart](examples/quickstart/main.go), which makes one live call, and only with `-live`.

> **Note:** tests never touch the network. They use in-memory transports and local TLS servers over
HTTP/1.1 and HTTP/2, with synthetic data only, and run in parallel.

<br/>

### Live tests

`live_internal_test.go` (build tag `live`) runs the SDK against the real Bouncer API with your own key and
logs the shape of each answer, never its values. It is opt-in, so it never runs by default or in CI: it
skips unless `BOUNCER_LIVE=1`, and each tier runs only when listed in `BOUNCER_LIVE_TIERS`.

```bash
BOUNCER_LIVE=1 BOUNCER_LIVE_TIERS=credits BOUNCER_API_KEY=… go test -tags live -run '^TestLive' -count=1 -v .
```

The `credits` tier is free. The `verify` tier verifies one sandbox address. The `batch` tier **creates a
two-entry batch of sandbox addresses that stays in your account** (Delete is never called; its ID is
logged), waits for it and reads its results.

<br/>

## ⚡ Benchmarks

Run the Go benchmarks:

```bash script
magex bench
```

<br/>

### 📊 Performance Results

| Benchmark | Iterations | ns/op | B/op | allocs/op |
|---|---:|---:|---:|---:|
| [DecodeVerification](benchmark_internal_test.go) | 384,844 | 5,590 | 2,112 | 59 |
| [VerifyEndToEnd](benchmark_test.go) | 229,420 | 10,306 | 6,443 | 105 |
| [ScanArray](benchmark_internal_test.go) | 186 | 12,858,688 | 66,704 | 11 |
| [ResultsStream](benchmark_test.go) | 33 | 69,772,880 | 21,758,369 | 639,955 |
| [VerifyBatchSync10k](benchmark_test.go) | 32 | 72,647,395 | 39,035,423 | 640,031 |
| [EncodeCreateBatch10k](benchmark_internal_test.go) | 2,376 | 991,208 | 1,116,722 | 8 |
| [DownloadCopy](benchmark_test.go) | 1,029 | 2,318,979 | 110,482 | 44 |

> DecodeVerification decodes one full record; VerifyEndToEnd makes a whole `Verify` call against an
> in-memory transport; ScanArray frames a 10,000-record array (3.4 MB) without decoding it (about 265 MB/s);
> ResultsStream ranges over the same 10,000 records through `Results` (about 49 MB/s, 64 allocations per
> record), and VerifyBatchSync10k decodes them as a batch-sync answer; EncodeCreateBatch10k validates and
> encodes a 10,000-entry batch; DownloadCopy streams 64 MiB to `io.Discard` (about 29 GB/s). They measure
> local CPU work only, executed with `go test -bench . -benchtime 2s` on an Apple M1 Max (ARM64) with Go
> 1.26.9, and make no claim about network or Bouncer latency, which dominates real calls. A test
> (`TestAllocationCeilings`) fails if decoding a record, a `Verify` call or a streamed record starts
> allocating noticeably more.

<br/>

## 🧰 Development

View the generated [documentation](https://pkg.go.dev/github.com/mrz1836/go-bouncer?tab=doc) and
[Bouncer's API documentation](https://docs.usebouncer.com).

<details>
<summary><strong><code>Development Setup (Getting Started)</code></strong></summary>
<br/>

Install [MAGE-X](https://github.com/mrz1836/mage-x) build tool for development:

```bash
# Install MAGE-X for development and building
go install github.com/mrz1836/mage-x/cmd/magex@latest
magex update:install
```
</details>

<details>
<summary><strong><code>Lint, Fuzz and Coverage</code></strong></summary>
<br/>

Lint with the repository's [golangci-lint configuration](.golangci.json):

```bash
magex lint
```

Run every fuzz target briefly, or one target for longer:

```bash
magex test:fuzzshort
go test -run '^$' -fuzz '^FuzzScanArray$' -fuzztime 1m .
```

The fuzz targets are `FuzzScanArray`, `FuzzDecodeVerification`, `FuzzEnvelope`, `FuzzRetryAfter`,
`FuzzBatchIDPath`, `FuzzEmailQuery` and `FuzzTestBaseURL`.

Measure coverage:

```bash
magex test:cover
```

</details>

<details>
<summary><strong><code>Library Deployment</code></strong></summary>
<br/>

This project uses [goreleaser](https://github.com/goreleaser/goreleaser) for streamlined library releases to GitHub. To get started, install it via:

```bash
brew install goreleaser
```

The release process is defined in the [.goreleaser.yml](.goreleaser.yml) configuration file.

Then create and push a new Git tag using:

```bash
magex version:bump bump=patch push=true branch=master
```

</details>

<details>
<summary><strong><code>Build Commands</code></strong></summary>
<br/>

View all build commands

```bash script
magex help
```

</details>

<details>
<summary><strong><code>GitHub Workflows</code></strong></summary>
<br/>

All workflows are driven by modular configuration in [`.github/env/`](.github/env/README.md) — no YAML editing required.

**[View all workflows and the control center →](.github/docs/workflows.md)**

</details>

<details>
<summary><strong><code>Updating Dependencies</code></strong></summary>
<br/>

To update all dependencies (Go modules, linters, and related tools), run:

```bash
magex deps:update
```

</details>

<br/>

## 🛠️ Code Standards
Read more about this Go project's [code standards](.github/CODE_STANDARDS.md).

<br/>

## 🤖 AI Usage & Assistant Guidelines
Read the [AI Usage & Assistant Guidelines](.github/tech-conventions/ai-compliance.md) for details on how AI is used in this project and how to interact with the AI assistants.

<br/>

## 👥 Maintainers
| [<img src="https://github.com/mrz1836.png" height="50" alt="MrZ" />](https://github.com/mrz1836) |
|:------------------------------------------------------------------------------------------------:|
|                                [MrZ](https://github.com/mrz1836)                                 |

<br/>

## 🤝 Contributing
View the [contributing guidelines](.github/CONTRIBUTING.md) and please follow the [code of conduct](.github/CODE_OF_CONDUCT.md).

### How can I help?
All kinds of contributions are welcome :raised_hands:!
The most basic way to show your support is to star :star2: the project, or to raise issues :speech_balloon:.
You can also support this project by [becoming a sponsor on GitHub](https://github.com/sponsors/mrz1836) :clap:
or by making a [**bitcoin donation**](https://mrz1818.com/?tab=tips&utm_source=github&utm_medium=sponsor-link&utm_campaign=go-bouncer&utm_term=go-bouncer&utm_content=go-bouncer) to ensure this journey continues indefinitely! :rocket:


[![Stars](https://img.shields.io/github/stars/mrz1836/go-bouncer?label=Please%20like%20us&style=social)](https://github.com/mrz1836/go-bouncer/stargazers)

<br/>

## 📝 License

go-bouncer is released under the [MIT License](LICENSE).

[![License](https://img.shields.io/github/license/mrz1836/go-bouncer.svg?style=flat&v=1)](LICENSE)
