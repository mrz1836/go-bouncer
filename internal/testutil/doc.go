// Package testutil holds the test plumbing go-bouncer's tests share: testdata
// fixtures, HTTP fakes, a recording TLS server for HTTP/1.1 and HTTP/2, a
// scripted transport, writer fakes for streaming downloads, formatting-leak
// assertions, race-aware allocation guards, and the value-free shape printer
// the live tests report with.
//
// It is imported only by tests. It imports testify and the standard library,
// never the bouncer package, so that the root package's internal tests can use
// it too.
package testutil
