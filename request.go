package bouncer

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// Media types the SDK sends in Accept and Content-Type.
const (
	mediaJSON = "application/json"
	mediaCSV  = "text/csv"
)

// outgoing describes one request before it is built: everything the sender
// needs except the API key and the User-Agent, which only the sender holds.
type outgoing struct {
	op     Operation
	method string

	// path is the decoded path under apiRoot, such as "/email/verify", and
	// rawPath its escaped form when that differs, else "".
	path    string
	rawPath string

	// query is the encoded query string, without "?".
	query string

	// accept is the Accept header.
	accept string

	// body is the JSON request body, or nil for a call without one.
	body []byte
}

// request builds the HTTP request for o on host. The URL is assembled from its
// parts, never parsed from a string that holds request data.
//
// Every request is one the standard library will not resend on its own. A
// request whose Body is nil or http.NoBody, or that has a GetBody, counts as
// replayable: HTTP/1 resends a replayable GET on a new connection when a
// reused one fails before the first response byte, although the server may
// already have processed (and billed) it, and HTTP/2 may resend any of them
// after a refused stream, a GOAWAY or, depending on the Go version, a protocol
// error. So GetBody stays nil, a call with a JSON body sends it as a plain
// reader, and a GET or DELETE carries an empty Body that is not http.NoBody.
// On HTTP/1 the transport probes that empty body and drops it, so the bytes on
// the wire are those of a bodyless request.
//
// The one exception is a POST without a body (Finish), sent with http.NoBody
// and "Content-Length: 0", as servers expect: marking it would send it chunked
// instead. HTTP/1 resends it only when nothing was written; an injected
// HTTP/2 transport may resend it after a refused stream, a GOAWAY or,
// depending on the Go version, a protocol error.
func (o *outgoing) request(ctx context.Context, host string) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, o.method, "https://"+host, nil)
	if err != nil {
		return nil, err
	}
	req.URL.Path = apiRoot + o.path
	if o.rawPath != "" {
		req.URL.RawPath = apiRoot + o.rawPath
	}
	req.URL.RawQuery = o.query
	switch {
	case o.body != nil:
		req.Body = io.NopCloser(bytes.NewReader(o.body))
		req.ContentLength = int64(len(o.body))
	case o.method == http.MethodPost:
		req.Body = http.NoBody
	default:
		req.Body = emptyBody{}
	}
	req.GetBody = nil
	return req, nil
}

// header returns a fresh header map for one call: exactly X-Api-Key, Accept,
// User-Agent and, with a body, Content-Type. The values share one backing
// array, allocated per call so that no two requests share header memory; each
// is a full slice expression, so an append to one cannot overwrite the next.
//
// It never sets Authorization, Cookie, Referer, Expect or an idempotency key:
// with an Idempotency-Key header, the standard library may resend a POST.
// Accept-Encoding is left to the transport, which then decodes gzip itself.
func (o *outgoing) header(apiKey, userAgent string) http.Header {
	n := 3
	if o.body != nil {
		n = 4
	}
	v := append(make([]string, 0, n), apiKey, o.accept, userAgent)
	h := make(http.Header, n)
	h["X-Api-Key"] = v[0:1:1]
	h["Accept"] = v[1:2:2]
	h["User-Agent"] = v[2:3:3]
	if o.body != nil {
		v = append(v, mediaJSON)
		h["Content-Type"] = v[3:4:4]
	}
	return h
}

// emptyBody is the empty request body of a GET or DELETE. It is a type of its
// own, never http.NoBody, so that the standard library does not count the
// request as safe to resend.
type emptyBody struct{}

// Read reports the end of the body.
func (emptyBody) Read([]byte) (int, error) { return 0, io.EOF }

// Close does nothing.
func (emptyBody) Close() error { return nil }

// Paths under apiRoot.
const (
	pathVerify  = "/email/verify"
	pathBatch   = "/email/verify/batch"
	pathSync    = "/email/verify/batch/sync"
	pathCredits = "/credits"
)

// batchPath returns the path of a call on batch id, with suffix (such as
// "/download") after it, decoded and escaped. id has passed checkBatchID, so
// it is one path segment that escaping keeps whole.
func batchPath(id BatchID, suffix string) (path, rawPath string) {
	path = pathBatch + "/" + string(id) + suffix
	escaped := url.PathEscape(string(id))
	if escaped == string(id) {
		return path, ""
	}
	return path, pathBatch + "/" + escaped + suffix
}

// queryParam appends "name=value" to a query under construction, with value
// percent-encoded strictly: every byte except the RFC 3986 unreserved
// characters, so that "+" is sent as "%2B" and a space as "%20", never "+".
func queryParam(b *strings.Builder, name, value string) {
	if b.Len() > 0 {
		b.WriteByte('&')
	}
	b.WriteString(name)
	b.WriteByte('=')
	const hexUpper = "0123456789ABCDEF"
	for i := range len(value) {
		c := value[i]
		if unreserved(c) {
			b.WriteByte(c)
			continue
		}
		b.WriteByte('%')
		b.WriteByte(hexUpper[c>>4])
		b.WriteByte(hexUpper[c&0xf])
	}
}

// unreserved reports whether c is an RFC 3986 unreserved character.
func unreserved(c byte) bool {
	return 'a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' || '0' <= c && c <= '9' ||
		c == '-' || c == '.' || c == '_' || c == '~'
}
