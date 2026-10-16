package bouncer

import (
	"bytes"
	"context"
	"encoding/json"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

// Request bounds.
const (
	maxNameBytes        = 256
	maxCallbackURLBytes = 2048
	maxBatchIDBytes     = 128

	// maxBatchBodyBytes and maxSyncBodyBytes bound the encoded request bodies
	// of Create and VerifyBatchSync.
	maxBatchBodyBytes = 64 << 20
	maxSyncBodyBytes  = 8 << 20

	minVerifyTimeout      = time.Second
	verifyTimeoutHeadroom = 10 * time.Second
)

// prepare runs the checks every call starts with: a Client built by
// NewClient, then a non-nil context.
func (c *Client) prepare(ctx context.Context) error {
	if err := c.ready(); err != nil {
		return err
	}
	if ctx == nil {
		return invalidRequest("ctx", reasonNil)
	}
	return nil
}

// checkEmail validates one address: 1 to MaxEmailBytes bytes of valid UTF-8.
// Nothing else is checked, and the address is sent verbatim: a malformed
// address is a legitimate input for the provider to judge.
func checkEmail(field, s string) error {
	if reason := emailProblem(s); reason != "" {
		return invalidRequest(field, reason)
	}
	return nil
}

// emailProblem returns the reason s is not a valid address input, or "". It
// builds nothing, so callers can render a field path only on failure.
func emailProblem(s string) string {
	switch {
	case s == "":
		return reasonRequired
	case len(s) > MaxEmailBytes:
		return reasonTooLong
	case !utf8.ValidString(s):
		return reasonInvalidUTF8
	}
	return ""
}

// nameProblem returns the reason a BatchEntry.Name is invalid, or "": it is
// optional, and at most 256 bytes of valid UTF-8.
func nameProblem(s string) string {
	switch {
	case len(s) > maxNameBytes:
		return reasonTooLong
	case !utf8.ValidString(s):
		return reasonInvalidUTF8
	}
	return ""
}

// elemPath returns the path of element i of a list, such as "[17]".
func elemPath(i int64) string { return "[" + strconv.FormatInt(i, 10) + "]" }

// indexed returns a field path such as "Entries[17].Email".
func indexed(list string, i int, field string) string {
	path := list + elemPath(int64(i))
	if field != "" {
		path += "." + field
	}
	return path
}

// checkBatchID validates a batch handle as one path segment the SDK can
// address safely: 1 to 128 bytes of visible ASCII, without '/', '\', '?', '#'
// or '%', not "." or "..", and not "sync" in any case, which would address
// the batch-sync route instead. The provider's IDs look like 24 hexadecimal
// digits, which the SDK does not enforce.
func checkBatchID(id BatchID) error {
	if reason := batchIDProblem(id); reason != "" {
		return invalidRequest("BatchID", reason)
	}
	return nil
}

// batchIDProblem returns the reason id is not a valid batch handle, or "".
func batchIDProblem(id BatchID) string {
	s := string(id)
	switch {
	case s == "":
		return reasonRequired
	case len(s) > maxBatchIDBytes:
		return reasonTooLong
	case !asciiRange(s, 0x21, 0x7e) || strings.ContainsAny(s, `/\?#%`) ||
		s == "." || s == ".." || strings.EqualFold(s, "sync"):
		return reasonInvalidFormat
	}
	return ""
}

// checkCallbackURL validates an optional callback URL: at most 2048 bytes,
// without whitespace or control characters, an absolute https URL with a host
// and no fragment.
func checkCallbackURL(raw string) error {
	const field = "CallbackURL"
	switch {
	case raw == "":
		return nil
	case len(raw) > maxCallbackURLBytes:
		return invalidRequest(field, reasonTooLong)
	case !utf8.ValidString(raw) || strings.ContainsFunc(raw, isSpaceOrControl) || strings.ContainsRune(raw, '#'):
		return invalidRequest(field, reasonInvalidURL)
	}
	u, err := url.Parse(raw)
	switch {
	case err != nil || u.Opaque != "" || u.Hostname() == "" || u.Fragment != "":
		if err == nil && u.Scheme != "" && u.Scheme != "https" {
			return invalidRequest(field, reasonUnsupportedScheme)
		}
		return invalidRequest(field, reasonInvalidURL)
	case u.Scheme != "https":
		return invalidRequest(field, reasonUnsupportedScheme)
	}
	return nil
}

// isSpaceOrControl reports whether r is whitespace or a control character,
// which a URL must not contain.
func isSpaceOrControl(r rune) bool {
	return r <= ' ' || r == 0x7f || (r >= 0x80 && r <= 0x9f) || r == 0x85 || r == 0xa0 ||
		r == 0x1680 || (r >= 0x2000 && r <= 0x200a) || r == 0x2028 || r == 0x2029 ||
		r == 0x202f || r == 0x205f || r == 0x3000 || r == 0xfeff
}

// checkVerifyTimeout validates VerifyRequest.Timeout against the Client's own
// timeout.
func checkVerifyTimeout(d, clientTimeout time.Duration) error {
	switch {
	case d == 0:
		return nil
	case d < minVerifyTimeout || d > MaxVerifyTimeout:
		return invalidRequest("Timeout", reasonOutOfRange)
	case d%time.Second != 0:
		return invalidRequest("Timeout", reasonNotWholeSeconds)
	case d+verifyTimeoutHeadroom > clientTimeout:
		return invalidRequest("Timeout", reasonExceedsClientTimeout)
	}
	return nil
}

// encodeJSON returns v as compact JSON without HTML escaping, so that strings
// reach the provider as close to verbatim as JSON allows. Its inputs are
// strings already checked to be valid UTF-8, so nothing is substituted, and
// encoding them cannot fail: callers check the error defensively.
func encodeJSON(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(buf.Bytes(), []byte{'\n'}), nil
}
