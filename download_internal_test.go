package bouncer

import (
	"errors"
	"io"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// downloadCountWriter returns a fixed count and error from every Write.
type downloadCountWriter struct {
	n   int
	err error
}

// Write reports the fixed answer.
func (w downloadCountWriter) Write([]byte) (int, error) { return w.n, w.err }

var errDownloadWriter = errors.New("download test writer failed")

func TestWriteChunk(t *testing.T) {
	t.Parallel()
	p := []byte("abcdef")
	tests := []struct {
		name string
		w    io.Writer
		n    int
		ok   bool
	}{
		{"full write", downloadCountWriter{n: 6}, 6, true},
		{"short write without error", downloadCountWriter{n: 2}, 2, false},
		{"full write with error", downloadCountWriter{n: 6, err: errDownloadWriter}, 6, false},
		{"partial write with error", downloadCountWriter{n: 3, err: errDownloadWriter}, 3, false},
		{"zero write", downloadCountWriter{}, 0, false},
		{"negative count", downloadCountWriter{n: -1}, 0, false},
		{"count over the chunk", downloadCountWriter{n: 7}, 0, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			n, ok := writeChunk(tt.w, p)
			assert.Equal(t, tt.n, n)
			assert.Equal(t, tt.ok, ok)
		})
	}
}

func TestLastNonSpace(t *testing.T) {
	t.Parallel()
	tests := []struct {
		in   string
		want int
	}{
		{"", -1},
		{" \t\r\n", -1},
		{"]", 0},
		{"[1] \n", 2},
		{"a b", 2},
		{"\x00", 0},
	}
	for _, tt := range tests {
		assert.Equal(t, tt.want, lastNonSpace([]byte(tt.in)), "%q", tt.in)
	}
}

func TestIsCSVMedia(t *testing.T) {
	t.Parallel()
	for _, m := range []string{"text/csv", "application/csv", "text/plain", "application/octet-stream"} {
		assert.True(t, isCSVMedia(m), m)
	}
	for _, m := range []string{"", "text/html", "application/json", "text/csv; charset=utf-8", "TEXT/CSV", "text/*"} {
		assert.False(t, isCSVMedia(m), "%q: isCSVMedia sees parsed, lowercased media types only", m)
	}
}

func TestDownloadFormatAccept(t *testing.T) {
	t.Parallel()
	accept, ok := FormatJSON.accept()
	assert.True(t, ok)
	assert.Equal(t, "application/json", accept)
	accept, ok = FormatCSV.accept()
	assert.True(t, ok)
	assert.Equal(t, mediaCSV, accept)
	for _, f := range []DownloadFormat{"", "JSON", "xml", "tsv"} {
		_, ok := f.accept()
		assert.False(t, ok, "%q", f)
	}
}

func TestSniff(t *testing.T) {
	t.Parallel()
	c := newTestClient(t, nil)
	tests := []struct {
		name   string
		head   string
		whole  bool
		format DownloadFormat
		kind   FailureKind
	}{
		{"json array", "[]", true, FormatJSON, ""},
		{"json array, partial", " \n[", false, FormatJSON, ""},
		{"json envelope", `{"status":404}`, true, FormatJSON, FailureNotFound},
		{"json object, partial", `{"status":404`, false, FormatJSON, FailureUnexpectedResponse},
		{"json non-envelope object", `{"a":1}`, true, FormatJSON, FailureUnexpectedResponse},
		{"json empty", "", true, FormatJSON, FailureMalformedResponse},
		{"json word", "null", true, FormatJSON, FailureMalformedResponse},
		{"json word, partial", "nul", false, FormatJSON, FailureMalformedResponse},
		{"csv", "email\r\n", true, FormatCSV, ""},
		{"csv empty", "", true, FormatCSV, ""},
		{"csv envelope", ` {"status":"402"} `, true, FormatCSV, FailurePaymentRequired},
		{"csv non-envelope object", `{"a":1}`, true, FormatCSV, FailureUnexpectedResponse},
		{"csv invalid object", `{"a":}`, true, FormatCSV, ""},
		{"csv object, partial", `{"status":402}`, false, FormatCSV, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			cerr := c.sniff([]byte(tt.head), tt.whole, tt.format, 200)
			if tt.kind == "" {
				assert.Nil(t, cerr)
				return
			}
			require.NotNil(t, cerr)
			assert.Equal(t, tt.kind, cerr.Kind)
			assert.Equal(t, 200, cerr.StatusCode)
		})
	}
}
