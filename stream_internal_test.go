package bouncer

import (
	"errors"
	"io"
	"strings"
	"testing"
	"testing/iotest"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Scan test errors.
var (
	// errScanReader is the reader failure the scanner must pass on unchanged.
	errScanReader = errors.New("scan test: reader failed")

	// errScanRunaway stops scanAll on input with too many elements.
	errScanRunaway = errors.New("scan test: runaway scan")
)

// scanAll reads every element of r and returns copies of them, with the
// error that ended the scan (io.EOF at a clean end).
func scanAll(r io.Reader) ([]string, error) {
	sc := newArrayScanner(r)
	var out []string
	for {
		elem, err := sc.next()
		if err != nil {
			return out, err
		}
		out = append(out, string(elem))
		if len(out) > 1000 {
			return out, errScanRunaway
		}
	}
}

func TestArrayScannerFraming(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name  string
		input string
		elems []string
	}{
		{"empty array", `[]`, nil},
		{"empty array with whitespace", " \t\r\n[ \t\r\n] \t\r\n", nil},
		{"one element", `[{"a":1}]`, []string{`{"a":1}`}},
		{"empty object", `[{}]`, []string{`{}`}},
		{"elements with whitespace", "\n[\n  {\"a\":1} ,\r\n\t{\"b\":2}\n]\n", []string{`{"a":1}`, `{"b":2}`}},
		{"brackets inside strings", `[{"a":"]}"},{"b":"[{"}]`, []string{`{"a":"]}"}`, `{"b":"[{"}`}},
		{"escaped quote inside a string", `[{"a":"\"]}"}]`, []string{`{"a":"\"]}"}`}},
		{
			"escaped backslash before the closing quote", `[{"a":"\\"},{"b":"]"}]`,
			[]string{`{"a":"\\"}`, `{"b":"]"}`},
		},
		{"escaped backslash then quote", `[{"a":"\\\"}"}]`, []string{`{"a":"\\\"}"}`}},
		{"unicode escapes", `[{"a":"]}"}]`, []string{`{"a":"]}"}`}},
		{"nested objects and arrays", `[{"a":{"b":[1,{"c":[]}],"d":{}}}]`, []string{`{"a":{"b":[1,{"c":[]}],"d":{}}}`}},
		{"element bytes are kept as sent", `[{ "a" : [ 1 , 2 ] }]`, []string{`{ "a" : [ 1 , 2 ] }`}},
		{"multibyte text", `[{"a":"été 😀"}]`, []string{`{"a":"été 😀"}`}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := scanAll(strings.NewReader(tc.input))
			require.ErrorIs(t, err, io.EOF)
			assert.Equal(t, tc.elems, got)
		})
	}
}

func TestArrayScannerFaults(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name  string
		input string
		elems int
		cause error
		field string
	}{
		{"empty input", ``, 0, errTruncated, ""},
		{"only whitespace", " \n\t", 0, errTruncated, ""},
		{"null element", `[null]`, 0, errWrongKind, "[0]"},
		{"number element", `[1]`, 0, errWrongKind, "[0]"},
		{"string element", `["x"]`, 0, errWrongKind, "[0]"},
		{"array element", `[[]]`, 0, errWrongKind, "[0]"},
		{"boolean element", `[true]`, 0, errWrongKind, "[0]"},
		{"later element of the wrong kind", `[{},{},7]`, 2, errWrongKind, "[2]"},
		{"leading comma", `[,{}]`, 0, errInvalidJSON, "[0]"},
		{"stray closing brace", `[}]`, 0, errInvalidJSON, "[0]"},
		{"trailing comma", `[{"a":1},]`, 1, errInvalidJSON, "[1]"},
		{"double comma", `[{"a":1},,{"b":2}]`, 1, errInvalidJSON, "[1]"},
		{"missing comma", `[{"a":1}{"b":2}]`, 1, errInvalidJSON, "[1]"},
		{"separator other than a comma", `[{"a":1};{"b":2}]`, 1, errInvalidJSON, "[1]"},
		{"unclosed array after an element", `[{}`, 1, errTruncated, "[1]"},
		{"unclosed array after a comma", `[{},`, 1, errTruncated, "[1]"},
		{"unclosed array", `[`, 0, errTruncated, "[0]"},
		{"truncated element", `[{"a":"b"`, 0, errTruncated, "[0]"},
		{"truncated inside a string", `[{},{"a":"]}`, 1, errTruncated, "[1]"},
		{"truncated after an escape", `[{"a":"\`, 0, errTruncated, "[0]"},
		{"trailing data", `[{"a":1}] x`, 1, errTrailingData, ""},
		{"trailing array", `[][]`, 0, errTrailingData, ""},
		{"trailing object", `[{}]{}`, 1, errTrailingData, ""},
		{"non-array start", `x`, 0, errWrongKind, ""},
		{"string start", `"[]"`, 0, errWrongKind, ""},
		{"number start", `12`, 0, errWrongKind, ""},
		{"null start", `null`, 0, errWrongKind, ""},
		{"byte order mark", "\xef\xbb\xbf[]", 0, errWrongKind, ""},
		{"closing bracket start", `]`, 0, errWrongKind, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := scanAll(strings.NewReader(tc.input))
			assert.Len(t, got, tc.elems, "elements before the fault")
			requireDecodeError(t, err, FailureMalformedResponse, tc.cause, tc.field)
		})
	}
}

func TestArrayScannerElementBound(t *testing.T) {
	t.Parallel()
	element := func(size int) string {
		const shell = `{"a":""}`
		return `{"a":"` + strings.Repeat("x", size-len(shell)) + `"}`
	}
	t.Run("exactly the bound", func(t *testing.T) {
		t.Parallel()
		e := element(maxRecordBytes)
		require.Len(t, e, maxRecordBytes)
		got, err := scanAll(strings.NewReader(`[{},` + e + `,{}]`))
		require.ErrorIs(t, err, io.EOF)
		require.Len(t, got, 3)
		assert.Equal(t, e, got[1])
	})
	t.Run("one byte over the bound", func(t *testing.T) {
		t.Parallel()
		got, err := scanAll(strings.NewReader(`[{},{},` + element(maxRecordBytes+1) + `]`))
		assert.Len(t, got, 2)
		requireDecodeError(t, err, FailureResponseTooLarge, errFieldTooLarge, "[2]")
	})
	t.Run("far over the bound fails early", func(t *testing.T) {
		t.Parallel()
		r := &countingScanReader{r: strings.NewReader(`[` + element(4*maxRecordBytes) + `]`)}
		_, err := scanAll(r)
		requireDecodeError(t, err, FailureResponseTooLarge, errFieldTooLarge, "[0]")
		assert.Less(t, r.n, int64(2*maxRecordBytes+streamBufferBytes), "the scan stops at the bound")
	})
	t.Run("a smaller bound", func(t *testing.T) {
		t.Parallel()
		sc := newArrayScanner(strings.NewReader(`[{"a":1},{"bb":22}]`))
		sc.maxElem = len(`{"a":1}`)
		elem, err := sc.next()
		require.NoError(t, err)
		assert.Equal(t, `{"a":1}`, string(elem))
		_, err = sc.next()
		requireDecodeError(t, err, FailureResponseTooLarge, errFieldTooLarge, "[1]")
	})
}

// countingScanReader counts the bytes read through it.
type countingScanReader struct {
	r io.Reader
	n int64
}

// Read reads from the wrapped reader and counts the bytes.
func (c *countingScanReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += int64(n)
	return n, err
}

func TestArrayScannerObjectBody(t *testing.T) {
	t.Parallel()
	t.Run("an object instead of the array", func(t *testing.T) {
		t.Parallel()
		const body = `{"status":"402","error":"Payment Required","message":"m"}`
		sc := newArrayScanner(strings.NewReader("  \n" + body + "\n "))
		_, err := sc.next()
		require.ErrorIs(t, err, errObjectBody)
		obj, err := sc.object()
		require.NoError(t, err)
		assert.Equal(t, []byte(body), obj) //nolint:testifylint // the exact bytes, not equivalent JSON
	})
	t.Run("object with trailing data", func(t *testing.T) {
		t.Parallel()
		sc := newArrayScanner(strings.NewReader(`{"status":400} []`))
		_, err := sc.next()
		require.ErrorIs(t, err, errObjectBody)
		_, err = sc.object()
		requireDecodeError(t, err, FailureMalformedResponse, errTrailingData, "")
	})
	t.Run("truncated object", func(t *testing.T) {
		t.Parallel()
		// A clean end of input inside the object is truncation, as it is
		// inside an array element, never the clean end io.EOF reports.
		sc := newArrayScanner(strings.NewReader(`{"status":`))
		_, err := sc.next()
		require.ErrorIs(t, err, errObjectBody)
		_, err = sc.object()
		requireDecodeError(t, err, FailureMalformedResponse, errTruncated, "")
	})
	t.Run("object over the bound", func(t *testing.T) {
		t.Parallel()
		sc := newArrayScanner(strings.NewReader(`{"a":"` + strings.Repeat("x", maxRecordBytes) + `"}`))
		_, err := sc.next()
		require.ErrorIs(t, err, errObjectBody)
		_, err = sc.object()
		requireDecodeError(t, err, FailureResponseTooLarge, errFieldTooLarge, "")
	})
	t.Run("object reader failure", func(t *testing.T) {
		t.Parallel()
		sc := newArrayScanner(io.MultiReader(strings.NewReader(`{"status":`), iotest.ErrReader(errScanReader)))
		_, err := sc.next()
		require.ErrorIs(t, err, errObjectBody)
		_, err = sc.object()
		require.ErrorIs(t, err, errScanReader)
	})
}

func TestArrayScannerReaderErrors(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name   string
		prefix string
		err    error
		elems  int
	}{
		{"before the array", ``, errScanReader, 0},
		{"inside an element", `[{"a":`, errScanReader, 0},
		{"between elements", `[{"a":1},`, errScanReader, 1},
		{"after the array", `[{"a":1}]`, errScanReader, 1},
		{"unexpected EOF", `[{"a":1},{"b"`, io.ErrUnexpectedEOF, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			r := io.MultiReader(strings.NewReader(tc.prefix), iotest.ErrReader(tc.err))
			got, err := scanAll(r)
			assert.Len(t, got, tc.elems)
			require.ErrorIs(t, err, tc.err, "the reader's own error is passed on")
			_, isDecode := errors.AsType[*decodeError](err)
			assert.False(t, isDecode, "a reader error is not a decode failure")
			if errors.Is(tc.err, io.ErrUnexpectedEOF) {
				assert.NotErrorIs(t, err, io.EOF, "an unexpected EOF never looks like a clean end")
			}
		})
	}
	t.Run("one byte at a time", func(t *testing.T) {
		t.Parallel()
		got, err := scanAll(iotest.OneByteReader(strings.NewReader(`[ {"a":"]"} , {"b":[{}]} ]`)))
		require.ErrorIs(t, err, io.EOF)
		assert.Equal(t, []string{`{"a":"]"}`, `{"b":[{}]}`}, got)
	})
	t.Run("data with the final error", func(t *testing.T) {
		t.Parallel()
		got, err := scanAll(iotest.DataErrReader(strings.NewReader(`[{"a":1}]`)))
		require.ErrorIs(t, err, io.EOF)
		assert.Equal(t, []string{`{"a":1}`}, got)
	})
	t.Run("timeouts pass through", func(t *testing.T) {
		t.Parallel()
		_, err := scanAll(iotest.TimeoutReader(strings.NewReader(strings.Repeat(" ", 2*streamBufferBytes) + `[]`)))
		require.ErrorIs(t, err, iotest.ErrTimeout)
	})
}

func TestArrayScannerPathsAndBuffer(t *testing.T) {
	t.Parallel()
	sc := newArrayScanner(strings.NewReader(`[{"a":"first element"},{"b":2},{"c":3}]`))
	assert.Empty(t, sc.path(), "before the array")

	first, err := sc.next()
	require.NoError(t, err)
	assert.Equal(t, []byte(`{"a":"first element"}`), first) //nolint:testifylint // the exact bytes, not equivalent JSON
	assert.Equal(t, "[1]", sc.path(), "the next element's path")

	second, err := sc.next()
	require.NoError(t, err)
	assert.Equal(t, `{"b":2}`, string(second))
	assert.Same(t, &first[0], &second[0], "one reused buffer: an element is valid until the next call")
	assert.Equal(t, `{"b":2}`, string(first[:len(second)]), "the earlier element's bytes were overwritten")

	third, err := sc.next()
	require.NoError(t, err)
	assert.Equal(t, `{"c":3}`, string(third))
	assert.Equal(t, int64(3), sc.index)

	_, err = sc.next()
	require.ErrorIs(t, err, io.EOF)
	_, err = sc.next()
	require.ErrorIs(t, err, io.EOF, "a scan that ended stays ended")
}

func TestArrayScannerManyElements(t *testing.T) {
	t.Parallel()
	const n = 5000
	var b strings.Builder
	b.WriteString("[")
	for i := range n {
		if i > 0 {
			b.WriteString(",")
		}
		b.WriteString(`{"email":"avery.example@example.com","status":"risky","reason":"low_quality","note":"]},["}`)
	}
	b.WriteString("]")
	got, err := scanAll(strings.NewReader(b.String()))
	require.ErrorIs(t, err, errScanRunaway, "the helper caps its scans")
	assert.Len(t, got, 1001)

	sc := newArrayScanner(strings.NewReader(b.String()))
	count := 0
	for {
		elem, err := sc.next()
		if errors.Is(err, io.EOF) {
			break
		}
		require.NoError(t, err)
		_, derr := decodeVerification(elem, "")
		require.Nil(t, derr)
		count++
	}
	assert.Equal(t, n, count)
	assert.LessOrEqual(t, cap(sc.buf), 256, "the buffer stays the size of one element")
}
