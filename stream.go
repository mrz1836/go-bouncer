package bouncer

import (
	"bufio"
	"errors"
	"io"
)

// streamBufferBytes is the read buffer of a streamed answer.
const streamBufferBytes = 64 << 10

// errObjectBody reports an answer that is a JSON object where an array was
// expected: possibly an error envelope, which arrayScanner.object reads.
var errObjectBody = errors.New("bouncer: response is an object, not an array")

// Scanner states.
const (
	scanStart  = iota // before the opening bracket
	scanFirst         // after the opening bracket
	scanNext          // after an element
	scanObject        // inside an object read in place of the array
	scanEnd           // after the closing bracket, or the object
	scanDone          // the input ended cleanly after the closing bracket
)

// arrayScanner reads a JSON array of objects one element at a time, so that
// memory stays bounded by one element whatever the array's length. It frames
// elements itself rather than relying on json.Decoder, which buffers each
// whole value and reads ahead, so that the bound is exact: every element is
// at most maxElem bytes, copied into one reused buffer.
//
// It checks only the framing: an opening bracket, objects separated by commas,
// a closing bracket, then nothing but whitespace up to the end of the input.
// Each element's own syntax is left to the decoder that reads it.
type arrayScanner struct {
	r       *bufio.Reader
	buf     []byte
	closers []byte
	maxElem int
	state   int
	index   int64
}

// newArrayScanner returns a scanner over r.
func newArrayScanner(r io.Reader) *arrayScanner {
	return &arrayScanner{r: bufio.NewReaderSize(r, streamBufferBytes), maxElem: maxRecordBytes, state: scanStart}
}

// next returns the next element, valid until the following call, or io.EOF
// once the array has ended cleanly. Other errors are final:
//   - errObjectBody: the input is an object, not an array (read it with
//     object, which carries on from its opening brace);
//   - a *decodeError: bad framing, a truncated array, data after it, an
//     element that is not an object, or one over maxElem bytes;
//   - any other error is the reader's own, for the caller to classify (an
//     io.EOF from the reader inside the array is reported as truncation).
func (s *arrayScanner) next() ([]byte, error) {
	for {
		c, err := s.nonSpace()
		if err != nil {
			return nil, s.endError(err)
		}
		switch s.state {
		case scanStart:
			switch c {
			case '[':
				s.state = scanFirst
				continue
			case '{':
				return nil, errObjectBody
			}
			return nil, malformed("", errWrongKind)
		case scanFirst:
			if c == ']' {
				s.state = scanEnd
				continue
			}
			return s.element(c)
		case scanNext:
			switch c {
			case ',':
				c, err = s.nonSpace()
				if err != nil {
					return nil, s.endError(err)
				}
				return s.element(c)
			case ']':
				s.state = scanEnd
				continue
			}
			return nil, malformed(s.path(), errInvalidJSON)
		default:
			// After the closing bracket, any byte is trailing data.
			return nil, malformed("", errTrailingData)
		}
	}
}

// object reads the whole input as one JSON object of at most maxElem bytes,
// after next returned errObjectBody, having read its opening brace, and
// returns it. It fails like next.
func (s *arrayScanner) object() ([]byte, error) {
	s.state = scanObject
	elem, err := s.element('{')
	if err != nil {
		return nil, err
	}
	s.state = scanEnd
	if _, err := s.next(); !errors.Is(err, io.EOF) {
		return nil, err
	}
	return elem, nil
}

// element reads one element that starts with c, which must be '{', up to its
// matching closing brace, tracking strings and escapes so that brackets inside
// them do not count. Each closing bracket must match the innermost open one.
func (s *arrayScanner) element(c byte) ([]byte, error) {
	switch c {
	case '{':
	case ']', ',', '}':
		return nil, malformed(s.path(), errInvalidJSON)
	default:
		return nil, malformed(s.path(), errWrongKind)
	}
	s.buf = append(s.buf[:0], c)
	// closers holds the bracket each open object or array must end with,
	// innermost last, so that a mismatched one fails here.
	s.closers = append(s.closers[:0], '}')
	inString, escaped := false, false
	for len(s.closers) > 0 {
		b, err := s.r.ReadByte()
		if err != nil {
			return nil, s.endError(err)
		}
		if len(s.buf) == s.maxElem {
			return nil, tooLarge(s.path())
		}
		s.buf = append(s.buf, b)
		switch {
		case escaped:
			escaped = false
		case inString:
			switch b {
			case '\\':
				escaped = true
			case '"':
				inString = false
			}
		case b == '"':
			inString = true
		case b == '{':
			s.closers = append(s.closers, '}')
		case b == '[':
			s.closers = append(s.closers, ']')
		case b == '}' || b == ']':
			if s.closers[len(s.closers)-1] != b {
				return nil, malformed(s.path(), errInvalidJSON)
			}
			s.closers = s.closers[:len(s.closers)-1]
		}
	}
	if s.state == scanFirst || s.state == scanNext {
		s.state = scanNext
	}
	s.index++
	return s.buf, nil
}

// nonSpace returns the next byte that is not JSON whitespace.
func (s *arrayScanner) nonSpace() (byte, error) {
	for {
		c, err := s.r.ReadByte()
		if err != nil || !isSpace(c) {
			return c, err
		}
	}
}

// endError maps a read error: io.EOF is the clean end after the closing
// bracket, and truncation anywhere before it; any other error is passed on.
func (s *arrayScanner) endError(err error) error {
	if !errors.Is(err, io.EOF) {
		return err
	}
	if s.state == scanEnd {
		s.state = scanDone
		return io.EOF
	}
	if s.state == scanDone {
		return io.EOF
	}
	return malformed(s.path(), errTruncated)
}

// path returns the JSON path of the element being read, such as "[17]".
func (s *arrayScanner) path() string {
	switch s.state {
	case scanStart, scanObject, scanEnd, scanDone:
		return ""
	}
	return elemPath(s.index)
}
