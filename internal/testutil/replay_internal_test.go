package testutil

import (
	"bytes"
	"crypto/tls"
	"errors"
	"io"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// errShortWrite is the error failWriter returns.
var errShortWrite = errors.New("short write")

// failWriter fails every Write.
type failWriter struct{}

func (failWriter) Write([]byte) (int, error) { return 0, errShortWrite }

func TestWriteH2Frame(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	require.NoError(t, writeH2Frame(&buf, h2FramePing, h2FlagAck, 0x80000005, []byte("payload")))
	assert.Equal(t, []byte{
		0, 0, 7, // length, 24 bits
		h2FramePing, h2FlagAck,
		0x80, 0, 0, 5, // stream ID, written as given
		'p', 'a', 'y', 'l', 'o', 'a', 'd',
	}, buf.Bytes())

	buf.Reset()
	require.NoError(t, writeH2Frame(&buf, h2FrameSettings, 0, 0, nil))
	assert.Equal(t, []byte{0, 0, 0, h2FrameSettings, 0, 0, 0, 0, 0}, buf.Bytes(), "an empty frame is its header")

	assert.ErrorIs(t, writeH2Frame(failWriter{}, h2FrameSettings, 0, 0, nil), errShortWrite)
}

// h2Frame is one frame a raw client read.
type h2Frame struct {
	typ, flags byte
	payload    []byte
}

// readH2Frame reads one frame from r.
func readH2Frame(t *testing.T, r io.Reader) h2Frame {
	t.Helper()
	hdr := make([]byte, h2FrameHeaderLen)
	_, err := io.ReadFull(r, hdr)
	require.NoError(t, err)
	payload := make([]byte, int(hdr[0])<<16|int(hdr[1])<<8|int(hdr[2]))
	_, err = io.ReadFull(r, payload)
	require.NoError(t, err)
	return h2Frame{typ: hdr[3], flags: hdr[4], payload: payload}
}

// dialH2 opens a raw TLS connection to s that negotiates h2.
func dialH2(t *testing.T, s *H2Server) *tls.Conn {
	t.Helper()
	d := tls.Dialer{Config: &tls.Config{RootCAs: s.pool, NextProtos: []string{"h2"}, MinVersion: tls.VersionTLS12}}
	conn, err := d.DialContext(t.Context(), "tcp", s.ln.Addr().String())
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })
	tc, ok := conn.(*tls.Conn)
	require.True(t, ok)
	require.Equal(t, "h2", tc.ConnectionState().NegotiatedProtocol)
	return tc
}

// TestH2ServerFrames drives the server with frames Go's HTTP/2 client does not
// send unprompted: it acknowledges a SETTINGS and a PING, echoing the PING's
// payload, and ignores their acknowledgments.
func TestH2ServerFrames(t *testing.T) {
	t.Parallel()
	s := NewH2Server(t, H2RefusedStream)
	conn := dialH2(t, s)

	_, err := io.WriteString(conn, "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
	require.NoError(t, err)
	assert.Equal(t, h2Frame{typ: h2FrameSettings, payload: []byte{}}, readH2Frame(t, conn), "the server's SETTINGS")

	ping := []byte("12345678")
	for _, f := range []h2Frame{
		{typ: h2FrameSettings, flags: h2FlagAck}, // ignored
		{typ: h2FramePing, flags: h2FlagAck},     // ignored
		{typ: h2FrameSettings},                   // acknowledged
		{typ: h2FramePing, payload: ping},        // acknowledged with its payload
		{typ: 0x8, payload: []byte{0, 0, 0, 1}},  // WINDOW_UPDATE, ignored
	} {
		require.NoError(t, writeH2Frame(conn, f.typ, f.flags, 0, f.payload))
	}
	assert.Equal(t, h2Frame{typ: h2FrameSettings, flags: h2FlagAck, payload: []byte{}}, readH2Frame(t, conn))
	assert.Equal(t, h2Frame{typ: h2FramePing, flags: h2FlagAck, payload: ping}, readH2Frame(t, conn))
	assert.Zero(t, s.Headers())
}

// TestH2ServerDropsBrokenConnections closes connections mid-preface and
// mid-frame: the server ends each, and its cleanup still returns.
func TestH2ServerDropsBrokenConnections(t *testing.T) {
	t.Parallel()
	s := NewH2Server(t, H2RefusedStream)

	conn := dialH2(t, s)
	_, err := io.WriteString(conn, "PRI *")
	require.NoError(t, err)
	require.NoError(t, conn.Close(), "mid-preface")

	conn = dialH2(t, s)
	_, err = io.WriteString(conn, "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
	require.NoError(t, err)
	readH2Frame(t, conn)
	_, err = conn.Write([]byte{0, 0, 4, h2FramePing, 0, 0, 0, 0, 0, 'x'})
	require.NoError(t, err)
	require.NoError(t, conn.Close(), "mid-payload")
	assert.Zero(t, s.Headers())
}
