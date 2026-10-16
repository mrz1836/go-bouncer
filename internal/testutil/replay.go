package testutil

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// DropServer is a local TLS HTTP/1.1 server that answers each request with
// a Step, except the requests Drop selects: for those it reads the whole
// request and then closes the connection without writing a byte, as a server
// that crashed after processing it would. A client that resends such a
// request shows up as an extra hit.
type DropServer struct {
	srv   *httptest.Server
	hits  atomic.Int32
	conns atomic.Int32
}

// NewDropServer starts a DropServer. drop receives the 1-based number of each
// request and reports whether to drop it; every other request is answered
// with answer. It is closed when the test ends.
func NewDropServer(tb testing.TB, answer Step, drop func(n int) bool) *DropServer {
	tb.Helper()
	d := &DropServer{}
	serve := Serve(answer)
	d.srv = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := int(d.hits.Add(1))
		_, _ = io.Copy(io.Discard, r.Body)
		if !drop(n) {
			serve(w, r)
			return
		}
		conn, _, err := http.NewResponseController(w).Hijack()
		if err == nil {
			_ = conn.Close()
		}
	}))
	d.srv.Config.ErrorLog = log.New(io.Discard, "", 0)
	d.srv.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateNew {
			d.conns.Add(1)
		}
	}
	d.srv.StartTLS()
	tb.Cleanup(d.srv.Close)
	return d
}

// URL returns the server's base URL.
func (d *DropServer) URL() string { return d.srv.URL }

// Client returns an HTTP/1.1 client that trusts the server's certificate.
func (d *DropServer) Client() *http.Client { return d.srv.Client() }

// Hits returns the number of requests the server has read.
func (d *DropServer) Hits() int { return int(d.hits.Load()) }

// Conns returns the number of connections the server has accepted.
func (d *DropServer) Conns() int { return int(d.conns.Load()) }

// RootCAs returns a pool that trusts the server's certificate.
func (d *DropServer) RootCAs() *x509.CertPool {
	return d.srv.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs
}

// H2Fault is how an H2Server answers the first request it receives.
type H2Fault string

// HTTP/2 faults. The standard library's HTTP/2 client may retry a request
// after each of them when the request body allows it; whether it does depends
// on the Go version: Go 1.27 and later no longer retry after PROTOCOL_ERROR.
const (
	// H2RefusedStream resets the stream with REFUSED_STREAM.
	H2RefusedStream H2Fault = "refused_stream"

	// H2ProtocolError resets the stream with PROTOCOL_ERROR.
	H2ProtocolError H2Fault = "protocol_error"

	// H2GoAway sends GOAWAY with NO_ERROR and last stream 0, so that the
	// client counts the stream as never processed.
	H2GoAway H2Fault = "goaway"
)

// H2Faults returns every fault an H2Server can inject.
func H2Faults() []H2Fault { return []H2Fault{H2RefusedStream, H2ProtocolError, H2GoAway} }

// HTTP/2 frame types and flags the server uses.
const (
	h2FrameHeaders   = 0x1
	h2FrameRSTStream = 0x3
	h2FrameSettings  = 0x4
	h2FramePing      = 0x6
	h2FrameGoAway    = 0x7

	h2FlagAck        = 0x1
	h2FlagEndStream  = 0x1
	h2FlagEndHeaders = 0x4

	h2ErrProtocol      = 0x1
	h2ErrRefusedStream = 0x7

	// h2Status200 is the HPACK encoding of ":status: 200": index 8 of the
	// static table.
	h2Status200 = 0x88

	h2FrameHeaderLen = 9
	h2PrefaceLen     = 24
)

// H2Server is a raw HTTP/2 server over TLS that speaks just enough of the
// protocol to fault the first request it receives (see H2Fault) and answer
// every later one with 200 and an empty body. It counts the HEADERS frames
// it reads, one per request the client sends, retries included.
type H2Server struct {
	ln      net.Listener
	pool    *x509.CertPool
	headers atomic.Int32
	faulted atomic.Bool
	fault   H2Fault

	mu    sync.Mutex
	conns []net.Conn
	wg    sync.WaitGroup
}

// NewH2Server starts an H2Server on 127.0.0.1 with a fresh self-signed
// certificate. It is closed when the test ends. A fault that is not one of
// H2Faults fails tb and returns nil, since the server would never answer the
// request it should fault.
func NewH2Server(tb testing.TB, fault H2Fault) *H2Server {
	tb.Helper()
	if !slices.Contains(H2Faults(), fault) {
		require.Failf(tb, "unknown H2Fault", "%q", fault)
		return nil
	}
	cert, pool := selfSignedCert(tb)
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"h2"},
		MinVersion:   tls.VersionTLS12,
	})
	require.NoError(tb, err)
	s := &H2Server{ln: ln, pool: pool, fault: fault}
	s.wg.Go(s.accept)
	tb.Cleanup(s.close)
	return s
}

// URL returns the server's base URL, such as https://127.0.0.1:port.
func (s *H2Server) URL() string { return "https://" + s.ln.Addr().String() }

// Transport returns a new HTTP/2 transport that trusts the server.
func (s *H2Server) Transport() *http.Transport {
	return &http.Transport{
		TLSClientConfig:   &tls.Config{RootCAs: s.pool, MinVersion: tls.VersionTLS12},
		ForceAttemptHTTP2: true,
	}
}

// Headers returns the number of HEADERS frames read so far.
func (s *H2Server) Headers() int { return int(s.headers.Load()) }

func (s *H2Server) accept() {
	for {
		conn, err := s.ln.Accept()
		if err != nil {
			return
		}
		s.mu.Lock()
		s.conns = append(s.conns, conn)
		s.mu.Unlock()
		s.wg.Go(func() { s.serve(conn) })
	}
}

func (s *H2Server) close() {
	_ = s.ln.Close()
	s.mu.Lock()
	for _, c := range s.conns {
		_ = c.Close()
	}
	s.mu.Unlock()
	s.wg.Wait()
}

// serve speaks HTTP/2 on one connection until it fails or closes.
func (s *H2Server) serve(conn net.Conn) {
	defer func() { _ = conn.Close() }()
	preface := make([]byte, h2PrefaceLen)
	if _, err := io.ReadFull(conn, preface); err != nil {
		return
	}
	if writeH2Frame(conn, h2FrameSettings, 0, 0, nil) != nil {
		return
	}
	hdr := make([]byte, h2FrameHeaderLen)
	for {
		if _, err := io.ReadFull(conn, hdr); err != nil {
			return
		}
		length := int(hdr[0])<<16 | int(hdr[1])<<8 | int(hdr[2])
		typ, flags := hdr[3], hdr[4]
		stream := binary.BigEndian.Uint32(hdr[5:]) & 0x7fffffff
		payload := make([]byte, length)
		if _, err := io.ReadFull(conn, payload); err != nil {
			return
		}
		if s.answer(conn, typ, flags, stream, payload) != nil {
			return
		}
	}
}

// answer reacts to one frame.
func (s *H2Server) answer(conn net.Conn, typ, flags byte, stream uint32, payload []byte) error {
	switch typ {
	case h2FrameSettings:
		if flags&h2FlagAck == 0 {
			return writeH2Frame(conn, h2FrameSettings, h2FlagAck, 0, nil)
		}
	case h2FramePing:
		if flags&h2FlagAck == 0 {
			return writeH2Frame(conn, h2FramePing, h2FlagAck, 0, payload)
		}
	case h2FrameHeaders:
		s.headers.Add(1)
		if !s.faulted.CompareAndSwap(false, true) {
			return writeH2Frame(conn, h2FrameHeaders, h2FlagEndHeaders|h2FlagEndStream, stream, []byte{h2Status200})
		}
		switch s.fault {
		case H2RefusedStream:
			return writeH2Frame(conn, h2FrameRSTStream, 0, stream, binary.BigEndian.AppendUint32(nil, h2ErrRefusedStream))
		case H2ProtocolError:
			return writeH2Frame(conn, h2FrameRSTStream, 0, stream, binary.BigEndian.AppendUint32(nil, h2ErrProtocol))
		case H2GoAway:
			return writeH2Frame(conn, h2FrameGoAway, 0, 0, make([]byte, 8))
		}
	}
	return nil
}

// writeH2Frame writes one frame.
func writeH2Frame(w io.Writer, typ, flags byte, stream uint32, payload []byte) error {
	n := len(payload)
	frame := make([]byte, h2FrameHeaderLen, h2FrameHeaderLen+n)
	frame[0], frame[1], frame[2] = byte(n>>16), byte(n>>8), byte(n) //nolint:gosec // a frame length fits 24 bits
	frame[3], frame[4] = typ, flags
	binary.BigEndian.PutUint32(frame[5:], stream)
	_, err := w.Write(append(frame, payload...))
	return err
}

// selfSignedCert returns a fresh certificate for 127.0.0.1 and ::1, and a pool
// that trusts it.
func selfSignedCert(tb testing.TB) (tls.Certificate, *x509.CertPool) {
	tb.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(tb, err)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "go-bouncer test"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IPAddresses:           []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(tb, err)
	leaf, err := x509.ParseCertificate(der)
	require.NoError(tb, err)
	pool := x509.NewCertPool()
	pool.AddCert(leaf)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}, pool
}
