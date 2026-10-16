package testutil

import (
	"bytes"
	"errors"
	"sync"
	"sync/atomic"
)

// ErrWriterFailed is the error the failing writer fakes return.
var ErrWriterFailed = errors.New("testutil: writer failed")

// CountingWriter keeps every byte written to it and counts the Write calls.
// It is safe for concurrent use.
type CountingWriter struct {
	mu     sync.Mutex
	buf    bytes.Buffer
	writes int
}

// Write appends p.
func (w *CountingWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.writes++
	return w.buf.Write(p)
}

// Bytes returns a copy of everything written.
func (w *CountingWriter) Bytes() []byte {
	w.mu.Lock()
	defer w.mu.Unlock()
	return bytes.Clone(w.buf.Bytes())
}

// Len returns the number of bytes written.
func (w *CountingWriter) Len() int {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.buf.Len()
}

// Writes returns the number of Write calls.
func (w *CountingWriter) Writes() int {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.writes
}

// FailAfterWriter accepts the first N bytes, then fails: the Write that
// crosses N writes what fits and returns ErrWriterFailed, and every later
// Write fails without writing.
type FailAfterWriter struct {
	CountingWriter

	N int
}

// Write writes up to the remaining budget.
func (w *FailAfterWriter) Write(p []byte) (int, error) {
	room := max(w.N-w.Len(), 0)
	if len(p) <= room {
		return w.CountingWriter.Write(p)
	}
	n, _ := w.CountingWriter.Write(p[:room])
	return n, ErrWriterFailed
}

// ShortWriter breaks the io.Writer contract: it writes at most Max bytes of
// each call and returns that count without an error.
type ShortWriter struct {
	CountingWriter

	Max int
}

// Write writes at most Max bytes and reports no error.
func (w *ShortWriter) Write(p []byte) (int, error) {
	return w.CountingWriter.Write(p[:min(len(p), w.Max)])
}

// InvalidCountWriter breaks the io.Writer contract: it keeps every byte but
// returns N as the count, which may be negative or larger than len(p).
type InvalidCountWriter struct {
	CountingWriter

	N int
}

// Write keeps p and reports N.
func (w *InvalidCountWriter) Write(p []byte) (int, error) {
	_, _ = w.CountingWriter.Write(p)
	return w.N, nil
}

// BlockingWriter blocks its first Write until Release is called. Entered is
// closed when that Write begins. Later Writes do not block.
type BlockingWriter struct {
	CountingWriter

	once    sync.Once
	entered chan struct{}
	release chan struct{}
	blocked atomic.Bool
}

// NewBlockingWriter returns a BlockingWriter.
func NewBlockingWriter() *BlockingWriter {
	return &BlockingWriter{entered: make(chan struct{}), release: make(chan struct{})}
}

// Write blocks on the first call until Release, then writes p.
func (w *BlockingWriter) Write(p []byte) (int, error) {
	if w.blocked.CompareAndSwap(false, true) {
		close(w.entered)
		<-w.release
	}
	return w.CountingWriter.Write(p)
}

// Entered is closed when the first Write begins.
func (w *BlockingWriter) Entered() <-chan struct{} { return w.entered }

// Release unblocks the first Write. It is safe to call more than once.
func (w *BlockingWriter) Release() { w.once.Do(func() { close(w.release) }) }

// CloseFlushSpy is a writer that records whether anything called its Close,
// Flush or Sync methods, which a streaming function must never do to a
// caller's writer.
type CloseFlushSpy struct {
	CountingWriter

	closes  atomic.Int32
	flushes atomic.Int32
	syncs   atomic.Int32
}

// Close records the call.
func (w *CloseFlushSpy) Close() error {
	w.closes.Add(1)
	return nil
}

// Flush records the call.
func (w *CloseFlushSpy) Flush() error {
	w.flushes.Add(1)
	return nil
}

// Sync records the call.
func (w *CloseFlushSpy) Sync() error {
	w.syncs.Add(1)
	return nil
}

// Touched reports whether Close, Flush or Sync was ever called.
func (w *CloseFlushSpy) Touched() bool {
	return w.closes.Load()+w.flushes.Load()+w.syncs.Load() > 0
}
