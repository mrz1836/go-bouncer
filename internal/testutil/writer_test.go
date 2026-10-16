package testutil_test

import (
	"errors"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/mrz1836/go-bouncer/internal/testutil"
)

func TestCountingWriter(t *testing.T) {
	t.Parallel()
	var w testutil.CountingWriter
	for _, p := range []string{"ab", "", "cde"} {
		n, err := w.Write([]byte(p))
		require.NoError(t, err)
		assert.Equal(t, len(p), n)
	}
	assert.Equal(t, "abcde", string(w.Bytes()))
	assert.Equal(t, 5, w.Len())
	assert.Equal(t, 3, w.Writes())
	got := w.Bytes()
	got[0] = 'X'
	assert.Equal(t, "abcde", string(w.Bytes()), "Bytes returns a copy")
}

func TestFailAfterWriter(t *testing.T) {
	t.Parallel()
	w := &testutil.FailAfterWriter{N: 4}
	n, err := w.Write([]byte("abc"))
	require.NoError(t, err)
	assert.Equal(t, 3, n)
	n, err = w.Write([]byte("def"))
	require.ErrorIs(t, err, testutil.ErrWriterFailed)
	assert.Equal(t, 1, n)
	n, err = w.Write([]byte("g"))
	require.ErrorIs(t, err, testutil.ErrWriterFailed)
	assert.Zero(t, n)
	assert.Equal(t, "abcd", string(w.Bytes()))
}

func TestShortWriter(t *testing.T) {
	t.Parallel()
	w := &testutil.ShortWriter{Max: 2}
	n, err := w.Write([]byte("abcd"))
	require.NoError(t, err)
	assert.Equal(t, 2, n)
	assert.Equal(t, "ab", string(w.Bytes()))
}

func TestInvalidCountWriter(t *testing.T) {
	t.Parallel()
	for _, count := range []int{-1, 9} {
		w := &testutil.InvalidCountWriter{N: count}
		n, err := w.Write([]byte("abc"))
		require.NoError(t, err)
		assert.Equal(t, count, n)
		assert.Equal(t, "abc", string(w.Bytes()))
	}
}

func TestBlockingWriter(t *testing.T) {
	t.Parallel()
	w := testutil.NewBlockingWriter()
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = w.Write([]byte("first"))
	}()
	<-w.Entered()
	select {
	case <-done:
		t.Fatal("the first Write returned before Release")
	default:
	}
	w.Release()
	w.Release()
	<-done
	n, err := w.Write([]byte("!"))
	require.NoError(t, err)
	assert.Equal(t, 1, n)
	assert.Equal(t, "first!", string(w.Bytes()))
}

func TestCloseFlushSpy(t *testing.T) {
	t.Parallel()
	calls := map[string]func(*testutil.CloseFlushSpy) error{
		"close": (*testutil.CloseFlushSpy).Close,
		"flush": (*testutil.CloseFlushSpy).Flush,
		"sync":  (*testutil.CloseFlushSpy).Sync,
	}
	for name, call := range calls {
		w := &testutil.CloseFlushSpy{}
		_, err := w.Write([]byte("x"))
		require.NoError(t, err)
		assert.False(t, w.Touched(), name)
		require.NoError(t, call(w))
		assert.True(t, w.Touched(), name)
	}
}

// Static errors the writer and script tests use.
var (
	errOther = errors.New("other")
	errMine  = errors.New("mine")
	errPlain = errors.New("plain")
	errBoom  = errors.New("boom")
)

func TestRequireErrorAs(t *testing.T) {
	t.Parallel()
	type myErr struct{ error }
	err := errors.Join(errOther, &myErr{errMine})
	got := testutil.RequireErrorAs[*myErr](t, err)
	assert.Equal(t, "mine", got.Error())

	rec := &recorder{}
	assert.Nil(t, testutil.RequireErrorAs[*myErr](rec, errPlain))
	assert.True(t, rec.failed)
}

func TestScriptAnswersInOrder(t *testing.T) {
	t.Parallel()
	s := testutil.NewScript(
		testutil.Step{Body: `{"a":1}`},
		testutil.Step{Status: http.StatusTeapot, Header: http.Header{"Content-Type": {"text/csv"}}, Body: "x,y"},
		testutil.Step{Err: errBoom},
		testutil.Step{Respond: func(r *http.Request) (*http.Response, error) {
			return testutil.Response(r, http.StatusAccepted, testutil.NewBody(""), 0), nil
		}},
	)
	paths := []string{"/a", "/b", "/c", "/d", "/e"}
	var statuses []int
	errs := make([]error, 0, len(paths))
	for _, p := range paths {
		req := newRequest(t, "body-"+p)
		req.URL.Path = p
		resp, err := s.RoundTrip(req)
		errs = append(errs, err)
		if err == nil {
			statuses = append(statuses, resp.StatusCode)
			body := readAll(t, resp)
			if resp.StatusCode == http.StatusTeapot {
				assert.Equal(t, "x,y", body)
				assert.Equal(t, "text/csv", resp.Header.Get("Content-Type"))
			}
		}
	}
	assert.Equal(t, []int{http.StatusOK, http.StatusTeapot, http.StatusAccepted}, statuses)
	require.ErrorIs(t, errs[2], errBoom)
	require.ErrorIs(t, errs[4], testutil.ErrScriptExhausted)
	assert.Equal(t, 5, s.Calls())
	reqs := s.Requests()
	require.Len(t, reqs, 5)
	for i, r := range reqs {
		assert.Equal(t, paths[i], r.Path, "every request is recorded in order, past the last step too")
	}
	assert.Equal(t, "body-/a", string(reqs[0].Body))
}
