package testutil_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/mrz1836/go-bouncer/internal/testutil"
)

// TestFixture is not parallel: t.Chdir changes the process's working
// directory.
func TestFixture(t *testing.T) {
	t.Chdir(t.TempDir())
	require.NoError(t, os.MkdirAll(filepath.Join("testdata", "dir"), 0o750))
	require.NoError(t, os.WriteFile(filepath.Join("testdata", "dir", "f.json"), []byte(`{}`), 0o600))

	assert.Equal(t, []byte(`{}`), testutil.Fixture(t, "dir/f.json"), "a slash-separated path under testdata")

	rec := &recorder{}
	assert.Nil(t, testutil.Fixture(rec, "dir/missing.json"))
	assert.True(t, rec.failed, "a missing fixture fails the test")
}
