package testutil

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

// APIKey is the synthetic API key every test uses. It doubles as a leak
// marker: no error, formatted value or reflection walk may ever contain it.
// It is not a real secret.
const APIKey = "bk-SYNTHETIC-KEY-7f3a2c91" //nolint:gosec // gitleaks:allow (a synthetic test marker, not a credential)

// Fixture returns the contents of the file name, a slash-separated path under
// testdata, failing tb when it cannot be read.
func Fixture(tb testing.TB, name string) []byte {
	tb.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", filepath.FromSlash(name)))
	require.NoError(tb, err)
	return data
}
