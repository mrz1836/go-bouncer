package bouncer_test

import (
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fixtureAddress matches anything that looks like an email address.
var fixtureAddress = regexp.MustCompile(`[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}`)

// fixtureDomainAllowed reports whether an address's domain is one the tests
// may use: the reserved example domains, or the reserved .invalid TLD.
func fixtureDomainAllowed(address string) bool {
	_, domain, ok := strings.Cut(address, "@")
	if !ok {
		return false
	}
	domain = strings.ToLower(strings.TrimRight(domain, "."))
	switch domain {
	case "example.com", "example.net", "example.org":
		return true
	}
	return strings.HasSuffix(domain, ".invalid")
}

func TestFixtureDomainAllowed(t *testing.T) {
	t.Parallel()
	// The refused domains are split from the local part, so that this file's
	// own source never holds an address the scan below would refuse.
	for address, ok := range map[string]bool{
		"avery.example@example.com":         true,
		"blake.example@EXAMPLE.NET":         true,
		"casey.example@example.org":         true,
		"drew@unknown.invalid":              true,
		"drew@" + "mail.example.com":        false,
		"drew@" + "example.co":              false,
		"drew@" + "mailbox.test":            false,
		"drew@" + "notexample.com":          false,
		"drew@" + "example.com.attacker.io": false,
		"no-at-sign.example.com":            false,
	} {
		assert.Equal(t, ok, fixtureDomainAllowed(address), address)
	}
}

func TestSyntheticFixtures(t *testing.T) {
	t.Parallel()
	const dir = "testdata/synthetic"
	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	var jsonFiles int
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".") {
			continue // editor and tool state, never part of the deliverable
		}
		require.False(t, e.IsDir(), "no subdirectories: %s", e.Name())
		data, err := os.ReadFile(filepath.Join(dir, e.Name()))
		require.NoError(t, err)
		readme := e.Name() == "README.md"
		if !readme {
			jsonFiles++
		}
		t.Run(e.Name(), func(t *testing.T) {
			t.Parallel()
			if readme {
				assert.Contains(t, string(data), "written by hand", "the README labels the fixtures as SDK-authored")
				return
			}
			require.Equal(t, ".json", filepath.Ext(e.Name()), "fixtures are JSON")
			assert.True(t, json.Valid(data), "valid JSON")
			for _, address := range fixtureAddress.FindAllString(string(data), -1) {
				assert.True(t, fixtureDomainAllowed(address), "address at a non-synthetic domain: %s", address)
			}
		})
	}
	assert.Positive(t, jsonFiles)
}

func TestSourcesUseSyntheticAddressesOnly(t *testing.T) {
	t.Parallel()
	var scanned int
	err := filepath.WalkDir(".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if path != "." && strings.HasPrefix(d.Name(), ".") {
				return filepath.SkipDir
			}
			return nil
		}
		inTestdata := strings.HasPrefix(filepath.ToSlash(path), "testdata/")
		if filepath.Ext(path) != ".go" && !inTestdata {
			return nil
		}
		data, err := os.ReadFile(path) //nolint:gosec // the path comes from walking the repository itself
		if err != nil {
			return err
		}
		scanned++
		for _, address := range fixtureAddress.FindAllString(string(data), -1) {
			assert.True(t, fixtureDomainAllowed(address), "%s: address at a non-synthetic domain: %s", path, address)
		}
		return nil
	})
	require.NoError(t, err)
	assert.Positive(t, scanned)
}
