package testutil_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/mrz1836/go-bouncer/internal/testutil"
)

// TestJSONShapeNeverPrintsValues proves the live probe's shape printer keeps
// structure and drops every value, including keys that could carry data.
func TestJSONShapeNeverPrintsValues(t *testing.T) {
	t.Parallel()
	const body = `{"person":{"name":{"firstName":"MARKER-NAME"},"phones":[{"number":"MARKER-PHONE","isConnected":true},null],"age":"41"},` +
		`"identityScore":87,"isError":false,"message":"","MARKER KEY WITH SPACES":"MARKER-VALUE","error":{"warnings":["MARKER-WARNING"],"inputErrors":[]}}`
	shape, ok := testutil.JSONShape([]byte(body))
	assert.True(t, ok)
	for _, marker := range []string{"MARKER", "87", "41", "true", "false"} {
		assert.NotContains(t, shape, marker)
	}
	for _, want := range []string{"person", "firstName", "phones", "array(len=2)", "isError: bool", "identityScore: number", "message: string(empty)", "<key>", "warnings: array(len=1)[string]"} {
		assert.Contains(t, shape, want)
	}

	_, ok = testutil.JSONShape([]byte(`{"a":`))
	assert.False(t, ok)
}
