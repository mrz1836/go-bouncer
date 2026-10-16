package testutil

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestValueShapesHoldTheValue proves that every shape AssertShapesNeverPrint
// formats really holds the value, so that a clean result means something.
func TestValueShapesHoldTheValue(t *testing.T) {
	t.Parallel()
	type visible struct{ Name string }
	shapes := valueShapes(&visible{Name: "lk-marker"})
	require.Len(t, shapes, 10)
	for _, s := range shapes {
		assert.Contains(t, ReflectStrings(s.Value), "lk-marker", s.Name)
	}
}
