package testutil_test

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/mrz1836/go-bouncer/internal/testutil"
)

func TestTimeoutError(t *testing.T) {
	t.Parallel()
	var err net.Error = testutil.TimeoutError{Msg: "planted"}
	assert.Equal(t, "planted", err.Error())
	assert.True(t, err.Timeout())
	assert.True(t, err.Temporary()) //nolint:staticcheck // Temporary is part of net.Error
	assert.Equal(t, "testutil: network timeout", testutil.TimeoutError{}.Error())
}
