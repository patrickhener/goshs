package cli

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRunCMD(t *testing.T) {
	result, err := RunCMD("ls -la")
	if err != nil {
		t.Errorf("Command did not run succesfully: %+v", err)
	}

	require.Contains(t, result, "cli_unix.go")
}
