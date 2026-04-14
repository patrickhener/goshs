package sanity

import (
	"os"
	"path/filepath"
	"testing"

	"goshs.de/goshs/options"
	"github.com/stretchr/testify/require"
)

func TestSanitize_AbsolutePathUnchanged(t *testing.T) {
	opts := &options.Options{Webroot: "/absolute/path"}
	result, err := Sanitize(opts)
	require.NoError(t, err)
	require.Equal(t, "/absolute/path", result.Webroot)
}

func TestSanitize_RelativePathBecomesAbsolute(t *testing.T) {
	wd, err := os.Getwd()
	require.NoError(t, err)

	opts := &options.Options{Webroot: "relative/path"}
	result, err := Sanitize(opts)
	require.NoError(t, err)
	require.True(t, filepath.IsAbs(result.Webroot))
	require.Equal(t, filepath.Join(wd, "relative/path"), result.Webroot)
}

func TestSanitize_TrimsTrailingSlash(t *testing.T) {
	opts := &options.Options{Webroot: "/some/path/"}
	result, err := Sanitize(opts)
	require.NoError(t, err)
	require.Equal(t, "/some/path", result.Webroot)
}

func TestSanitize_TrimsTrailingBackslash(t *testing.T) {
	opts := &options.Options{Webroot: `/some/path\`}
	result, err := Sanitize(opts)
	require.NoError(t, err)
	require.Equal(t, "/some/path", result.Webroot)
}

func TestSanitize_DotBecomesAbsolute(t *testing.T) {
	wd, err := os.Getwd()
	require.NoError(t, err)

	opts := &options.Options{Webroot: "."}
	result, err := Sanitize(opts)
	require.NoError(t, err)
	require.Equal(t, wd, result.Webroot)
}
