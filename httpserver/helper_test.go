package httpserver

import (
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSanitizePath_NormalPath(t *testing.T) {
	root := "/srv/files"
	abs, err := sanitizePath(root, "/subdir/file.txt")
	require.NoError(t, err)
	require.Equal(t, "/srv/files/subdir/file.txt", abs)
}

func TestSanitizePath_Root(t *testing.T) {
	root := "/srv/files"
	abs, err := sanitizePath(root, "/")
	require.NoError(t, err)
	require.Equal(t, "/srv/files", abs)
}

// sanitizePath prevents path traversal by prepending "/" and using filepath.Join,
// so traversal sequences like ../ and %2e%2e are resolved safely within root.

func TestSanitizePath_TraversalDotDot(t *testing.T) {
	root := "/srv/files"
	// "/../etc/passwd" resolves to /srv/files/etc/passwd — not an error, but safely within root.
	result, err := sanitizePath(root, "/../etc/passwd")
	require.NoError(t, err)
	require.Equal(t, "/srv/files/etc/passwd", result)
}

func TestSanitizePath_EncodedTraversal(t *testing.T) {
	root := "/srv/files"
	// "%2e%2e" decodes to ".." which resolves within root via the "/" prefix.
	result, err := sanitizePath(root, "/%2e%2e/etc/passwd")
	require.NoError(t, err)
	require.Equal(t, "/srv/files/etc/passwd", result)
}

func TestSanitizePath_MultiLevelTraversal(t *testing.T) {
	root := "/srv/files"
	// Multiple levels of traversal are still safely contained.
	result, err := sanitizePath(root, "/a/b/../../../../etc/passwd")
	require.NoError(t, err)
	require.Equal(t, "/srv/files/etc/passwd", result)
}

func TestSanitizePath_AllResultsWithinRoot(t *testing.T) {
	root := "/srv/files"
	inputs := []string{
		"/../etc/passwd",
		"/%2e%2e/etc/passwd",
		"../../etc/passwd",
		"/../../etc/passwd",
		"/valid/../../../etc/passwd",
	}
	for _, input := range inputs {
		result, err := sanitizePath(root, input)
		require.NoError(t, err, "path %q should not error", input)
		require.True(t, strings.HasPrefix(result, root), "path %q should stay within root, got %q", input, result)
	}
}

func TestSanitizePath_NestedPath(t *testing.T) {
	root := "/srv/files"
	abs, err := sanitizePath(root, "/a/b/c/file.txt")
	require.NoError(t, err)
	require.Equal(t, "/srv/files/a/b/c/file.txt", abs)
}

func TestGenerateToken_NotEmpty(t *testing.T) {
	token := GenerateToken()
	require.NotEmpty(t, token)
}

func TestGenerateToken_NoPadding(t *testing.T) {
	token := GenerateToken()
	require.NotContains(t, token, "=")
}

func TestGenerateToken_Uniqueness(t *testing.T) {
	tokens := make(map[string]bool)
	for range 100 {
		tok := GenerateToken()
		require.False(t, tokens[tok], "duplicate token generated")
		tokens[tok] = true
	}
}

func TestDenyForTokenAccess_WithToken(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/?token=abc123", nil)
	denied := denyForTokenAccess(w, r)
	require.True(t, denied)
	require.Equal(t, 403, w.Code)
}

func TestDenyForTokenAccess_WithoutToken(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/", nil)
	denied := denyForTokenAccess(w, r)
	require.False(t, denied)
	require.Equal(t, 200, w.Code)
}
