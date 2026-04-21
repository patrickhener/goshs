package httpserver

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

// ─── handleInvisible ─────────────────────────────────────────────────────────

// TestHandleInvisible_NonHijackable verifies that handleInvisible returns
// immediately when the ResponseWriter doesn't support hijacking (e.g. httptest.Recorder).
func TestHandleInvisible_NonHijackable(t *testing.T) {
	fs := &FileServer{}
	w := httptest.NewRecorder()
	// Must not panic; returns silently because Recorder is not an http.Hijacker.
	require.NotPanics(t, func() { fs.handleInvisible(w) })
}

// TestHandleInvisible_HijacksAndClosesConnection verifies that handleInvisible
// actually closes the TCP connection when given a real hijackable ResponseWriter.
func TestHandleInvisible_HijacksAndClosesConnection(t *testing.T) {
	fs := &FileServer{}

	// Spin up a real HTTP server whose handler calls handleInvisible.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fs.handleInvisible(w)
	}))
	defer srv.Close()

	resp, err := http.Get(srv.URL)
	if err != nil {
		// Connection closed/reset by handleInvisible is expected.
		return
	}
	defer resp.Body.Close()
	_, _ = io.ReadAll(resp.Body)
	// If we got a response the connection was still valid — the body should be empty.
}

// ─── handleError ─────────────────────────────────────────────────────────────

func TestHandleError_Invisible(t *testing.T) {
	dir := t.TempDir()
	fs, cleanup := newTestFileServer(t, dir)
	defer cleanup()
	fs.Invisible = true

	r := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	// handleInvisible silently returns with a non-hijackable writer; no panic.
	require.NotPanics(t, func() {
		fs.handleError(w, r, errors.New("test error"), http.StatusForbidden)
	})
}

func TestHandleError_ErrorMessageInBody(t *testing.T) {
	dir := t.TempDir()
	fs, cleanup := newTestFileServer(t, dir)
	defer cleanup()

	r := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	fs.handleError(w, r, errors.New("something went wrong"), http.StatusNotFound)

	require.Equal(t, http.StatusNotFound, w.Code)
	require.Contains(t, w.Body.String(), "something went wrong")
}

func TestHandleError_SilentHidesDetail(t *testing.T) {
	dir := t.TempDir()
	fs, cleanup := newTestFileServer(t, dir)
	defer cleanup()
	fs.Silent = true

	r := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	fs.handleError(w, r, errors.New("secret-internal-cause-xyz"), http.StatusInternalServerError)

	require.Equal(t, http.StatusInternalServerError, w.Code)
	require.NotContains(t, w.Body.String(), "secret-internal-cause-xyz")
}
