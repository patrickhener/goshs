package httpserver

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/patrickhener/goshs/v2/clipboard"
	"github.com/patrickhener/goshs/v2/webhook"
	"github.com/patrickhener/goshs/v2/ws"
	"github.com/stretchr/testify/require"
)

// newTestFileServer returns a minimal FileServer wired to a running Hub so that
// emitCollabEvent does not block. Call cleanup() in a defer to drain the hub.
func newTestFileServer(t *testing.T, webroot string) (*FileServer, func()) {
	t.Helper()
	cb := clipboard.New()
	hub := ws.NewHub(cb, false)
	go hub.Run()

	wh := webhook.Register(false, "", "discord", []string{})

	fs := &FileServer{
		Webroot:     webroot,
		UploadFolder: webroot,
		CSRFToken:   "test-csrf",
		Hub:         hub,
		Webhook:     *wh,
		SharedLinks: map[string]SharedLink{},
		Version:     "test",
	}
	return fs, func() {} // hub goroutine is cleaned up by process exit in tests
}

// ─── handleMkdir ─────────────────────────────────────────────────────────────

func TestHandleMkdir_Success(t *testing.T) {
	root := t.TempDir()
	fs, cleanup := newTestFileServer(t, root)
	defer cleanup()

	r := httptest.NewRequest(http.MethodPost, "/newdir?mkdir", nil)
	r.Header.Set("X-CSRF-Token", "test-csrf")
	w := httptest.NewRecorder()

	fs.handleMkdir(w, r)

	require.Equal(t, http.StatusCreated, w.Code)
	require.DirExists(t, filepath.Join(root, "newdir"))
}

func TestHandleMkdir_ReadOnly(t *testing.T) {
	root := t.TempDir()
	fs, cleanup := newTestFileServer(t, root)
	defer cleanup()
	fs.ReadOnly = true

	r := httptest.NewRequest(http.MethodPost, "/blocked?mkdir", nil)
	r.Header.Set("X-CSRF-Token", "test-csrf")
	w := httptest.NewRecorder()

	fs.handleMkdir(w, r)

	require.Equal(t, http.StatusForbidden, w.Code)
}

func TestHandleMkdir_UploadOnly(t *testing.T) {
	root := t.TempDir()
	fs, cleanup := newTestFileServer(t, root)
	defer cleanup()
	fs.UploadOnly = true

	r := httptest.NewRequest(http.MethodPost, "/blocked?mkdir", nil)
	r.Header.Set("X-CSRF-Token", "test-csrf")
	w := httptest.NewRecorder()

	fs.handleMkdir(w, r)

	require.Equal(t, http.StatusForbidden, w.Code)
}

// ─── CreateShareHandler ───────────────────────────────────────────────────────

func TestCreateShareHandler_NoAuth_Forbidden(t *testing.T) {
	root := t.TempDir()
	fs, cleanup := newTestFileServer(t, root)
	defer cleanup()
	// Pass and CACert both empty → sharing disabled

	r := httptest.NewRequest(http.MethodGet, "/?share", nil)
	r.Header.Set("X-CSRF-Token", "test-csrf")
	w := httptest.NewRecorder()

	fs.CreateShareHandler(w, r)

	require.Equal(t, http.StatusForbidden, w.Code)
}

func TestCreateShareHandler_WithAuth_CreatesToken(t *testing.T) {
	root := t.TempDir()
	// Write a real file to share
	testFile := filepath.Join(root, "hello.txt")
	require.NoError(t, os.WriteFile(testFile, []byte("hello"), 0644))

	fs, cleanup := newTestFileServer(t, root)
	defer cleanup()
	fs.Pass = "somepassword"
	fs.IP = "127.0.0.1"
	fs.Port = 8000

	r := httptest.NewRequest(http.MethodGet, "/hello.txt?share", nil)
	r.Header.Set("X-CSRF-Token", "test-csrf")
	w := httptest.NewRecorder()

	fs.CreateShareHandler(w, r)

	require.Equal(t, http.StatusOK, w.Code)
	var resp map[string][]string
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	require.NotEmpty(t, resp["urls"])

	// Token should now be registered in SharedLinks
	require.Len(t, fs.SharedLinks, 1)
}

func TestCreateShareHandler_CustomExpiryAndLimit(t *testing.T) {
	root := t.TempDir()
	testFile := filepath.Join(root, "data.txt")
	require.NoError(t, os.WriteFile(testFile, []byte("data"), 0644))

	fs, cleanup := newTestFileServer(t, root)
	defer cleanup()
	fs.Pass = "secret"
	fs.IP = "127.0.0.1"
	fs.Port = 8000

	r := httptest.NewRequest(http.MethodGet, "/data.txt?share&expires=120&limit=3", nil)
	r.Header.Set("X-CSRF-Token", "test-csrf")
	w := httptest.NewRecorder()

	fs.CreateShareHandler(w, r)

	require.Equal(t, http.StatusOK, w.Code)
	require.Len(t, fs.SharedLinks, 1)
	for _, sl := range fs.SharedLinks {
		require.Equal(t, 3, sl.DownloadLimit)
		require.True(t, sl.Expires.After(time.Now()))
	}
}

// ─── ShareHandler ─────────────────────────────────────────────────────────────

func TestShareHandler_InvalidToken_NotFound(t *testing.T) {
	root := t.TempDir()
	fs, cleanup := newTestFileServer(t, root)
	defer cleanup()

	r := httptest.NewRequest(http.MethodGet, "/?token=doesnotexist", nil)
	w := httptest.NewRecorder()

	fs.ShareHandler(w, r)

	require.Equal(t, http.StatusNotFound, w.Code)
}

func TestShareHandler_ExpiredToken_NotFound(t *testing.T) {
	root := t.TempDir()
	testFile := filepath.Join(root, "old.txt")
	require.NoError(t, os.WriteFile(testFile, []byte("old content"), 0644))

	fs, cleanup := newTestFileServer(t, root)
	defer cleanup()
	fs.SharedLinks["expiredtoken"] = SharedLink{
		FilePath:      "/old.txt",
		IsDir:         false,
		Expires:       time.Now().Add(-1 * time.Hour), // already expired
		DownloadLimit: 1,
	}

	r := httptest.NewRequest(http.MethodGet, "/?token=expiredtoken", nil)
	w := httptest.NewRecorder()

	fs.ShareHandler(w, r)

	require.Equal(t, http.StatusNotFound, w.Code)
}

func TestShareHandler_ValidToken_ServesFile(t *testing.T) {
	root := t.TempDir()
	testFile := filepath.Join(root, "secret.txt")
	require.NoError(t, os.WriteFile(testFile, []byte("top secret"), 0644))

	fs, cleanup := newTestFileServer(t, root)
	defer cleanup()
	fs.SharedLinks["validtoken"] = SharedLink{
		FilePath:      "/secret.txt",
		IsDir:         false,
		Expires:       time.Now().Add(1 * time.Hour),
		DownloadLimit: 5,
	}

	r := httptest.NewRequest(http.MethodGet, "/?token=validtoken", nil)
	w := httptest.NewRecorder()

	fs.ShareHandler(w, r)

	require.Equal(t, http.StatusOK, w.Code)
	require.Equal(t, "top secret", w.Body.String())
}

func TestShareHandler_DownloadLimitExhausted(t *testing.T) {
	root := t.TempDir()
	testFile := filepath.Join(root, "limited.txt")
	require.NoError(t, os.WriteFile(testFile, []byte("data"), 0644))

	fs, cleanup := newTestFileServer(t, root)
	defer cleanup()
	// Limit=0 means already exhausted (not -1 which is unlimited)
	fs.SharedLinks["limitedtoken"] = SharedLink{
		FilePath:      "/limited.txt",
		IsDir:         false,
		Expires:       time.Now().Add(1 * time.Hour),
		DownloadLimit: 0,
		Downloaded:    0,
	}

	r := httptest.NewRequest(http.MethodGet, "/?token=limitedtoken", nil)
	w := httptest.NewRecorder()

	fs.ShareHandler(w, r)

	require.Equal(t, http.StatusNotFound, w.Code)
}

func TestShareHandler_UnlimitedDownloads(t *testing.T) {
	root := t.TempDir()
	testFile := filepath.Join(root, "unlimited.txt")
	require.NoError(t, os.WriteFile(testFile, []byte("unlimited content"), 0644))

	fs, cleanup := newTestFileServer(t, root)
	defer cleanup()
	fs.SharedLinks["unlimitedtoken"] = SharedLink{
		FilePath:      "/unlimited.txt",
		IsDir:         false,
		Expires:       time.Now().Add(1 * time.Hour),
		DownloadLimit: -1, // unlimited
	}

	r := httptest.NewRequest(http.MethodGet, "/?token=unlimitedtoken", nil)
	w := httptest.NewRecorder()

	fs.ShareHandler(w, r)

	require.Equal(t, http.StatusOK, w.Code)
	require.Equal(t, "unlimited content", w.Body.String())
}

// ─── DeleteShareHandler ───────────────────────────────────────────────────────

func TestDeleteShareHandler_RemovesToken(t *testing.T) {
	root := t.TempDir()
	fs, cleanup := newTestFileServer(t, root)
	defer cleanup()
	fs.SharedLinks["mytoken"] = SharedLink{
		Expires: time.Now().Add(time.Hour),
	}

	r := httptest.NewRequest(http.MethodDelete, "/?token=mytoken", nil)
	w := httptest.NewRecorder()

	fs.DeleteShareHandler(w, r)

	require.Equal(t, http.StatusNoContent, w.Code)
	_, exists := fs.SharedLinks["mytoken"]
	require.False(t, exists)
}

func TestDeleteShareHandler_NonexistentToken_NoError(t *testing.T) {
	root := t.TempDir()
	fs, cleanup := newTestFileServer(t, root)
	defer cleanup()

	r := httptest.NewRequest(http.MethodDelete, "/?token=ghost", nil)
	w := httptest.NewRecorder()

	fs.DeleteShareHandler(w, r)

	require.Equal(t, http.StatusNoContent, w.Code)
}

// ─── handleSMTPAttachment ─────────────────────────────────────────────────────

func TestHandleSMTPAttachment_NotFound(t *testing.T) {
	root := t.TempDir()
	fs, cleanup := newTestFileServer(t, root)
	defer cleanup()

	r := httptest.NewRequest(http.MethodGet, "/?smtp&id=nonexistent", nil)
	w := httptest.NewRecorder()

	fs.handleSMTPAttachment(w, r)

	require.Equal(t, http.StatusNotFound, w.Code)
}

func TestHandleSMTPAttachment_NoID(t *testing.T) {
	root := t.TempDir()
	fs, cleanup := newTestFileServer(t, root)
	defer cleanup()

	r := httptest.NewRequest(http.MethodGet, "/?smtp", nil)
	w := httptest.NewRecorder()

	fs.handleSMTPAttachment(w, r)

	require.Equal(t, http.StatusNotFound, w.Code)
}
