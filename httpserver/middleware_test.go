package httpserver

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"runtime"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"
)

// nextHandler is a trivial next handler that records whether it was called.
func nextHandler(called *bool) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		*called = true
		w.WriteHeader(http.StatusOK)
	})
}

func basicAuthHeader(user, pass string) string {
	creds := base64.StdEncoding.EncodeToString([]byte(user + ":" + pass))
	return "Basic " + creds
}

func newFS(user, pass string) *FileServer {
	// Clear the global auth cache between tests to avoid cross-test interference.
	authCacheMutex.Lock()
	authCache = make(map[string]bool)
	authCacheMutex.Unlock()
	return &FileServer{
		User:        user,
		Pass:        pass,
		SharedLinks: map[string]SharedLink{},
	}
}

func TestBasicAuthMiddleware_NoAuthHeader(t *testing.T) {
	fs := newFS("user", "pass")
	called := false
	handler := fs.BasicAuthMiddleware(nextHandler(&called))

	r := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)

	require.False(t, called)
	require.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestBasicAuthMiddleware_WrongCredentials(t *testing.T) {
	fs := newFS("user", "pass")
	called := false
	handler := fs.BasicAuthMiddleware(nextHandler(&called))

	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("Authorization", basicAuthHeader("user", "wrongpass"))
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)

	require.False(t, called)
	require.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestBasicAuthMiddleware_CorrectPlainText(t *testing.T) {
	fs := newFS("user", "pass")
	called := false
	handler := fs.BasicAuthMiddleware(nextHandler(&called))

	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("Authorization", basicAuthHeader("user", "pass"))
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)

	require.True(t, called)
	require.Equal(t, http.StatusOK, w.Code)
}

func TestBasicAuthMiddleware_WrongUser(t *testing.T) {
	fs := newFS("user", "pass")
	called := false
	handler := fs.BasicAuthMiddleware(nextHandler(&called))

	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("Authorization", basicAuthHeader("wronguser", "pass"))
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)

	require.False(t, called)
	require.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestBasicAuthMiddleware_CorrectBcrypt(t *testing.T) {
	hash, err := bcrypt.GenerateFromPassword([]byte("secret"), bcrypt.MinCost)
	require.NoError(t, err)

	fs := newFS("admin", string(hash))
	called := false
	handler := fs.BasicAuthMiddleware(nextHandler(&called))

	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("Authorization", basicAuthHeader("admin", "secret"))
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)

	require.True(t, called)
	require.Equal(t, http.StatusOK, w.Code)
}

func TestBasicAuthMiddleware_WrongBcryptPassword(t *testing.T) {
	hash, err := bcrypt.GenerateFromPassword([]byte("secret"), bcrypt.MinCost)
	require.NoError(t, err)

	fs := newFS("admin", string(hash))
	called := false
	handler := fs.BasicAuthMiddleware(nextHandler(&called))

	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("Authorization", basicAuthHeader("admin", "wrongsecret"))
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)

	require.False(t, called)
	require.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestBasicAuthMiddleware_ValidToken(t *testing.T) {
	fs := newFS("user", "pass")
	fs.SharedLinks["mytoken"] = SharedLink{}
	called := false
	handler := fs.BasicAuthMiddleware(nextHandler(&called))

	r := httptest.NewRequest(http.MethodGet, "/?token=mytoken", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)

	require.True(t, called)
	require.Equal(t, http.StatusOK, w.Code)
}

func TestBasicAuthMiddleware_InvalidToken(t *testing.T) {
	fs := newFS("user", "pass")
	called := false
	handler := fs.BasicAuthMiddleware(nextHandler(&called))

	r := httptest.NewRequest(http.MethodGet, "/?token=badtoken", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)

	// Token not in SharedLinks — falls through to auth check, no credentials → 401
	require.False(t, called)
	require.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestServerHeaderMiddleware_SetsHeader(t *testing.T) {
	fs := &FileServer{Version: "v2.0.0-test", Invisible: false}
	called := false
	handler := fs.ServerHeaderMiddleware(nextHandler(&called))

	r := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)

	require.True(t, called)
	expected := fmt.Sprintf("goshs/v2.0.0-test (%s; %s)", runtime.GOOS, runtime.Version())
	require.Equal(t, expected, w.Header().Get("Server"))
}

func TestServerHeaderMiddleware_Invisible(t *testing.T) {
	fs := &FileServer{Version: "v2.0.0-test", Invisible: true}
	called := false
	handler := fs.ServerHeaderMiddleware(nextHandler(&called))

	r := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)

	require.True(t, called)
	require.Empty(t, w.Header().Get("Server"), "invisible mode should not set Server header")
}
