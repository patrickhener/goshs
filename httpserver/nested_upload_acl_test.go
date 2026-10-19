package httpserver

import (
	"bytes"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/textproto"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// Regression tests for GHSA-625w-3rc8-3c3h: a folder (nested) multipart upload
// to an unprotected directory must not write into a descendant directory that
// is protected by its own .goshs auth.

func nestedUploadRequest(t *testing.T, url string, files map[string]string) *http.Request {
	t.Helper()
	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	for name, content := range files {
		h := make(textproto.MIMEHeader)
		h.Set("Content-Disposition", `form-data; name="files"; filename="`+name+`"`)
		part, err := mw.CreatePart(h)
		require.NoError(t, err)
		_, err = part.Write([]byte(content))
		require.NoError(t, err)
	}
	require.NoError(t, mw.Close())

	r := httptest.NewRequest(http.MethodPost, url, &body)
	r.Header.Set("Content-Type", mw.FormDataContentType())
	r.Header.Set("X-CSRF-Token", "test-csrf")
	return r
}

func TestNestedUploadACL_PutIntoProtectedDirDenied(t *testing.T) {
	root := aclTree(t)
	fs, _ := newTestFileServer(t, root)

	r := httptest.NewRequest(http.MethodPut, "/protected/pwn.txt", strings.NewReader("PWNED"))
	r.Header.Set("X-CSRF-Token", "test-csrf")
	w := httptest.NewRecorder()
	fs.put(w, r)

	require.Equal(t, http.StatusUnauthorized, w.Code)
	_, err := os.Stat(filepath.Join(root, "protected", "pwn.txt"))
	require.True(t, os.IsNotExist(err))
}

func TestNestedUploadACL_FolderUploadCrossesSubdirACL(t *testing.T) {
	root := aclTree(t)
	fs, _ := newTestFileServer(t, root)

	w := httptest.NewRecorder()
	fs.upload(w, nestedUploadRequest(t, "/upload", map[string]string{"protected/pwn.txt": "PWNED"}))

	_, err := os.Stat(filepath.Join(root, "protected", "pwn.txt"))
	require.True(t, os.IsNotExist(err),
		"unauthenticated nested upload wrote into ACL-protected dir (status %d)", w.Code)
}

// A not-yet-existing directory below the protected one inherits its ACL.
func TestNestedUploadACL_NewSubdirInheritsProtection(t *testing.T) {
	root := aclTree(t)
	fs, _ := newTestFileServer(t, root)

	w := httptest.NewRecorder()
	fs.upload(w, nestedUploadRequest(t, "/upload", map[string]string{"protected/new/deep/pwn.txt": "PWNED"}))

	_, err := os.Stat(filepath.Join(root, "protected", "new"))
	require.True(t, os.IsNotExist(err), "nested upload created a directory inside the protected tree")
}

func TestNestedUploadACL_OverwriteDenied(t *testing.T) {
	root := aclTree(t)
	fs, _ := newTestFileServer(t, root)

	w := httptest.NewRecorder()
	fs.upload(w, nestedUploadRequest(t, "/upload", map[string]string{"protected/secret.txt": "PWNED"}))

	got, err := os.ReadFile(filepath.Join(root, "protected", "secret.txt"))
	require.NoError(t, err)
	require.Equal(t, "secret", string(got))
}

// With the protected directory's credentials the nested upload goes through,
// and unprotected parts of the same request are unaffected.
func TestNestedUploadACL_WithCredentialsAllowed(t *testing.T) {
	root := aclTree(t)
	fs, _ := newTestFileServer(t, root)

	r := nestedUploadRequest(t, "/upload", map[string]string{
		"protected/ok.txt": "ok",
		"public/ok.txt":    "ok",
	})
	r.SetBasicAuth("user", "pass")
	w := httptest.NewRecorder()
	fs.upload(w, r)

	require.Equal(t, http.StatusSeeOther, w.Code)
	require.FileExists(t, filepath.Join(root, "protected", "ok.txt"))
	require.FileExists(t, filepath.Join(root, "public", "ok.txt"))
}

// Mixed request without credentials: the unprotected part lands, the
// protected one is skipped.
func TestNestedUploadACL_MixedWithoutCredentials(t *testing.T) {
	root := aclTree(t)
	fs, _ := newTestFileServer(t, root)

	w := httptest.NewRecorder()
	fs.upload(w, nestedUploadRequest(t, "/upload", map[string]string{
		"protected/pwn.txt": "PWNED",
		"public/sub/ok.txt": "ok",
	}))

	require.Equal(t, http.StatusSeeOther, w.Code)
	require.FileExists(t, filepath.Join(root, "public", "sub", "ok.txt"))
	_, err := os.Stat(filepath.Join(root, "protected", "pwn.txt"))
	require.True(t, os.IsNotExist(err))
}
