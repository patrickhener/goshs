package httpserver

import (
	"bytes"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

// blockTree builds a webroot with a "blocked" directory whose .goshs ACL blocks
// "secret.txt". The ACL is block-only (no auth), which is the configuration the
// trailing-slash bypass affects.
func blockTree(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	blocked := filepath.Join(dir, "blocked")
	require.NoError(t, os.Mkdir(blocked, 0755))
	require.NoError(t, os.WriteFile(filepath.Join(blocked, "secret.txt"), []byte("TOP-SECRET"), 0644))
	require.NoError(t, os.WriteFile(filepath.Join(blocked, ".goshs"), []byte(`{"block":["secret.txt"]}`), 0644))
	return dir
}

// Regression for the trailing-slash bypass in sendFile: a blocked file must stay
// blocked whether or not the request path carries a trailing slash. Before the
// fix, sendFile derived the guard name from the raw req.URL.Path, so a trailing
// slash produced an empty name that matched neither ".goshs" nor the block list.
func TestSendFile_TrailingSlash_BlockedFile(t *testing.T) {
	fs, cleanup := newTestFileServer(t, blockTree(t))
	defer cleanup()

	cases := []struct {
		name string
		path string
	}{
		{"control-no-slash", "/blocked/secret.txt"},
		{"trailing-slash", "/blocked/secret.txt/"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, tc.path, nil)
			w := httptest.NewRecorder()
			fs.handler(w, r)

			require.Equal(t, http.StatusNotFound, w.Code)
			require.NotContains(t, w.Body.String(), "TOP-SECRET")
		})
	}
}

// The .goshs ACL file itself must never be served, again regardless of a trailing
// slash. Before the fix, /blocked/.goshs/ returned the ACL file (including any
// bcrypt hash) with 200.
func TestSendFile_TrailingSlash_ACLFileNeverServed(t *testing.T) {
	fs, cleanup := newTestFileServer(t, blockTree(t))
	defer cleanup()

	for _, path := range []string{"/blocked/.goshs", "/blocked/.goshs/"} {
		t.Run(path, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, path, nil)
			w := httptest.NewRecorder()
			fs.handler(w, r)

			require.Equal(t, http.StatusNotFound, w.Code)
			// The ACL file's own JSON must never appear in the response body.
			require.NotContains(t, w.Body.String(), `"block":[`)
		})
	}
}

// multipartUpload builds a multipart/form-data body with a single file part whose
// declared filename is filename, returning the body and its Content-Type header.
func multipartUpload(t *testing.T, filename, content string) (*bytes.Buffer, string) {
	t.Helper()
	body := &bytes.Buffer{}
	mw := multipart.NewWriter(body)
	// Write the Content-Disposition by hand so the raw filename (e.g. "..") is
	// preserved instead of being escaped by CreateFormFile's quoting helper.
	part, err := mw.CreatePart(map[string][]string{
		"Content-Disposition": {`form-data; name="files"; filename="` + filename + `"`},
	})
	require.NoError(t, err)
	_, err = part.Write([]byte(content))
	require.NoError(t, err)
	require.NoError(t, mw.Close())
	return body, mw.FormDataContentType()
}

// Regression for the residual upload traversal (CVE-2026-35393 follow-up): an
// upload whose filename is ".." must be rejected, not written to the parent of
// the served tree. Before the fix, filepath.Join(targetDir, "..")+"~" landed a
// file outside the webroot.
func TestUpload_DotDotFilename_NoEscape(t *testing.T) {
	webroot := t.TempDir()
	fs, cleanup := newTestFileServer(t, webroot)
	defer cleanup()

	escape := filepath.Join(webroot, "..") + "~"
	// Clean up any stray artifact even if the test fails.
	t.Cleanup(func() { _ = os.Remove(escape) })

	body, ctype := multipartUpload(t, "..", "ESCAPED_WRITE_PROOF")
	r := httptest.NewRequest(http.MethodPost, "/upload", body)
	r.Header.Set("Content-Type", ctype)
	r.Header.Set("X-CSRF-Token", "test-csrf")
	w := httptest.NewRecorder()

	fs.upload(w, r)

	_, err := os.Stat(escape)
	require.Truef(t, os.IsNotExist(err), "file escaped the webroot at %s", escape)
}

// A normal upload must still succeed after the traversal hardening.
func TestUpload_ValidFilename_Succeeds(t *testing.T) {
	webroot := t.TempDir()
	fs, cleanup := newTestFileServer(t, webroot)
	defer cleanup()

	body, ctype := multipartUpload(t, "good.txt", "hello")
	r := httptest.NewRequest(http.MethodPost, "/upload", body)
	r.Header.Set("Content-Type", ctype)
	r.Header.Set("X-CSRF-Token", "test-csrf")
	w := httptest.NewRecorder()

	fs.upload(w, r)

	require.Equal(t, http.StatusSeeOther, w.Code)
	got, err := os.ReadFile(filepath.Join(webroot, "good.txt"))
	require.NoError(t, err)
	require.Equal(t, "hello", string(got))
}

// Folder upload: a multipart filename carrying a relative path (as browsers send
// via webkitRelativePath) must recreate the subdirectory tree, creating any
// intermediate directories, rather than flattening or rejecting the file.
func TestUpload_FolderPath_PreservesSubdirectory(t *testing.T) {
	webroot := t.TempDir()
	fs, cleanup := newTestFileServer(t, webroot)
	defer cleanup()

	body, ctype := multipartUpload(t, "sub/dir/file.txt", "nested")
	r := httptest.NewRequest(http.MethodPost, "/upload", body)
	r.Header.Set("Content-Type", ctype)
	r.Header.Set("X-CSRF-Token", "test-csrf")
	w := httptest.NewRecorder()

	fs.upload(w, r)

	require.Equal(t, http.StatusSeeOther, w.Code)
	got, err := os.ReadFile(filepath.Join(webroot, "sub", "dir", "file.txt"))
	require.NoError(t, err)
	require.Equal(t, "nested", string(got))
}

// Folder upload must not become a traversal primitive: a relative path that
// climbs out of the target with ".." is rejected, leaving nothing outside the
// webroot. sanitizePath cleans "sub/../../escape.txt" and detects the escape.
func TestUpload_FolderPath_DotDot_NoEscape(t *testing.T) {
	webroot := t.TempDir()
	fs, cleanup := newTestFileServer(t, webroot)
	defer cleanup()

	escape := filepath.Join(filepath.Dir(webroot), "escape.txt")
	t.Cleanup(func() { _ = os.Remove(escape) })

	body, ctype := multipartUpload(t, "sub/../../escape.txt", "ESCAPED_WRITE_PROOF")
	r := httptest.NewRequest(http.MethodPost, "/upload", body)
	r.Header.Set("Content-Type", ctype)
	r.Header.Set("X-CSRF-Token", "test-csrf")
	w := httptest.NewRecorder()

	fs.upload(w, r)

	_, err := os.Stat(escape)
	require.Truef(t, os.IsNotExist(err), "file escaped the webroot at %s", escape)
}

// ─── GHSA-3x28-6v7h-gg87: case-insensitive ACL enforcement ──────────────────

// blockListed must match alternate-case spellings so that requests like
// /SECRET.TXT are blocked when the ACL has "secret.txt" (GHSA-3x28-6v7h-gg87).
func TestBlockListed_CaseInsensitive(t *testing.T) {
	block := []string{"secret.txt"}
	require.True(t, blockListed(block, "secret.txt"))
	require.True(t, blockListed(block, "SECRET.TXT"))
	require.True(t, blockListed(block, "Secret.Txt"))
	require.False(t, blockListed(block, "other.txt"))
}

// On a case-insensitive filesystem sendFile receives the filename in the
// attacker's casing (os.File.Stat().Name() returns the basename of the path
// passed to os.Open). Before the fix the case-sensitive comparison let it
// through. A symlink makes the bypass reproducible on Linux.
func TestSendFile_BlockedByACL_AlternateCasing(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "secret.txt"), []byte("TOP-SECRET"), 0644))
	require.NoError(t, os.Symlink(filepath.Join(dir, "secret.txt"), filepath.Join(dir, "SECRET.TXT")))
	fs, cleanup := newTestFileServer(t, dir)
	defer cleanup()

	f, err := os.Open(filepath.Join(dir, "SECRET.TXT"))
	require.NoError(t, err)
	defer f.Close()

	r := httptest.NewRequest(http.MethodGet, "/SECRET.TXT", nil)
	w := httptest.NewRecorder()
	fs.sendFile(w, r, f, configFile{Block: []string{"secret.txt"}})

	require.Equal(t, http.StatusNotFound, w.Code)
	require.NotContains(t, w.Body.String(), "TOP-SECRET")
}

// The .goshs ACL file must never be served regardless of letter case.
func TestSendFile_GoshsACLFile_AlternateCasing(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, ".goshs"), []byte(`{"block":["secret.txt"]}`), 0644))
	require.NoError(t, os.Symlink(filepath.Join(dir, ".goshs"), filepath.Join(dir, ".GOSHS")))
	fs, cleanup := newTestFileServer(t, dir)
	defer cleanup()

	f, err := os.Open(filepath.Join(dir, ".GOSHS"))
	require.NoError(t, err)
	defer f.Close()

	r := httptest.NewRequest(http.MethodGet, "/.GOSHS", nil)
	w := httptest.NewRecorder()
	fs.sendFile(w, r, f, configFile{})

	require.Equal(t, http.StatusNotFound, w.Code)
	require.NotContains(t, w.Body.String(), `"block":[`)
}

// Uploading a file named ".GOSHS" (alternate case) must be blocked.
func TestUpload_GoshsFile_AlternateCasing_Blocked(t *testing.T) {
	webroot := t.TempDir()
	fs, cleanup := newTestFileServer(t, webroot)
	defer cleanup()

	body, ctype := multipartUpload(t, ".GOSHS", `{"block":["x"]}`)
	r := httptest.NewRequest(http.MethodPost, "/upload", body)
	r.Header.Set("Content-Type", ctype)
	r.Header.Set("X-CSRF-Token", "test-csrf")
	w := httptest.NewRecorder()

	fs.upload(w, r)

	_, err := os.Stat(filepath.Join(webroot, ".GOSHS"))
	require.Truef(t, os.IsNotExist(err), "upload of alternate-case .GOSHS must be blocked")
}

// A .GOSHS component anywhere in a folder-upload path must also be blocked.
func TestUpload_FolderPath_GoshsComponent_AlternateCasing_Blocked(t *testing.T) {
	webroot := t.TempDir()
	fs, cleanup := newTestFileServer(t, webroot)
	defer cleanup()

	body, ctype := multipartUpload(t, "sub/.GOSHS", `{"block":["x"]}`)
	r := httptest.NewRequest(http.MethodPost, "/upload", body)
	r.Header.Set("Content-Type", ctype)
	r.Header.Set("X-CSRF-Token", "test-csrf")
	w := httptest.NewRecorder()

	fs.upload(w, r)

	_, err := os.Stat(filepath.Join(webroot, "sub", ".GOSHS"))
	require.Truef(t, os.IsNotExist(err), "folder upload with alternate-case .GOSHS component must be blocked")
}

// A .goshs component anywhere in an uploaded folder path must be rejected, so a
// folder upload cannot plant or shadow an ACL file.
func TestUpload_FolderPath_GoshsComponent_Blocked(t *testing.T) {
	webroot := t.TempDir()
	fs, cleanup := newTestFileServer(t, webroot)
	defer cleanup()

	body, ctype := multipartUpload(t, "sub/.goshs", `{"block":["x"]}`)
	r := httptest.NewRequest(http.MethodPost, "/upload", body)
	r.Header.Set("Content-Type", ctype)
	r.Header.Set("X-CSRF-Token", "test-csrf")
	w := httptest.NewRecorder()

	fs.upload(w, r)

	_, err := os.Stat(filepath.Join(webroot, "sub", ".goshs"))
	require.Truef(t, os.IsNotExist(err), "an uploaded .goshs path component must be blocked")
}

// GHSA-966r-mw4j-rv64: HTTP PUT opens the target with O_TRUNC, so overwriting an
// existing file destroys its contents. Under --no-delete that must be blocked and
// the file left intact.
func TestPut_NoDelete_BlocksOverwrite(t *testing.T) {
	webroot := t.TempDir()
	fs, cleanup := newTestFileServer(t, webroot)
	defer cleanup()
	fs.NoDelete = true
	require.NoError(t, os.WriteFile(filepath.Join(webroot, "victim.txt"), []byte("VICTIM"), 0644))

	r := httptest.NewRequest(http.MethodPut, "/victim.txt", bytes.NewBufferString("CLOBBERED"))
	r.Header.Set("X-CSRF-Token", "test-csrf")
	w := httptest.NewRecorder()

	fs.put(w, r)

	require.Equal(t, http.StatusForbidden, w.Code)
	got, err := os.ReadFile(filepath.Join(webroot, "victim.txt"))
	require.NoError(t, err)
	require.Equal(t, "VICTIM", string(got), "existing file must not be truncated/overwritten")
}

// --upload-only likewise forbids destroying existing content via PUT overwrite.
func TestPut_UploadOnly_BlocksOverwrite(t *testing.T) {
	webroot := t.TempDir()
	fs, cleanup := newTestFileServer(t, webroot)
	defer cleanup()
	fs.UploadOnly = true
	require.NoError(t, os.WriteFile(filepath.Join(webroot, "victim.txt"), []byte("VICTIM"), 0644))

	r := httptest.NewRequest(http.MethodPut, "/victim.txt", bytes.NewBufferString("CLOBBERED"))
	r.Header.Set("X-CSRF-Token", "test-csrf")
	w := httptest.NewRecorder()

	fs.put(w, r)

	require.Equal(t, http.StatusForbidden, w.Code)
	got, err := os.ReadFile(filepath.Join(webroot, "victim.txt"))
	require.NoError(t, err)
	require.Equal(t, "VICTIM", string(got))
}

// Creating a new file via PUT destroys nothing and must stay allowed under
// --no-delete. Confirms the overwrite guard does not over-block fresh writes.
func TestPut_NoDelete_AllowsNewFile(t *testing.T) {
	webroot := t.TempDir()
	fs, cleanup := newTestFileServer(t, webroot)
	defer cleanup()
	fs.NoDelete = true

	r := httptest.NewRequest(http.MethodPut, "/fresh.txt", bytes.NewBufferString("NEW"))
	r.Header.Set("X-CSRF-Token", "test-csrf")
	w := httptest.NewRecorder()

	fs.put(w, r)

	got, err := os.ReadFile(filepath.Join(webroot, "fresh.txt"))
	require.NoError(t, err)
	require.Equal(t, "NEW", string(got))
}

// The multipart upload path renames the temp file over any existing same-named
// file, clobbering it. Under --no-delete that overwrite must be skipped and the
// existing file left intact.
func TestUpload_NoDelete_BlocksOverwrite(t *testing.T) {
	webroot := t.TempDir()
	fs, cleanup := newTestFileServer(t, webroot)
	defer cleanup()
	fs.NoDelete = true
	require.NoError(t, os.WriteFile(filepath.Join(webroot, "victim.txt"), []byte("VICTIM"), 0644))

	body, ctype := multipartUpload(t, "victim.txt", "CLOBBERED")
	r := httptest.NewRequest(http.MethodPost, "/upload", body)
	r.Header.Set("Content-Type", ctype)
	r.Header.Set("X-CSRF-Token", "test-csrf")
	w := httptest.NewRecorder()

	fs.upload(w, r)

	got, err := os.ReadFile(filepath.Join(webroot, "victim.txt"))
	require.NoError(t, err)
	require.Equal(t, "VICTIM", string(got), "existing file must not be clobbered by upload")
}

// A new-named upload must still succeed under --no-delete.
func TestUpload_NoDelete_AllowsNewFile(t *testing.T) {
	webroot := t.TempDir()
	fs, cleanup := newTestFileServer(t, webroot)
	defer cleanup()
	fs.NoDelete = true

	body, ctype := multipartUpload(t, "fresh.txt", "NEW")
	r := httptest.NewRequest(http.MethodPost, "/upload", body)
	r.Header.Set("Content-Type", ctype)
	r.Header.Set("X-CSRF-Token", "test-csrf")
	w := httptest.NewRecorder()

	fs.upload(w, r)

	require.Equal(t, http.StatusSeeOther, w.Code)
	got, err := os.ReadFile(filepath.Join(webroot, "fresh.txt"))
	require.NoError(t, err)
	require.Equal(t, "NEW", string(got))
}

// ─── GHSA-wh5w-m4vw-7mjm: Windows name-alias block-list bypass ──────────────
//
// On Windows (NTFS) a trailing-dot/space segment (".env." → ".env", any name)
// and an 8.3 short name ("LONGSE~1.TXT" → "longsecret.txt") open the same file
// as the canonical name, but the block check compared the attacker's spelling.
// EqualFold (the GHSA-3x28 fix) only folds case, so both aliases slipped a
// blocked file past the guard. On Linux a symlink makes each alias reproducible
// (os.Stat follows it to the real file, so canonicalBaseName's os.SameFile scan
// matches the real sibling entry), exactly as the GHSA-3x28 casing tests do.

// blockListed must treat trailing-dot and trailing-space spellings as the base
// name, for files and (with the "/" folder convention) directories.
func TestBlockListed_TrailingDotSpace(t *testing.T) {
	block := []string{".env", "secret.txt"}
	require.True(t, blockListed(block, ".env."))
	require.True(t, blockListed(block, ".env "))
	require.True(t, blockListed(block, ".env. ."))
	require.True(t, blockListed(block, "secret.txt."))
	require.False(t, blockListed(block, "other.txt"))
	require.False(t, blockListed(block, "env")) // not an alias of ".env"

	dirBlock := []string{"secretdir/"}
	require.True(t, blockListed(dirBlock, "secretdir/"))
	require.True(t, blockListed(dirBlock, "secretdir./"))
	require.True(t, blockListed(dirBlock, "secretdir /"))
}

// isACLFileName must recognise aliased spellings of .goshs so the credential
// hashes cannot be served or listed.
func TestIsACLFileName_Aliases(t *testing.T) {
	require.True(t, isACLFileName(".goshs"))
	require.True(t, isACLFileName(".GOSHS"))
	require.True(t, isACLFileName(".goshs."))
	require.True(t, isACLFileName(".goshs "))
	require.False(t, isACLFileName("goshs"))
	require.False(t, isACLFileName(".goshs.bak"))
}

// canonicalBaseName resolves an alias back to the real on-disk entry (via
// os.SameFile) and falls back to the lexical base when the path is absent.
func TestCanonicalBaseName(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "longsecret.txt"), []byte("LS"), 0644))
	require.NoError(t, os.Symlink(filepath.Join(dir, "longsecret.txt"), filepath.Join(dir, "LONGSE~1.TXT")))

	require.Equal(t, "longsecret.txt", canonicalBaseName(filepath.Join(dir, "LONGSE~1.TXT")))
	require.Equal(t, "longsecret.txt", canonicalBaseName(filepath.Join(dir, "longsecret.txt")))
	require.Equal(t, "missing.txt", canonicalBaseName(filepath.Join(dir, "missing.txt")))
}

// A blocked file must stay blocked when requested by its trailing-dot alias.
func TestSendFile_BlockedByACL_TrailingDot(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, ".env"), []byte("SECRET=topsecret"), 0644))
	require.NoError(t, os.Symlink(filepath.Join(dir, ".env"), filepath.Join(dir, ".env.")))
	fs, cleanup := newTestFileServer(t, dir)
	defer cleanup()

	f, err := os.Open(filepath.Join(dir, ".env."))
	require.NoError(t, err)
	defer f.Close()

	r := httptest.NewRequest(http.MethodGet, "/.env.", nil)
	w := httptest.NewRecorder()
	fs.sendFile(w, r, f, configFile{Block: []string{".env"}})

	require.Equal(t, http.StatusNotFound, w.Code)
	require.NotContains(t, w.Body.String(), "topsecret")
}

// A blocked file must stay blocked when requested by its 8.3 short name.
func TestSendFile_BlockedByACL_ShortName(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "longsecret.txt"), []byte("LONGSECRET"), 0644))
	require.NoError(t, os.Symlink(filepath.Join(dir, "longsecret.txt"), filepath.Join(dir, "LONGSE~1.TXT")))
	fs, cleanup := newTestFileServer(t, dir)
	defer cleanup()

	f, err := os.Open(filepath.Join(dir, "LONGSE~1.TXT"))
	require.NoError(t, err)
	defer f.Close()

	r := httptest.NewRequest(http.MethodGet, "/LONGSE~1.TXT", nil)
	w := httptest.NewRecorder()
	fs.sendFile(w, r, f, configFile{Block: []string{"longsecret.txt"}})

	require.Equal(t, http.StatusNotFound, w.Code)
	require.NotContains(t, w.Body.String(), "LONGSECRET")
}

// The .goshs ACL file must never be served via a trailing-dot alias.
func TestSendFile_GoshsACLFile_TrailingDot(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, ".goshs"), []byte(`{"block":["secret.txt"]}`), 0644))
	require.NoError(t, os.Symlink(filepath.Join(dir, ".goshs"), filepath.Join(dir, ".goshs.")))
	fs, cleanup := newTestFileServer(t, dir)
	defer cleanup()

	f, err := os.Open(filepath.Join(dir, ".goshs."))
	require.NoError(t, err)
	defer f.Close()

	r := httptest.NewRequest(http.MethodGet, "/.goshs.", nil)
	w := httptest.NewRecorder()
	fs.sendFile(w, r, f, configFile{})

	require.Equal(t, http.StatusNotFound, w.Code)
	require.NotContains(t, w.Body.String(), `"block":[`)
}

// ProtocolACL (SFTP/FTP/TFTP/SMB) must deny aliased spellings of a blocked file
// and of the .goshs config.
func TestProtocolACL_Allowed_Aliases(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "longsecret.txt"), []byte("LS"), 0644))
	require.NoError(t, os.Symlink(filepath.Join(dir, "longsecret.txt"), filepath.Join(dir, "LONGSE~1.TXT")))
	require.NoError(t, os.WriteFile(filepath.Join(dir, ".goshs"), []byte(`{"block":["longsecret.txt"]}`), 0644))
	require.NoError(t, os.Symlink(filepath.Join(dir, ".goshs"), filepath.Join(dir, ".goshs.")))

	p := NewProtocolACL(dir)
	require.False(t, p.Allowed(filepath.Join(dir, "longsecret.txt")), "canonical blocked name")
	require.False(t, p.Allowed(filepath.Join(dir, "longsecret.txt.")), "trailing-dot alias")
	require.False(t, p.Allowed(filepath.Join(dir, "LONGSE~1.TXT")), "8.3 short-name alias")
	require.False(t, p.Allowed(filepath.Join(dir, ".goshs.")), "trailing-dot alias of .goshs")
}
