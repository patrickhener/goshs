package httpserver

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

// Regression tests for GHSA-rf62-vgq5-ggq5: DELETE resolved the .goshs ACL
// upwards from the parent of the target but then removed downwards with
// os.RemoveAll, so deleting an unprotected ancestor destroyed every
// auth-protected subtree below it without the credential.

func deleteReq(path string) *http.Request {
	r := httptest.NewRequest(http.MethodDelete, path, nil)
	r.Header.Set("X-CSRF-Token", "test-csrf")
	return r
}

// deepACLTree nests aclTree's protected dir two levels down: a/b/protected.
func deepACLTree(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	src := aclTree(t)
	require.NoError(t, os.MkdirAll(filepath.Join(root, "a", "b"), 0755))
	require.NoError(t, os.Rename(filepath.Join(src, "protected"), filepath.Join(root, "a", "b", "protected")))
	return root
}

func TestDeleteACL_ProtectedDirItselfRequiresAuth(t *testing.T) {
	root := aclTree(t)
	fs, _ := newTestFileServer(t, root)

	w := httptest.NewRecorder()
	fs.deleteFile(w, deleteReq("/protected"))
	require.Equal(t, http.StatusUnauthorized, w.Code)
	require.FileExists(t, filepath.Join(root, "protected", "secret.txt"))
	require.FileExists(t, filepath.Join(root, "protected", ".goshs"))
}

func TestDeleteACL_ProtectedDirWithCredsDeleted(t *testing.T) {
	root := aclTree(t)
	fs, _ := newTestFileServer(t, root)

	r := deleteReq("/protected")
	r.SetBasicAuth("user", "pass")
	w := httptest.NewRecorder()
	fs.deleteFile(w, r)
	require.NoDirExists(t, filepath.Join(root, "protected"))
}

func TestDeleteACL_AncestorOfProtectedSubtreeDenied(t *testing.T) {
	root := deepACLTree(t)
	fs, _ := newTestFileServer(t, root)

	w := httptest.NewRecorder()
	fs.deleteFile(w, deleteReq("/a"))
	require.Equal(t, http.StatusForbidden, w.Code)
	require.FileExists(t, filepath.Join(root, "a", "b", "protected", "secret.txt"))
	require.FileExists(t, filepath.Join(root, "a", "b", "protected", ".goshs"))
}

func TestDeleteACL_WebrootDenied(t *testing.T) {
	root := aclTree(t)
	fs, _ := newTestFileServer(t, root)

	w := httptest.NewRecorder()
	fs.deleteFile(w, deleteReq("/"))
	require.Equal(t, http.StatusForbidden, w.Code)
	require.FileExists(t, filepath.Join(root, "public.txt"))
}

// A directory holding a block-listed (hidden) entry must not be deletable
// either, in both the plain-name and "name/" folder conventions.
func TestDeleteACL_SubtreeWithBlockedEntryDenied(t *testing.T) {
	for _, entry := range []string{"hidden.txt", "hidden/"} {
		root := t.TempDir()
		d := filepath.Join(root, "d")
		require.NoError(t, os.Mkdir(d, 0755))
		require.NoError(t, os.WriteFile(filepath.Join(d, ".goshs"), []byte(`{"block":["`+entry+`"]}`), 0644))
		if entry == "hidden/" {
			require.NoError(t, os.Mkdir(filepath.Join(d, "hidden"), 0755))
		} else {
			require.NoError(t, os.WriteFile(filepath.Join(d, "hidden.txt"), []byte("x"), 0644))
		}
		fs, _ := newTestFileServer(t, root)

		w := httptest.NewRecorder()
		fs.deleteFile(w, deleteReq("/d"))
		require.Equal(t, http.StatusForbidden, w.Code, entry)
		require.DirExists(t, d, entry)
	}
}

// A block-listed directory addressed directly ("secret/" convention, which
// blockListedPath's bare basename never matched).
func TestDeleteACL_BlockListedDirDenied(t *testing.T) {
	root := t.TempDir()
	require.NoError(t, os.Mkdir(filepath.Join(root, "secret"), 0755))
	require.NoError(t, os.WriteFile(filepath.Join(root, ".goshs"), []byte(`{"block":["secret/"]}`), 0644))
	fs, _ := newTestFileServer(t, root)

	w := httptest.NewRecorder()
	fs.deleteFile(w, deleteReq("/secret"))
	require.DirExists(t, filepath.Join(root, "secret"))
}

func TestDeleteACL_UnprotectedDirStillDeleted(t *testing.T) {
	root := aclTree(t)
	require.NoError(t, os.MkdirAll(filepath.Join(root, "plain", "sub"), 0755))
	require.NoError(t, os.WriteFile(filepath.Join(root, "plain", "sub", "f.txt"), []byte("x"), 0644))
	fs, _ := newTestFileServer(t, root)

	w := httptest.NewRecorder()
	fs.deleteFile(w, deleteReq("/plain"))
	require.NoDirExists(t, filepath.Join(root, "plain"))
}

func TestDeleteACL_WebDAVRemoveAllAncestorDenied(t *testing.T) {
	root := deepACLTree(t)
	fs, _ := newTestFileServer(t, root)
	wfs := fs.newWebdavFileSystem()

	r := httptest.NewRequest(http.MethodDelete, "/a", nil)
	ctx := context.WithValue(context.Background(), webdavCtxKey{}, r)
	require.ErrorIs(t, wfs.RemoveAll(ctx, "/a"), os.ErrPermission)
	require.FileExists(t, filepath.Join(root, "a", "b", "protected", "secret.txt"))

	// Still works for an unprotected subtree.
	require.NoError(t, os.MkdirAll(filepath.Join(root, "plain", "sub"), 0755))
	require.NoError(t, wfs.RemoveAll(ctx, "/plain"))
	require.NoDirExists(t, filepath.Join(root, "plain"))
}

func TestDeleteACL_ProtocolSubtreeAllowed(t *testing.T) {
	root := deepACLTree(t)
	p := NewProtocolACL(root)
	require.False(t, p.SubtreeAllowed(filepath.Join(root, "a")))
	require.False(t, p.SubtreeAllowed(root))
	require.NoError(t, os.MkdirAll(filepath.Join(root, "plain"), 0755))
	require.True(t, p.SubtreeAllowed(filepath.Join(root, "plain")))
	require.True(t, p.SubtreeAllowed(filepath.Join(root, "public.txt")))
}
