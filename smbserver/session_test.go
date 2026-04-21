package smbserver

import (
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
)

// ─── newConnState ─────────────────────────────────────────────────────────────

func TestNewConnState(t *testing.T) {
	c := newConnState()
	require.NotNil(t, c)
	require.NotNil(t, c.trees)
	require.Equal(t, uint32(1), c.nextTreeID)
}

// ─── tree management ──────────────────────────────────────────────────────────

func TestNewTreeID_Increments(t *testing.T) {
	c := newConnState()
	id1 := c.newTreeID()
	id2 := c.newTreeID()
	require.Equal(t, uint32(1), id1)
	require.Equal(t, uint32(2), id2)
}

func TestAddGetRemoveTree(t *testing.T) {
	c := newConnState()
	tree := &smbTree{ID: 5, ShareName: "goshs", RootPath: "/tmp"}
	c.addTree(tree)

	got := c.getTree(5)
	require.NotNil(t, got)
	require.Equal(t, "goshs", got.ShareName)

	c.removeTree(5)
	require.Nil(t, c.getTree(5))
}

func TestGetTree_Missing(t *testing.T) {
	c := newConnState()
	require.Nil(t, c.getTree(999))
}

// ─── handle management ────────────────────────────────────────────────────────

func TestNewHandleID_Increments(t *testing.T) {
	c := newConnState()
	id1 := c.newHandleID()
	id2 := c.newHandleID()
	require.Equal(t, uint64(2), id1)
	require.Equal(t, uint64(3), id2)
}

func TestAddGetRemoveHandle(t *testing.T) {
	c := newConnState()
	h := &smbHandle{ID: 42, Path: "/tmp/foo.txt"}
	c.addHandle(h)

	got := c.getHandle(42)
	require.NotNil(t, got)
	require.Equal(t, "/tmp/foo.txt", got.Path)

	removed := c.removeHandle(42)
	require.NotNil(t, removed)
	require.Equal(t, "/tmp/foo.txt", removed.Path)
	require.Nil(t, c.getHandle(42))
}

func TestRemoveHandle_Missing(t *testing.T) {
	c := newConnState()
	require.Nil(t, c.removeHandle(999))
}

func TestGetHandle_Missing(t *testing.T) {
	c := newConnState()
	require.Nil(t, c.getHandle(999))
}

// ─── closeAllHandles ──────────────────────────────────────────────────────────

func TestCloseAllHandles_ClosesFiles(t *testing.T) {
	dir := t.TempDir()
	f, err := os.Create(filepath.Join(dir, "test.txt"))
	require.NoError(t, err)

	c := newConnState()
	h := &smbHandle{ID: 1, Path: f.Name(), File: f}
	c.addHandle(h)

	c.closeAllHandles()

	// File should be closed; attempting to write should fail
	_, err = f.Write([]byte("x"))
	require.Error(t, err)

	// Handle should be gone
	require.Nil(t, c.getHandle(1))
}

func TestCloseAllHandles_DeleteOnClose(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "delete_me.txt")
	f, err := os.Create(path)
	require.NoError(t, err)

	c := newConnState()
	h := &smbHandle{ID: 2, Path: path, File: f, DeleteOnClose: true}
	c.addHandle(h)

	c.closeAllHandles()

	_, err = os.Stat(path)
	require.True(t, os.IsNotExist(err), "file should have been deleted on close")
}

func TestCloseAllHandles_NilFile(t *testing.T) {
	c := newConnState()
	// Handle without an open file (e.g. a directory handle that wasn't opened)
	h := &smbHandle{ID: 3, Path: "/nonexistent", File: nil}
	c.addHandle(h)

	require.NotPanics(t, func() { c.closeAllHandles() })
}

func TestCloseAllHandles_Concurrent(t *testing.T) {
	c := newConnState()
	for i := uint64(1); i <= 20; i++ {
		h := &smbHandle{ID: i, Path: "/tmp/x"}
		c.addHandle(h)
	}

	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); c.closeAllHandles() }()
	go func() { defer wg.Done(); c.closeAllHandles() }()
	wg.Wait()
}

// ─── handleFileID / fileIDFromBuf ────────────────────────────────────────────

func TestHandleFileID_RoundTrip(t *testing.T) {
	fid := handleFileID(0xDEADBEEFCAFEBABE)
	require.Equal(t, 16, len(fid))
	// Both halves encode the same ID
	require.Equal(t, uint64(0xDEADBEEFCAFEBABE), le64(fid, 0))
	require.Equal(t, uint64(0xDEADBEEFCAFEBABE), le64(fid, 8))
}

func TestFileIDFromBuf_Valid(t *testing.T) {
	buf := make([]byte, 80)
	putle64(buf, 16+8, 0xABCDEF1234567890) // volatile half at off+8
	id := fileIDFromBuf(buf, 16)
	require.Equal(t, uint64(0xABCDEF1234567890), id)
}

func TestFileIDFromBuf_TooShort(t *testing.T) {
	buf := make([]byte, 10)
	// off+16 > len(buf), returns 0
	require.Equal(t, uint64(0), fileIDFromBuf(buf, 0))
}
