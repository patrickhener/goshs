package smtpattach

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func clearStore() {
	mu.Lock()
	store = map[string]*Attachment{}
	mu.Unlock()
}

func TestSave(t *testing.T) {
	clearStore()
	a := Save("id1", "file.txt", "text/plain", []byte("hello"))
	require.NotNil(t, a)
	require.Equal(t, "id1", a.ID)
	require.Equal(t, "file.txt", a.Filename)
	require.Equal(t, "text/plain", a.ContentType)
	require.Equal(t, 5, a.Size)
	require.Equal(t, []byte("hello"), a.Data)
}

func TestGet_Existing(t *testing.T) {
	clearStore()
	Save("id2", "doc.pdf", "application/pdf", []byte("data"))
	a, ok := Get("id2")
	require.True(t, ok)
	require.Equal(t, "id2", a.ID)
}

func TestGet_Missing(t *testing.T) {
	clearStore()
	_, ok := Get("nonexistent")
	require.False(t, ok)
}

func TestDelete(t *testing.T) {
	clearStore()
	Save("id3", "img.png", "image/png", []byte{1, 2, 3})
	Delete("id3")
	_, ok := Get("id3")
	require.False(t, ok)
}

func TestDelete_Nonexistent(t *testing.T) {
	clearStore()
	// Should not panic on deleting a non-existent key.
	require.NotPanics(t, func() { Delete("ghost") })
}

func TestPurgeOlderThan(t *testing.T) {
	clearStore()

	old := &Attachment{
		ID:       "old",
		StoredAt: time.Now().Add(-2 * time.Hour),
	}
	recent := &Attachment{
		ID:       "recent",
		StoredAt: time.Now(),
	}
	mu.Lock()
	store["old"] = old
	store["recent"] = recent
	mu.Unlock()

	PurgeOlderThan(1 * time.Hour)

	_, okOld := Get("old")
	_, okRecent := Get("recent")
	require.False(t, okOld, "old attachment should have been purged")
	require.True(t, okRecent, "recent attachment should still be present")
}

func TestWriteToTempFile(t *testing.T) {
	a := &Attachment{
		ID:       "tmpid",
		Filename: "test.txt",
		Data:     []byte("temp content"),
	}

	path, err := WriteToTempFile(a)
	require.NoError(t, err)
	require.NotEmpty(t, path)
	defer os.Remove(path)

	require.True(t, strings.HasSuffix(path, "tmpid-test.txt"))
	require.True(t, strings.Contains(path, "goshs-smtp"))

	content, err := os.ReadFile(path)
	require.NoError(t, err)
	require.Equal(t, []byte("temp content"), content)

	// Verify it's inside the expected temp dir
	expected := filepath.Join(os.TempDir(), "goshs-smtp", "tmpid-test.txt")
	require.Equal(t, expected, path)
}
