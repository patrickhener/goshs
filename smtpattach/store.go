// smtpattach/store.go
package smtpattach

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type Attachment struct {
	ID          string
	Filename    string
	ContentType string
	Size        int
	Data        []byte
	StoredAt    time.Time
}

var (
	mu    sync.RWMutex
	store = map[string]*Attachment{}
)

func Save(id, filename, contentType string, data []byte) *Attachment {
	a := &Attachment{
		ID:          id,
		Filename:    filename,
		ContentType: contentType,
		Size:        len(data),
		Data:        data,
		StoredAt:    time.Now(),
	}
	mu.Lock()
	store[id] = a
	mu.Unlock()
	return a
}

func Get(id string) (*Attachment, bool) {
	mu.RLock()
	defer mu.RUnlock()
	a, ok := store[id]
	return a, ok
}

func Delete(id string) {
	mu.Lock()
	delete(store, id)
	mu.Unlock()
}

// PurgeOlderThan deletes attachments stored before the given duration.
// Call periodically if you want automatic cleanup, e.g. go PurgeLoop(1 * time.Hour)
func PurgeOlderThan(age time.Duration) {
	cutoff := time.Now().Add(-age)
	mu.Lock()
	for id, a := range store {
		if a.StoredAt.Before(cutoff) {
			delete(store, id)
		}
	}
	mu.Unlock()
}

func PurgeLoop(age time.Duration) {
	for range time.Tick(15 * time.Minute) {
		PurgeOlderThan(age)
	}
}

// WriteToTempFile writes an attachment to a real temp file and returns the path.
// Useful if you want to hand the file off to another process.
func WriteToTempFile(a *Attachment) (string, error) {
	dir := filepath.Join(os.TempDir(), "goshs-smtp")
	if err := os.MkdirAll(dir, 0700); err != nil {
		return "", err
	}
	path := filepath.Join(dir, fmt.Sprintf("%s-%s", a.ID, a.Filename))
	return path, os.WriteFile(path, a.Data, 0600)
}
