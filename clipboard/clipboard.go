// Package clipboard will provide the functionality of a clipboard
package clipboard

import (
	"encoding/json"
	"fmt"
	"time"
)

// Clipboard is the in memory clipboard to hold the copy-pasteable content
type Clipboard struct {
	Entries []Entry
}

// Entry will represent a single entry in the clipboard
type Entry struct {
	ID      int
	Content string
	Time    string
}

// New will return an instantiated Clipboard
func New() *Clipboard {
	cb := &Clipboard{}
	return cb
}

// AddEntry will give the opportunity to add an entry to the clipboard
func (c *Clipboard) AddEntry(con string) error {
	entries := c.Entries
	if len(entries) > 0 {
		entries = append([]Entry{{
			ID:      len(entries),
			Content: con,
			Time:    time.Now().Format("Mon Jan _2 15:04:05 2006"),
		}}, entries...) // Create a copy of the slice to avoid modifying the original
	} else {
		entries = append([]Entry{{
			ID:      0,
			Content: con,
			Time:    time.Now().Format("Mon Jan _2 15:04:05 2006"),
		}}, entries...) // Create a copy of the slice to avoid modifying the original
	}
	c.Entries = entries
	return nil
}

// DeleteEntry will give the opportunity to delete an entry from the clipboard
func (c *Clipboard) DeleteEntry(id int) error {
	entries := c.Entries
	if id < 0 {
		return fmt.Errorf("id cannot be negative: %d", id)
	}
	if id >= len(entries) {
		return fmt.Errorf("invalid entry ID: %d", id)
	}
	entries = append(entries[:id], entries[id+1:]...)
	newEntries := reindex(entries)
	c.Entries = newEntries
	return nil
}

// ClearClipboard will empty the clipboard
func (c *Clipboard) ClearClipboard() error {
	c.Entries = nil
	return nil
}

// GetEntries will give the opportunity to receive the entries from the clipboard
func (c *Clipboard) GetEntries() ([]Entry, error) {
	entries := c.Entries
	return entries, nil
}

// Download will return a json encoded representation of the clipboards content for download purposes
func (c *Clipboard) Download() ([]byte, error) {
	entries := c.Entries
	e, err := json.MarshalIndent(entries, "", "    ")
	if err != nil {
		return nil, err
	}
	return e, nil
}

func reindex(entries []Entry) []Entry {
	n := len(entries)
	for i := range entries {
		entries[i].ID = n - 1 - i
	}

	return entries
}
