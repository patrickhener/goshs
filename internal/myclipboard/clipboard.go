package myclipboard

import "encoding/json"

// Clipboard is the in memory clipboard to hold the copy-pasteable content
type Clipboard struct {
	Entries []Entry
}

// Entry will represent a single entry in the clipboard
type Entry struct {
	id      int
	content string
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
		lastEntry := entries[len(entries)-1]
		newID := lastEntry.id + 1
		entries = append(entries, Entry{
			id:      newID,
			content: con,
		})
	} else {
		entries = append(entries, Entry{
			id:      0,
			content: con,
		})
	}
	c.Entries = entries
	return nil
}

// DeleteEntry will give the opportunity to delete an entry from the clipboard
func (c *Clipboard) DeleteEntry(id int) error {
	entries := c.Entries
	entries = append(entries[:id], entries[id+1:]...)
	c.Entries = entries
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
	e, err := json.Marshal(entries)
	if err != nil {
		return nil, err
	}
	return e, nil
}
