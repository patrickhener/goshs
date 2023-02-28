package clipboard

import (
	"encoding/json"
	"testing"
)

var (
	cb *Clipboard
)

func TestNew(t *testing.T) {
	cb = New()
	if len(cb.Entries) != 0 {
		t.Error("Error testing New")
	}
}

func TestAddEntry(t *testing.T) {
	lengthBefore := len(cb.Entries)
	if lengthBefore == 0 {
		cb.AddEntry("This is a test entry")
		lengthAfter := len(cb.Entries)
		if lengthAfter != 1 {
			t.Errorf("Error in testing AddEntry: want length of 1 got length of %d", lengthAfter)
		}
	} else {
		t.Error("something went wrong testing AddEntry")
	}
}

func TestDeleteEntry(t *testing.T) {
	lengthBefore := len(cb.Entries)
	if lengthBefore == 1 {
		cb.DeleteEntry(0)
		lengthAfter := len(cb.Entries)
		if lengthAfter != 0 {
			t.Errorf("Error in testing DeleteEntry: want length of 0 got length of %d", lengthAfter)
		}
	} else {
		t.Error("something went wrong testing DeleteEntry")
	}
}

func TestGetEntries(t *testing.T) {
	cb.AddEntry("This is a test entry")
	cb.AddEntry("This is another test entry")
	cb.AddEntry("This is yet another test entry")

	res, err := cb.GetEntries()
	if err != nil {
		t.Fatal(err)
	}
	if len(res) == 0 {
		t.Errorf("Error getting Entries: want 3 entries got %d", len(res))
	}
}

func TestDownload(t *testing.T) {
	var js json.RawMessage

	resJson, err := cb.Download()
	if err != nil {
		t.Fatal(err)
	}

	if json.Unmarshal(resJson, &js) != nil {
		t.Error("Download has an error. The returned bytes are not valid json")
	}
}

func TestReindex(t *testing.T) {
	if err := cb.DeleteEntry(1); err != nil {
		t.Fatal(err)
	}
	if cb.Entries[0].ID != 0 || cb.Entries[1].ID != 1 {
		t.Logf("Error reindexing after Deletion. Entries 0 and 1 should have ID 0 and 1 - got %d and %d", cb.Entries[0].ID, cb.Entries[1].ID)
	}
}

func TestClearClipboard(t *testing.T) {
	lengthBefore := len(cb.Entries)
	if lengthBefore == 2 {
		err := cb.ClearClipboard()
		if err != nil {
			t.Fatal(err)
		}
		lengthAfter := len(cb.Entries)
		if lengthAfter != 0 {
			t.Errorf("Error clearing clipboard Entries: want 0 entries got %d", lengthAfter)
		}
	} else {
		t.Error("something went wrong testing ClearClipboard")
	}
}
