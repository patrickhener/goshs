package httpserver

import (
	"html/template"
	"net/http"

	"github.com/patrickhener/goshs/v2/logger"
)

// UIData is the struct passed to index.html on every page render.
// Map your existing FileServer fields onto this when calling renderIndex.
type UIData struct {
	// Meta
	GoshsVersion string

	// Current path
	AbsPath         string
	BreadcrumbParts []BreadcrumbPart
	Subdirectory    bool
	QRCode          string
	SharedLinks     map[string]SharedLink

	// Feature flags (controls which tabs/buttons appear)
	ReadOnly    bool
	UploadOnly  bool
	NoClipboard bool
	NoDelete    bool
	CLI         bool
	Embedded    bool

	// File listing
	Items []FileItem

	// Embedded files
	EmbeddedItems []FileItem

	// Clipboard entries (pre-loaded from server state)
	Clipboard []ClipEntry

	// CSRF token embedded into the page for JS to read
	CSRFToken string
}

// BreadcrumbPart is a single segment of the path breadcrumb.
type BreadcrumbPart struct {
	Name string
	Path string
}

// FileItem represents one row in the file listing table.
type FileItem struct {
	RelPath    string
	Name       string
	IsDir      bool
	Size       string // human-readable, e.g. "1.4 MB"
	SizeRaw    int64  // bytes, used for JS sorting
	LastMod    string // formatted date string
	LastModRaw int64  // unix timestamp, used for JS sorting
	Extension  string // lowercase with dot, e.g. ".go"
	QRCode     string
	Auth       bool
}

// ClipEntry is a single clipboard entry rendered server-side.
type ClipEntry struct {
	ID      int
	Content string
	Time    string
}

// renderIndex parses and executes the embedded index.html template.
func renderIndex(w http.ResponseWriter, data UIData) error {
	tmpl, err := template.New("index.html").
		Funcs(template.FuncMap{
			// {{if not .Flag}} helper — Go templates don't have "not" built-in
			"not": func(b bool) bool { return !b },
			"sub": func(a, b int) int { return a - b },
			"percent": func(used, total int) int {
				if total <= 0 {
					return 0
				}
				p := used * 100 / total
				if p > 100 {
					return 100
				}
				return p
			},
		}).
		ParseFS(static, "static/templates/index.html")
	if err != nil {
		logger.Errorf("parsing index.html: %+v", err)
		return err
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := tmpl.Execute(w, data); err != nil {
		logger.Errorf("executing index.html: %+v", err)
	}

	return err
}
