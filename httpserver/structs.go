package httpserver

import (
	"html/template"
	"time"

	"github.com/patrickhener/goshs/clipboard"
	"github.com/patrickhener/goshs/ws"
)

type indexTemplate struct {
	Clipboard    *clipboard.Clipboard
	GoshsVersion string
	Directory    *directory
}

type silentTemplate struct {
	GoshsVersion string
}

type directory struct {
	RelPath        string
	AbsPath        string
	IsSubdirectory bool
	Back           string
	Content        []item
}

type item struct {
	URI                 string    `json:"-"`
	Name                string    `json:"name"`
	IsDir               bool      `json:"is_dir"`
	IsSymlink           bool      `json:"is_symlink"`
	SymlinkTarget       string    `json:"symlink_target"`
	Ext                 string    `json:"extension"`
	DisplaySize         string    `json:"-"`
	SortSize            int64     `json:"size_bytes"`
	DisplayLastModified string    `json:"-"`
	SortLastModified    time.Time `json:"last_modified"`
}

// FileServer holds the fileserver information
type FileServer struct {
	IP             string
	Port           int
	WebdavPort     int
	Webroot        string
	SSL            bool
	SelfSigned     bool
	MyKey          string
	MyCert         string
	User           string
	Pass           string
	DropUser       string
	Version        string
	Fingerprint256 string
	Fingerprint1   string
	UploadOnly     bool
	ReadOnly       bool
	Silent         bool
	Verbose        bool
	Hub            *ws.Hub
	Clipboard      *clipboard.Clipboard
}

type httperror struct {
	ErrorCode    int
	ErrorMessage string
	AbsPath      string
	GoshsVersion string
	Statics      template.FuncMap
}
