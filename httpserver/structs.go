package httpserver

import (
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
	URI                 string
	Name                string
	IsDir               bool
	IsSymlink           bool
	SymlinkTarget       string
	Ext                 string
	DisplaySize         string
	SortSize            int64
	DisplayLastModified string
	SortLastModified    time.Time
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
}
