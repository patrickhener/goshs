package httpserver

import (
	"html/template"
	"net/http"
	"time"

	"github.com/patrickhener/goshs/clipboard"
	"github.com/patrickhener/goshs/webhook"
	"github.com/patrickhener/goshs/ws"
)

type baseTemplate struct {
	Clipboard       *clipboard.Clipboard
	GoshsVersion    string
	Directory       *directory
	EmbeddedContent *directory
	CLI             bool
	Embedded        bool
	NoClipboard     bool
	NoDelete        bool
	SharedLinks     map[string]SharedLink
}

type directory struct {
	RelPath        string
	AbsPath        string
	IsSubdirectory bool
	Back           string
	Content        []item
	AuthEnabled    bool
}

type item struct {
	URI                 string       `json:"-"`
	QRCode              template.URL `json:"-"`
	Name                string       `json:"name"`
	IsDir               bool         `json:"is_dir"`
	IsSymlink           bool         `json:"is_symlink"`
	SymlinkTarget       string       `json:"symlink_target"`
	Ext                 string       `json:"extension"`
	DisplaySize         string       `json:"-"`
	SortSize            int64        `json:"size_bytes"`
	DisplayLastModified string       `json:"-"`
	SortLastModified    int64        `json:"last_modified"`
	ReadOnly            bool
	NoDelete            bool
	AuthEnabled         bool
}

// FileServer holds the fileserver information
type FileServer struct {
	IP             string
	Port           int
	CLI            bool
	WebdavPort     int
	Webroot        string
	SSL            bool
	SelfSigned     bool
	LetsEncrypt    bool
	MyKey          string
	MyCert         string
	MyP12          string
	P12NoPass      bool
	User           string
	Pass           string
	CACert         string
	DropUser       string
	Version        string
	Fingerprint256 string
	Fingerprint1   string
	UploadOnly     bool
	ReadOnly       bool
	NoClipboard    bool
	NoDelete       bool
	Silent         bool
	Embedded       bool
	Verbose        bool
	Webhook        webhook.Webhook
	Hub            *ws.Hub
	Clipboard      *clipboard.Clipboard
	Whitelist      *Whitelist
	SharedLinks    map[string]SharedLink
}

type httperror struct {
	ErrorCode    int
	ErrorMessage string
	Directory    *directory
	AbsPath      string
	GoshsVersion string
	Statics      template.FuncMap
}

type configFile struct {
	Auth  string   `json:"auth"`
	Block []string `json:"block"`
}

type Middleware func(http.Handler) http.Handler

type CustomMux struct {
	mux        *http.ServeMux
	middleware []Middleware
}

type SharedLink struct {
	FilePath      string
	IsDir         bool
	Expires       time.Time
	DownloadLimit int
}
