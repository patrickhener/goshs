package httpserver

import (
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"io/fs"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/patrickhener/goshs/logger"
	"github.com/patrickhener/goshs/smtpattach"
	"github.com/patrickhener/goshs/utils"
	"github.com/patrickhener/goshs/ws"
)

// embedded will give additional embedded content shipped with the binary
func (fs *FileServer) embedded(w http.ResponseWriter, req *http.Request) error {
	path := "embedded" + req.URL.Path
	// Load file from embed package

	embeddedFile, err := embedded.ReadFile(path)
	if err != nil {
		logger.Errorf("embedded file: %+v cannot be loaded: %+v", path, err)
		return err
	}

	// Get mimetype from extension
	contentType := utils.MimeByExtension(path)

	// Set mimetype and deliver to browser
	w.Header().Add("Content-Type", contentType)
	if _, err := w.Write(embeddedFile); err != nil {
		logger.Errorf("Error writing response to browser: %+v", err)
		return err
	}

	return nil
}

// static will give static content for style and function
func (fs *FileServer) static(w http.ResponseWriter, req *http.Request) {
	// Construct static path to file
	path := "static" + req.URL.Path
	// Load file from embed package
	staticFile, err := static.ReadFile(path)
	if err != nil {
		logger.Errorf("static file: %+v cannot be loaded: %+v", path, err)
	}

	// Get mimetype from extension
	contentType := utils.MimeByExtension(path)

	// Set mimetype and deliver to browser
	w.Header().Add("Content-Type", contentType)
	if _, err := w.Write(staticFile); err != nil {
		logger.Errorf("Error writing response to browser: %+v", err)
	}
}

func (fs *FileServer) doDir(file *os.File, w http.ResponseWriter, req *http.Request, upath string, json bool) {
	// Check if parent folder forbids access to this directory
	parent := filepath.Dir(file.Name())
	parentConfig, err := fs.findSpecialFile(parent)
	if err != nil {
		logger.Errorf("error reading file based access config: %+v", err)
	}

	// Get foldername
	_, foldername := filepath.Split(file.Name())

	if slices.Contains(parentConfig.Block, fmt.Sprintf("%s/", foldername)) {
		fs.handleError(w, req, fmt.Errorf("open %s: no such file or directory", file.Name()), 404)
		return
	}

	// Check for effective .goshs ACL (walks up to webroot so parent configs apply recursively)
	config, err := fs.findEffectiveACL(file.Name())
	if err != nil {
		logger.Errorf("error reading file based access config: %+v", err)
	}
	fs.processDir(w, req, file, upath, json, config)
}

func (fs *FileServer) doFile(file *os.File, w http.ResponseWriter, req *http.Request) {
	// Walk up from the file's directory to find the effective .goshs ACL
	parent := filepath.Dir(file.Name())
	config, err := fs.findEffectiveACL(parent)
	if err != nil {
		logger.Errorf("error reading file based access config: %+v", err)
	}
	fs.sendFile(w, req, file, config)
}

// checkCSRF validates the X-CSRF-Token header for mutating GET actions.
// It only enforces the check when auth is enabled; anonymous deployments are
// already fully open so there is no session to hijack.
func (fs *FileServer) checkCSRF(w http.ResponseWriter, req *http.Request) bool {
	if fs.User == "" {
		return true
	}
	if req.Header.Get("X-CSRF-Token") != fs.CSRFToken {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return false
	}
	return true
}

func (fs *FileServer) earlyBreakParameters(w http.ResponseWriter, req *http.Request) bool {
	if _, ok := req.URL.Query()["smtp"]; ok {
		if denyForTokenAccess(w, req) {
			return true
		}
		fs.handleSMTPAttachment(w, req)
		return true
	}
	if _, ok := req.URL.Query()["goshs-info"]; ok {
		if denyForTokenAccess(w, req) {
			return true
		}
		fs.handleInfo(w)
		return true
	}
	if _, ok := req.URL.Query()["mkdir"]; ok {
		if denyForTokenAccess(w, req) {
			return true
		}
		if !fs.checkCSRF(w, req) {
			return true
		}
		fs.handleMkdir(w, req)
		return true
	}
	if _, ok := req.URL.Query()["ws"]; ok {
		if denyForTokenAccess(w, req) {
			return true
		}
		fs.socket(w, req)
		return true
	}
	if _, ok := req.URL.Query()["cbDown"]; ok {
		if denyForTokenAccess(w, req) {
			return true
		}
		if !fs.NoClipboard && !fs.Invisible {
			fs.cbDown(w, req)
			return true
		}
	}
	if _, ok := req.URL.Query()["bulk"]; ok {
		if denyForTokenAccess(w, req) {
			return true
		}
		if !fs.Invisible {
			fs.bulkDownload(w, req)
		} else {
			fs.handleInvisible(w)
		}
		return true
	}
	if _, ok := req.URL.Query()["static"]; ok {
		if denyForTokenAccess(w, req) {
			return true
		}
		if !fs.Invisible {
			fs.static(w, req)
		} else {
			fs.handleInvisible(w)
		}
		return true
	}
	if _, ok := req.URL.Query()["embedded"]; ok {
		if denyForTokenAccess(w, req) {
			return true
		}
		if err := fs.embedded(w, req); err != nil {
			if !fs.Invisible {
				body := fs.emitCollabEvent(req, http.StatusNotFound)
				logger.LogRequest(req, http.StatusNotFound, fs.Verbose, fs.Webhook, body)
			} else {
				fs.handleInvisible(w)
			}
			return true
		}
		body := fs.emitCollabEvent(req, http.StatusOK)
		logger.LogRequest(req, http.StatusOK, fs.Verbose, fs.Webhook, body)
		return true
	}
	if _, ok := req.URL.Query()["delete"]; ok {
		if denyForTokenAccess(w, req) {
			return true
		}
		if !fs.checkCSRF(w, req) {
			return true
		}
		if !fs.ReadOnly && !fs.UploadOnly && !fs.NoDelete {
			fs.deleteFile(w, req)
			return true
		} else {
			fs.handleError(w, req, fmt.Errorf("delete not allowed"), http.StatusForbidden)
			return true
		}
	}
	if _, ok := req.URL.Query()["share"]; ok {
		if denyForTokenAccess(w, req) {
			return true
		}
		if !fs.Invisible {
			fs.CreateShareHandler(w, req)
		} else {
			fs.handleInvisible(w)
		}
		return true
	}
	if _, ok := req.URL.Query()["redirect"]; ok {
		if denyForTokenAccess(w, req) {
			return true
		}
		fs.handleRedirect(w, req)
		return true
	}
	if _, ok := req.URL.Query()["token"]; ok {
		if !fs.Invisible {
			switch req.Method {
			case http.MethodGet:
				fs.ShareHandler(w, req)
			case http.MethodDelete:
				fs.DeleteShareHandler(w, req)
			default:
			}
		} else {
			fs.handleInvisible(w)
		}
		return true
	}
	return false
}

// handler is the function which actually handles dir or file retrieval
func (fs *FileServer) handler(w http.ResponseWriter, req *http.Request) {
	// Early break for /?ws, /?cbDown, /?bulk, /?static /?delete, ?embedded, ?share, ?token
	if ok := fs.earlyBreakParameters(w, req); ok {
		return
	}

	// Define if to return json instead of html parsing
	json := false
	if _, ok := req.URL.Query()["json"]; ok {
		json = true
	}

	// Ignore default browser call to /favicon.ico
	if req.URL.Path == "/favicon.ico" {
		return
	}

	open, err := sanitizePath(fs.Webroot, req.URL.Path)
	if err != nil {
		fs.handleError(w, req, err, http.StatusBadRequest)
		return
	}
	// Relative path used by templates
	upath := strings.TrimPrefix(open, filepath.Clean(fs.Webroot))
	if upath == "" {
		upath = "/"
	}

	// Check if you are in a dir
	// disable G304 (CWE-22): Potential file inclusion via variable
	// #nosec G304
	file, err := os.Open(open)
	if os.IsNotExist(err) {
		fs.handleError(w, req, err, http.StatusNotFound)
		return
	}
	if os.IsPermission(err) {
		fs.handleError(w, req, err, http.StatusInternalServerError)
		return
	}
	if err != nil {
		// Handle general error
		logger.Info(err)
		return
	}
	// disable G307 (CWE-703): Deferring unsafe method "Close" on type "*os.File"
	// #nosec G307
	defer file.Close()

	// Log request
	body := fs.emitCollabEvent(req, http.StatusOK)
	logger.LogRequest(req, http.StatusOK, fs.Verbose, fs.Webhook, body)

	// Switch and check if dir
	stat, _ := file.Stat()
	if stat.IsDir() {
		fs.doDir(file, w, req, upath, json)
	} else {
		fs.doFile(file, w, req)
	}
}

// Applies custom auth for file based acls
func (fileS *FileServer) applyCustomAuth(w http.ResponseWriter, req *http.Request, acl configFile) bool {
	if acl.Auth != "" {
		if !fileS.Invisible {
			w.Header().Set("WWW-Authenticate", `Basic realm="Filebased Restricted"`)
		}

		username, password, authOK := req.BasicAuth()
		if !authOK {
			fileS.handleError(w, req, fmt.Errorf("%s", "not authorized"), http.StatusUnauthorized)
			return false
		}

		user := strings.Split(acl.Auth, ":")[0]
		passwordHash := strings.Split(acl.Auth, ":")[1]

		if username != user || !checkPasswordHash(password, passwordHash) {
			fileS.handleError(w, req, fmt.Errorf("%s", "not authorized"), http.StatusUnauthorized)
			return false
		}
	}
	return true
}

func (fileS *FileServer) constructEmbedded() []item {
	var err error
	// Construct Items for embedded files
	embeddedItems := make([]item, 0)
	// Iterate over FileInfo of embedded FS
	err = fs.WalkDir(embedded, ".",
		func(pathS string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			// Set item fields
			item := item{}
			if !d.IsDir() {
				name_temp := url.PathEscape(pathS)
				name_temp = strings.TrimPrefix(name_temp, "embedded")
				item.Name = strings.ReplaceAll(name_temp, "%2F", "/")
				item.Ext = strings.ToLower(utils.ReturnExt(d.Name()))
				uri_temp := url.PathEscape(pathS)
				uri_temp = strings.TrimPrefix(uri_temp, "embedded")
				uri_temp = strings.TrimPrefix(uri_temp, "%2F")
				item.URI = fmt.Sprintf("%s?embedded", uri_temp)

				// Add to items slice
				embeddedItems = append(embeddedItems, item)
			}

			return nil
		})
	if err != nil {
		logger.Errorf("error compiling list for embedded files: %+v", err)
	}

	return embeddedItems
}

func returnJsonDirListing(w http.ResponseWriter, items []item) {
	w.Header().Add("Content-Type", "application/json")
	resJson, err := json.Marshal(items)
	if err != nil {
		logger.Errorf("error marshaling items to json: %+v", err)
	}
	_, err = w.Write(resJson)
	if err != nil {
		logger.Errorf("error writing json as response: %+v", err)
	}
}

func (fileS *FileServer) constructSilent(w http.ResponseWriter) {
	tem := &baseTemplate{
		GoshsVersion: fileS.Version,
	}

	files := []string{"static/templates/silent.html"}

	t, err := template.ParseFS(static, files...)
	if err != nil {
		logger.Errorf("Error parsing templates: %+v", err)
	}

	if err := t.Execute(w, tem); err != nil {
		logger.Errorf("Error executing template: %+v", err)
	}
}

func (fileS *FileServer) constructDefault(w http.ResponseWriter, relpath string, items []item, embeddedItems []item) {
	var subdirectory bool
	// Windows upload compatibility
	if relpath == "\\" {
		relpath = "/"
	}

	if relpath != "/" {
		subdirectory = true
	} else {
		subdirectory = false
	}

	var breadcrumbParts []BreadcrumbPart
	for i, e := range strings.Split(relpath, "/") {
		if e != "" {
			breadcrumbParts = append(breadcrumbParts, BreadcrumbPart{Name: e, Path: strings.Join(strings.Split(relpath, "/")[:i+1], "/")})
		}
	}

	var fileItems []FileItem
	for _, item := range items {
		qrcode := GenerateQRCode(relpath + item.Name)
		fileItems = append(fileItems, FileItem{
			RelPath:    relpath,
			Name:       item.Name,
			IsDir:      item.IsDir,
			Size:       item.DisplaySize,
			SizeRaw:    item.SortSize,
			LastMod:    item.DisplayLastModified,
			LastModRaw: item.SortLastModified,
			Extension:  item.Ext,
			QRCode:     qrcode,
			Auth:       fileS.Pass != "" || fileS.CACert != "",
		})
	}

	var embeddedFiles []FileItem
	for _, item := range embeddedItems {
		qrcode := GenerateQRCode(relpath + item.Name)
		embeddedFiles = append(embeddedFiles, FileItem{
			RelPath:    relpath,
			Name:       item.Name,
			IsDir:      item.IsDir,
			Size:       item.DisplaySize,
			SizeRaw:    item.SortSize,
			LastMod:    item.DisplayLastModified,
			LastModRaw: item.SortLastModified,
			Extension:  item.Ext,
			QRCode:     qrcode,
			Auth:       fileS.Pass != "" || fileS.CACert != "",
		})
	}

	var clipEntries []ClipEntry
	entries, _ := fileS.Clipboard.GetEntries()
	for _, entry := range entries {
		clipEntries = append(clipEntries, ClipEntry{
			ID:      entry.ID,
			Content: entry.Content,
			Time:    entry.Time,
		})
	}

	// http(s)://ip:port port only if not 80 and 443
	proto := "http"
	if fileS.SSL {
		proto = "https"
	}
	port := fileS.Port
	if fileS.Port == 80 || fileS.Port == 443 {
		port = 0
	}
	// prefer ip from public interface if available, otherwise use 127.0.0.1
	ip := fileS.IP
	if ip == "0.0.0.0" {
		ip = "127.0.0.1"
	}

	qrcodeRoot := GenerateQRCode(fmt.Sprintf("%s://%s:%d", proto, ip, port))
	uiData := UIData{
		GoshsVersion:    fileS.Version,
		AbsPath:         fileS.Webroot,
		QRCode:          qrcodeRoot,
		BreadcrumbParts: breadcrumbParts,
		Subdirectory:    subdirectory,
		ReadOnly:        fileS.ReadOnly,
		UploadOnly:      fileS.UploadOnly,
		NoClipboard:     fileS.NoClipboard,
		NoDelete:        fileS.NoDelete,
		CLI:             fileS.CLI,
		Embedded:        fileS.Embedded,
		Items:           fileItems,
		EmbeddedItems:   embeddedFiles,
		Clipboard:       clipEntries,
		SharedLinks:     fileS.SharedLinks,
		CSRFToken:       fileS.CSRFToken,
	}

	err := renderIndex(w, uiData)
	if err != nil {
		logger.Error(err)
	}
}

func (fileS *FileServer) constructItems(fis []fs.FileInfo, relpath string, acl configFile, r *http.Request) []item {
	var err error
	// Create empty slice
	items := make([]item, 0, len(fis))
	// Iterate over FileInfo of dir
	for _, fi := range fis {
		if fi.Name() == ".goshs" {
			logger.Debug(".goshs detected and therefore applying")
			// Do not add it to items
			continue
		}
		item := item{}
		// Need to set this up here for directories to work
		item.Name = fi.Name()
		item.Ext = strings.ToLower(utils.ReturnExt(fi.Name()))
		// Add / to name if dir
		if fi.IsDir() {
			item.Name += "/"
			item.IsDir = true
			item.Ext = ""
		}
		// Set item fields
		item.URI = url.PathEscape(filepath.Join(relpath, fi.Name()))
		// Set QR Code link
		scheme := "http"
		if r.TLS != nil {
			scheme = "https"
		}
		url := fmt.Sprintf("%s://%s/%s", scheme, r.Host, strings.TrimPrefix(item.URI, "%2F"))
		item.QRCode = template.URL(GenerateQRCode(url))
		if fileS.Pass != "" || fileS.CACert != "" {
			item.AuthEnabled = true
		} else {
			item.AuthEnabled = false
		}
		item.DisplaySize = utils.ByteCountDecimal(fi.Size())
		item.SortSize = fi.Size()
		item.DisplayLastModified = fi.ModTime().Format("Mon Jan _2 15:04:05 2006")
		item.SortLastModified = fi.ModTime().UTC().UnixMilli()
		item.ReadOnly = fileS.ReadOnly
		item.NoDelete = fileS.NoDelete
		// Check and resolve symlink
		if fi.Mode()&os.ModeSymlink != 0 {
			item.IsSymlink = true
			item.SymlinkTarget, err = os.Readlink(filepath.Join(fileS.Webroot, relpath, fi.Name()))
			if err != nil {
				logger.Errorf("resolving symlink: %+v", err)
			}
		}
		// Add to items slice
		items = append(items, item)
	}

	// Remove 'block' files from items
	if len(acl.Block) > 0 {
		for _, i := range acl.Block {
			items = removeItem(items, i)
		}
	}

	// Sort slice all lowercase
	sort.Slice(items, func(i, j int) bool {
		return strings.ToLower(items[i].Name) < strings.ToLower(items[j].Name)
	})

	return items

}

func (fileS *FileServer) processDir(w http.ResponseWriter, req *http.Request, file *os.File, relpath string, jsonOutput bool, acl configFile) {
	// Early break for invisible mode
	if fileS.Invisible {
		fileS.handleInvisible(w)
		return
	}
	// Read directory FileInfo
	fis, err := file.Readdir(-1)
	if err != nil {
		fileS.handleError(w, req, err, http.StatusNotFound)
		return
	}

	// Cleanup for Windows Paths
	relpath = strings.TrimLeft(relpath, "\\")

	// Apply Custom Auth if there is any due to file based acl
	if ok := fileS.applyCustomAuth(w, req, acl); !ok {
		fileS.handleError(w, req, err, http.StatusUnauthorized)
		return
	}

	// Construct items list
	items := fileS.constructItems(fis, relpath, acl, req)

	// Handle embedded files
	embeddedItems := fileS.constructEmbedded()

	// if ?json output json listing
	if jsonOutput {
		if fileS.Silent {
			fileS.handleError(w, req, fmt.Errorf("%s", "json output deactivated in silent mode"), http.StatusNotFound)
			return
		}
		returnJsonDirListing(w, items)
		return
	}

	if fileS.Silent {
		fileS.constructSilent(w)
	} else {
		fileS.constructDefault(w, relpath, items, embeddedItems)
	}
}

func (fs *FileServer) sendFile(w http.ResponseWriter, req *http.Request, file *os.File, acl configFile) {
	if fs.UploadOnly {
		fs.handleError(w, req, fmt.Errorf("%s", "Download not allowed due to 'upload only' option"), http.StatusForbidden)
		return
	}

	// Apply Custom Auth if there
	if acl.Auth != "" {
		if !fs.Invisible {
			w.Header().Set("WWW-Authenticate", `Basic realm="Filebased Restricted"`)
		}

		username, password, authOK := req.BasicAuth()
		if !authOK {
			fs.handleError(w, req, fmt.Errorf("%s", "not authorized"), http.StatusUnauthorized)
			return
		}

		user := strings.Split(acl.Auth, ":")[0]
		passwordHash := strings.Split(acl.Auth, ":")[1]

		if username != user || !checkPasswordHash(password, passwordHash) {
			fs.handleError(w, req, fmt.Errorf("%s", "not authorized"), http.StatusUnauthorized)
			return
		}
	}

	// Never serve .goshs file and return same error message if it was not there
	// This way it is also not possible to enumerate
	pathSplit := strings.Split(req.URL.Path, "/")
	filename := pathSplit[len(pathSplit)-1]
	if filename == ".goshs" {
		fs.handleError(w, req, fmt.Errorf("open %s: no such file or directory", file.Name()), 404)
		return
	}

	// Check if file is in block list and discard
	if slices.Contains(acl.Block, filename) {
		fs.handleError(w, req, fmt.Errorf("open %s: no such file or directory", file.Name()), 404)
		return
	}

	// Extract download parameter
	download := req.URL.Query()
	if _, ok := download["download"]; ok {
		stat, err := file.Stat()
		if err != nil {
			logger.Errorf("reading file stats for download: %+v", err)
		}
		contentDisposition := fmt.Sprintf("attachment; filename=\"%s\"; modification-date=\"%s\"", stat.Name(), stat.ModTime().Format(time.RFC1123Z))
		// Handle as download
		w.Header().Add("Content-Type", "application/octet-stream")
		w.Header().Add("Content-Disposition", contentDisposition)
		w.Header().Add("Content-Length", fmt.Sprintf("%d", stat.Size()))
		if _, err := io.Copy(w, file); err != nil {
			logger.Errorf("Error writing response to browser: %+v", err)
		}

		// Send webhook message
		logger.HandleWebhookSend(fmt.Sprintf("[WEB] File downloaded: %s", filepath.Join(fs.Webroot, req.URL.Path)), "download", fs.Webhook)

	} else {
		// Write to browser
		stat, _ := file.Stat()
		filename := stat.Name()
		contentType := utils.MimeByExtension(filename)
		w.Header().Add("Content-Type", contentType)
		w.Header().Add("Last-Modified", stat.ModTime().UTC().Format("Mon, 02 Jan 2006 15:04:05 GMT"))
		if _, err := io.Copy(w, file); err != nil {
			logger.Errorf("Error writing response to browser: %+v", err)
		}

		// Send webhook message
		logger.HandleWebhookSend(fmt.Sprintf("[WEB] File viewed: %s", filepath.Join(fs.Webroot, req.URL.Path)), "view", fs.Webhook)
	}
}

// socket will handle the socket connection
func (fs *FileServer) socket(w http.ResponseWriter, req *http.Request) {
	ok := ws.ServeWS(fs.Hub, w, req)
	if !ok {
		fs.handleError(w, req, fmt.Errorf("failed to serve websocket"), http.StatusInternalServerError)
		return
	}
}

// deleteFile will delete a file
func (fs *FileServer) deleteFile(w http.ResponseWriter, req *http.Request) {
	deletePath, err := sanitizePath(fs.Webroot, req.URL.Path)
	if err != nil {
		http.Error(w, "Cannot delete file", http.StatusBadRequest)
		body := fs.emitCollabEvent(req, http.StatusBadRequest)
		logger.LogRequest(req, http.StatusBadRequest, fs.Verbose, fs.Webhook, body)
		return
	}

	// Block deletion of the .goshs ACL file itself
	if filepath.Base(deletePath) == ".goshs" {
		fs.handleError(w, req, fmt.Errorf("cannot delete ACL file"), http.StatusForbidden)
		return
	}

	// Enforce .goshs ACL (recursive: walks up to webroot)
	aclDir := filepath.Dir(deletePath)
	acl, aclErr := fs.findEffectiveACL(aclDir)
	if aclErr != nil {
		logger.Errorf("error reading file based access config: %+v", aclErr)
	}
	if ok := fs.applyCustomAuth(w, req, acl); !ok {
		return
	}

	err = os.RemoveAll(deletePath)
	if err != nil {
		logger.Warnf("error removing %+v", deletePath)
	}

	// Send webhook message
	logger.HandleWebhookSend(fmt.Sprintf("[WEB] File deleted: %s", deletePath), "delete", fs.Webhook)

	body := fs.emitCollabEvent(req, http.StatusResetContent)
	logger.LogRequest(req, http.StatusResetContent, fs.Verbose, fs.Webhook, body)
}

// handleRedirect issues an HTTP redirect to the URL given in the ?url= query
// parameter. An optional ?status= selects the response code (must be 3xx,
// defaults to 302). Zero or more ?header= values in "Name: Value" format are
// written to the response before the redirect is sent.
func (fs *FileServer) handleRedirect(w http.ResponseWriter, req *http.Request) {
	q := req.URL.Query()

	target := q.Get("url")
	if target == "" {
		fs.handleError(w, req, fmt.Errorf("redirect: missing required 'url' parameter"), http.StatusBadRequest)
		return
	}

	// Parse and validate status code
	status := http.StatusFound // 302 default
	if s := q.Get("status"); s != "" {
		code, err := strconv.Atoi(s)
		if err != nil || code < 300 || code > 399 {
			fs.handleError(w, req, fmt.Errorf("redirect: 'status' must be a 3xx code, got %q", s), http.StatusBadRequest)
			return
		}
		status = code
	}

	// Set any caller-supplied headers ("Name: Value")
	for _, h := range q["header"] {
		parts := strings.SplitN(h, ": ", 2)
		if len(parts) != 2 || strings.TrimSpace(parts[0]) == "" {
			fs.handleError(w, req, fmt.Errorf("redirect: malformed header %q — expected 'Name: Value'", h), http.StatusBadRequest)
			return
		}
		w.Header().Set(strings.TrimSpace(parts[0]), parts[1])
	}

	http.Redirect(w, req, target, status)

	body := fs.emitCollabEvent(req, status)
	logger.LogRequest(req, status, fs.Verbose, fs.Webhook, body)
}

func (fs *FileServer) CreateShareHandler(w http.ResponseWriter, r *http.Request) {
	var downloadEntries []DownloadEntry
	var shareURLs []string
	var err error
	var stat os.FileInfo

	// If Auth is not used there is no sharing
	if fs.Pass == "" && fs.CACert == "" {
		body := fs.emitCollabEvent(r, 403)
		logger.LogRequest(r, 403, fs.Verbose, fs.Webhook, body)
		http.Error(w, "Sharing disabled when auth is disabled", http.StatusForbidden)
		return
	}

	fpath, err := sanitizePath(fs.Webroot, r.URL.Path)
	if err != nil {
		body := fs.emitCollabEvent(r, http.StatusBadRequest)
		logger.LogRequest(r, http.StatusBadRequest, fs.Verbose, fs.Webhook, body)
		http.Error(w, "Invalid path", http.StatusBadRequest)
		return
	}
	upath := strings.TrimPrefix(fpath, filepath.Clean(fs.Webroot))
	if upath == "" {
		upath = "/"
	}

	var expires time.Time
	var downloadLimit int

	now := time.Now()
	// Set expiration
	if _, ok := r.URL.Query()["expires"]; !ok {
		// Apply default of 60 minutes expiration
		expires = now.Add(time.Duration(3600 * time.Second))
	} else {
		seconds, err := strconv.Atoi(r.URL.Query()["expires"][0])
		if err != nil {
			body := fs.emitCollabEvent(r, 400)
			logger.LogRequest(r, 400, fs.Verbose, fs.Webhook, body)
			http.Error(w, "expires needs to be integer in seconds", http.StatusBadRequest)
		}
		expires = now.Add(time.Duration(seconds) * time.Second)
	}

	// Set download limit
	if _, ok := r.URL.Query()["limit"]; !ok {
		// Appy default of 1 single download
		downloadLimit = 1
	} else {
		limit, err := strconv.Atoi(r.URL.Query()["limit"][0])
		if err != nil {
			body := fs.emitCollabEvent(r, 400)
			logger.LogRequest(r, 400, fs.Verbose, fs.Webhook, body)
			http.Error(w, "limit needs to be integer", http.StatusBadRequest)
		}
		downloadLimit = limit
	}

	// Get stat for file
	stat, err = os.Stat(fpath)
	if err != nil {
		logger.Errorf("cannot get stat information for file: %s", fpath)
		http.Error(w, "cannot get stat informatio for file", 400)
	}

	// Fetch token
	token := GenerateToken()

	interfaceAdresses := make(map[string]string)
	// Return share URL
	if fs.IP == "0.0.0.0" {
		interfaceAdresses, err = utils.GetAllIPAdresses()
		if err != nil {
			logger.Errorf("There has been an error fetching the interface addresses: %+v\n", err)
		}
	} else {
		interfaceAdresses["0"] = "0.0.0.0"
	}

	protocol := "http://"
	if fs.SSL {
		protocol = "https://"
	}

	for _, ip := range interfaceAdresses {
		if fs.Port != 80 && fs.Port != 443 {
			url := fmt.Sprintf("%s%s:%d%s?token=%s", protocol, ip, fs.Port, upath, token)
			shareURLs = append(shareURLs, url)
			downloadEntry := DownloadEntry{
				DownloadURL: url,
				QRCode:      template.URL(GenerateQRCode(url)),
			}
			downloadEntries = append(downloadEntries, downloadEntry)
		} else {
			url := fmt.Sprintf("%s%s%s?token=%s", protocol, ip, upath, token)
			shareURLs = append(shareURLs, url)
			downloadEntry := DownloadEntry{
				DownloadURL: url,
				QRCode:      template.URL(GenerateQRCode(url)),
			}
			downloadEntries = append(downloadEntries, downloadEntry)
		}
	}

	sl := SharedLink{
		FilePath:        upath,
		DownloadEntries: downloadEntries,
		IsDir:           stat.IsDir(),
		Expires:         expires,
		Downloaded:      0,
		DownloadLimit:   downloadLimit,
	}

	// Add to map
	fs.SharedLinks[token] = sl

	body := fs.emitCollabEvent(r, http.StatusOK)
	logger.LogRequest(r, http.StatusOK, fs.Verbose, fs.Webhook, body)
	logger.Debugf("A file was shared: %s", shareURLs[0])

	response := map[string][]string{
		"urls": shareURLs,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)

	err = json.NewEncoder(w).Encode(response)
	if err != nil {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

}

func (fs *FileServer) ShareHandler(w http.ResponseWriter, r *http.Request) {
	if _, token := r.URL.Query()["token"]; !token {
		http.Error(w, "error in token handler", 400)
	}

	token := r.URL.Query()["token"][0]
	entry, ok := fs.SharedLinks[token]
	if !ok || time.Now().After(entry.Expires) {
		http.NotFound(w, r)
		return
	}

	file, err := os.Open(filepath.Join(fs.Webroot, entry.FilePath))
	if err != nil {
		logger.Errorf("error opening shared file: %s", entry.FilePath)
	}

	// Only send if download limit not reached
	if entry.DownloadLimit > 0 || entry.DownloadLimit == -1 {
		if entry.IsDir {
			// bulkDownload folder as zip
			// GET /?file=%252Ffilepath&bulk=true
			q := r.URL.Query()
			q.Set("file", entry.FilePath)
			q.Set("bulk", "true")
			r.URL.RawQuery = q.Encode()

			fs.bulkDownload(w, r)
		} else {
			fs.sendFile(w, r, file, configFile{})
		}
	} else {
		http.NotFound(w, r)
		return
	}

	// Subtract from download limit
	entry.Downloaded++

	fs.SharedLinks[token] = entry
	if fs.SharedLinks[token].DownloadLimit != -1 {
		if fs.SharedLinks[token].Downloaded >= fs.SharedLinks[token].DownloadLimit {
			// Remove the share link from map to keep it clean
			delete(fs.SharedLinks, token)
		}
	}
}

func (fs *FileServer) DeleteShareHandler(w http.ResponseWriter, r *http.Request) {
	if _, token := r.URL.Query()["token"]; !token {
		http.Error(w, "error in token delete handler", http.StatusBadRequest)
	}

	token := r.URL.Query().Get("token")
	delete(fs.SharedLinks, token)

	body := fs.emitCollabEvent(r, http.StatusNoContent)
	logger.LogRequest(r, http.StatusNoContent, fs.Verbose, fs.Webhook, body)

	w.WriteHeader(204)
	_, err := w.Write([]byte("shared link deleted successfully"))
	if err != nil {
		logger.Error(err)
	}
}

func (fs *FileServer) handleMkdir(w http.ResponseWriter, r *http.Request) {
	if !fs.Invisible {
		// if not read only or upload only create directory from mkdir query param
		if fs.ReadOnly || fs.UploadOnly {
			http.Error(w, "read only or upload only mode", http.StatusForbidden)
			return
		}

		// Get and sanitize path
		finalPath, err := sanitizePath(fs.Webroot, r.URL.Path)
		if err != nil {
			http.Error(w, "Invalid path", http.StatusBadRequest)
			return
		}

		// Enforce .goshs ACL (recursive: walks up to webroot)
		parentDir := filepath.Dir(finalPath)
		acl, aclErr := fs.findEffectiveACL(parentDir)
		if aclErr != nil {
			logger.Errorf("error reading file based access config: %+v", aclErr)
		}
		if ok := fs.applyCustomAuth(w, r, acl); !ok {
			return
		}

		// Create directory
		err = os.MkdirAll(finalPath, 0755)
		if err != nil {
			body := fs.emitCollabEvent(r, http.StatusInternalServerError)
			logger.LogRequest(r, http.StatusInternalServerError, fs.Verbose, fs.Webhook, body)
			logger.Errorf("Error creating directory %s: %+v", finalPath, err)
			return
		}

		body := fs.emitCollabEvent(r, http.StatusCreated)
		logger.LogRequest(r, http.StatusCreated, fs.Verbose, fs.Webhook, body)
		// Send success response
		w.WriteHeader(http.StatusCreated)
		_, err = w.Write([]byte("directory created successfully"))
		if err != nil {
			logger.Error(err)
		}
		return
	}

	fs.handleInvisible(w)
}

func (fs *FileServer) handleSMTPAttachment(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	if id == "" {
		body := fs.emitCollabEvent(r, http.StatusNotFound)
		logger.LogRequest(r, http.StatusNotFound, fs.Verbose, fs.Webhook, body)
		http.NotFound(w, r)
		return
	}

	a, ok := smtpattach.Get(id)
	if !ok {
		http.Error(w, "attachment not found or expired", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", a.ContentType)
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, a.Filename))
	w.Header().Set("Content-Length", fmt.Sprintf("%d", a.Size))
	_, err := w.Write(a.Data)
	if err != nil {
		logger.Error(err)
	}
}
