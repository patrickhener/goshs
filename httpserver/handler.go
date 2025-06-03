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
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/patrickhener/goshs/logger"
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

	for _, name := range parentConfig.Block {
		if name == fmt.Sprintf("%s/", foldername) {
			fs.handleError(w, req, fmt.Errorf("open %s: no such file or directory", file.Name()), 404)
			return
		}
	}

	// Check if the dir has a .goshs ACL file
	config, err := fs.findSpecialFile(file.Name())
	if err != nil {
		logger.Errorf("error reading file based access config: %+v", err)
	}
	fs.processDir(w, req, file, upath, json, config)
}

func (fs *FileServer) doFile(file *os.File, w http.ResponseWriter, req *http.Request) {
	// If it is a file we need to check for .goshs one directory up
	parent := filepath.Dir(file.Name())
	config, err := fs.findSpecialFile(parent)
	if err != nil {
		logger.Errorf("error reading file based access config: %+v", err)
	}
	fs.sendFile(w, req, file, config)
}

func (fs *FileServer) earlyBreakParameters(w http.ResponseWriter, req *http.Request) bool {
	if _, ok := req.URL.Query()["ws"]; ok {
		fs.socket(w, req)
		return true
	}
	if _, ok := req.URL.Query()["cbDown"]; ok {
		if !fs.NoClipboard {
			fs.cbDown(w, req)
			return true
		}
	}
	if _, ok := req.URL.Query()["bulk"]; ok {
		fs.bulkDownload(w, req)
		return true
	}
	if _, ok := req.URL.Query()["static"]; ok {
		fs.static(w, req)
		return true
	}
	if _, ok := req.URL.Query()["embedded"]; ok {
		if err := fs.embedded(w, req); err != nil {
			logger.LogRequest(req, http.StatusNotFound, fs.Verbose, fs.Webhook)
			return true
		}
		logger.LogRequest(req, http.StatusOK, fs.Verbose, fs.Webhook)
		return true
	}
	if _, ok := req.URL.Query()["delete"]; ok {
		if !fs.ReadOnly && !fs.UploadOnly && !fs.NoDelete {
			fs.deleteFile(w, req)
			return true
		} else {
			fs.handleError(w, req, fmt.Errorf("delete not allowed"), http.StatusForbidden)
			return true
		}
	}
	if _, ok := req.URL.Query()["share"]; ok {
		fs.CreateShareHandler(w, req)
		return true
	}
	if _, ok := req.URL.Query()["token"]; ok {
		switch req.Method {
		case http.MethodGet:
			fs.ShareHandler(w, req)
		case http.MethodDelete:
			fs.DeleteShareHandler(w, req)
		default:
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

	// Get url so you can extract Headline and title
	upath := req.URL.Path

	// Ignore default browser call to /favicon.ico
	if upath == "/favicon.ico" {
		return
	}

	upath = path.Clean(upath)
	upath = filepath.Clean(upath)

	// Define absolute path
	open := fs.Webroot + upath

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
	logger.LogRequest(req, http.StatusOK, fs.Verbose, fs.Webhook)

	// Switch and check if dir
	stat, _ := file.Stat()
	if stat.IsDir() {
		fs.doDir(file, w, req, upath, json)
	} else {
		fs.doFile(file, w, req)
	}
}

// Applies custom auth for file based acls
func (fileS *FileServer) applyCustomAuth(w http.ResponseWriter, req *http.Request, acl configFile) {
	if acl.Auth != "" {
		w.Header().Set("WWW-Authenticate", `Basic realm="Filebased Restricted"`)

		username, password, authOK := req.BasicAuth()
		if !authOK {
			fileS.handleError(w, req, fmt.Errorf("%s", "not authorized"), http.StatusUnauthorized)
			return
		}

		user := strings.Split(acl.Auth, ":")[0]
		passwordHash := strings.Split(acl.Auth, ":")[1]

		if username != user || !checkPasswordHash(password, passwordHash) {
			fileS.handleError(w, req, fmt.Errorf("%s", "not authorized"), http.StatusUnauthorized)
			return
		}
	}
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
		Directory:    &directory{AbsPath: "silent mode"},
	}

	files := []string{"static/templates/silent.html", "static/templates/header.tmpl", "static/templates/footer.tmpl"}

	t, err := template.ParseFS(static, files...)
	if err != nil {
		logger.Errorf("Error parsing templates: %+v", err)
	}

	if err := t.Execute(w, tem); err != nil {
		logger.Errorf("Error executing template: %+v", err)
	}
}

func (fileS *FileServer) constructDefault(w http.ResponseWriter, relpath string, items []item, embeddedItems []item) {
	// Windows upload compatibility
	if relpath == "\\" {
		relpath = "/"
	}

	// Construct directory for template
	d := &directory{
		RelPath: relpath,
		AbsPath: filepath.Join(fileS.Webroot, relpath),
		Content: items,
	}
	if fileS.Pass != "" || fileS.CACert != "" {
		// Auth -> Sharelinks on
		d.AuthEnabled = true
	} else {
		d.AuthEnabled = false
	}
	if relpath != "/" {
		d.IsSubdirectory = true
		pathSlice := strings.Split(relpath, "/")
		if len(pathSlice) > 2 {
			pathSlice = pathSlice[1 : len(pathSlice)-1]

			var backString string
			for _, part := range pathSlice {
				backString += "/" + part
			}
			d.Back = backString
		} else {
			d.Back = "/"
		}
	} else {
		d.IsSubdirectory = false
	}

	// Construct directory for embedded files
	e := &directory{
		RelPath: fileS.Webroot,
		AbsPath: fileS.Webroot,
		Content: embeddedItems,
	}

	// upload only mode empty directory
	if fileS.UploadOnly {
		d = &directory{}
		e = &directory{}
	}

	// Construct template
	tem := &baseTemplate{
		Directory:       d,
		GoshsVersion:    fileS.Version,
		Clipboard:       fileS.Clipboard,
		CLI:             fileS.CLI,
		Embedded:        fileS.Embedded,
		EmbeddedContent: e,
		NoClipboard:     fileS.NoClipboard,
		NoDelete:        fileS.NoDelete,
		SharedLinks:     fileS.SharedLinks,
	}

	files := []string{"static/templates/index.html", "static/templates/header.tmpl", "static/templates/footer.tmpl", "static/templates/scripts_index.tmpl"}

	var err error

	funcMap := template.FuncMap{
		"downloadLimitDisplay": func(l int) string {
			if l == -1 {
				return "disabled"
			}
			return strconv.Itoa(l)
		},
		"formatTime": func(t time.Time) string {
			return t.Format("2006-01-02 15:04:05")
		},
	}

	t := template.New("root").Funcs(funcMap)

	t, err = t.ParseFS(static, files...)
	if err != nil {
		logger.Errorf("Error parsing templates: %+v", err)
	}

	if err := t.ExecuteTemplate(w, "index.html", tem); err != nil {
		logger.Errorf("Error executing template: %+v", err)
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
		item.URI = url.PathEscape(path.Join(relpath, fi.Name()))
		// Set QR Code link
		scheme := "http"
		if r.TLS != nil {
			scheme = "https"
		}
		url := fmt.Sprintf("%s://%s%s", scheme, r.Host, item.URI)
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
			item.SymlinkTarget, err = os.Readlink(path.Join(fileS.Webroot, relpath, fi.Name()))
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
	// Read directory FileInfo
	fis, err := file.Readdir(-1)
	if err != nil {
		fileS.handleError(w, req, err, http.StatusNotFound)
		return
	}

	// Cleanup for Windows Paths
	relpath = strings.TrimLeft(relpath, "\\")

	// Apply Custom Auth if there is any due to file based acl
	fileS.applyCustomAuth(w, req, acl)

	// Construct items list
	items := fileS.constructItems(fis, relpath, acl, req)

	// Handle embedded files
	embeddedItems := fileS.constructEmbedded()

	// if ?json output json listing
	if jsonOutput {
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
		w.Header().Set("WWW-Authenticate", `Basic realm="Filebased Restricted"`)

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
	for _, name := range acl.Block {
		if name == filename {
			fs.handleError(w, req, fmt.Errorf("open %s: no such file or directory", file.Name()), 404)
			return
		}
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
	ws.ServeWS(fs.Hub, w, req)
}

// deleteFile will delete a file
func (fs *FileServer) deleteFile(w http.ResponseWriter, req *http.Request) {
	// Get path
	upath := req.URL.Path
	upath = path.Clean(upath)
	upath = filepath.Clean(upath)

	fileCleaned, _ := url.QueryUnescape(upath)
	if strings.Contains(fileCleaned, "..") {
		w.WriteHeader(500)
		_, err := w.Write([]byte("Cannot delete file"))
		if err != nil {
			logger.Errorf("error writing answer to client: %+v", err)
		}
	}

	deletePath := filepath.Join(fs.Webroot, fileCleaned)

	err := os.RemoveAll(deletePath)
	if err != nil {
		logger.Warnf("error removing %+v", deletePath)
	}

	// Send webhook message
	logger.HandleWebhookSend(fmt.Sprintf("[WEB] File deleted: %s", deletePath), "delete", fs.Webhook)

	logger.LogRequest(req, http.StatusResetContent, fs.Verbose, fs.Webhook)
}

func (fs *FileServer) CreateShareHandler(w http.ResponseWriter, r *http.Request) {
	var downloadEntries []DownloadEntry
	var shareURLs []string
	var err error
	var stat os.FileInfo

	// If Auth is not used there is no sharing
	if fs.Pass == "" && fs.CACert == "" {
		logger.LogRequest(r, 403, fs.Verbose, fs.Webhook)
		http.Error(w, "Sharing disabled when auth is disabled", http.StatusForbidden)
		return
	}

	upath := r.URL.Path
	upath = path.Clean(upath)
	upath = filepath.Clean(upath)

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
			logger.LogRequest(r, 400, fs.Verbose, fs.Webhook)
			http.Error(w, "expires needs to be integer in seconds", http.StatusBadRequest)
		}
		expires = now.Add(time.Duration(seconds * int(time.Second)))
	}

	// Set download limit
	if _, ok := r.URL.Query()["limit"]; !ok {
		// Appy default of 1 single download
		downloadLimit = 1
	} else {
		limit, err := strconv.Atoi(r.URL.Query()["limit"][0])
		if err != nil {
			logger.LogRequest(r, 400, fs.Verbose, fs.Webhook)
			http.Error(w, "limit needs to be integer", http.StatusBadRequest)
		}
		downloadLimit = limit
	}

	// Get stat for file
	fpath := filepath.Join(fs.Webroot, upath)
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
		DownloadLimit:   downloadLimit,
	}

	// Add to map
	fs.SharedLinks[token] = sl

	logger.LogRequest(r, http.StatusOK, fs.Verbose, fs.Webhook)
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

	// Substract from download limit
	if entry.DownloadLimit > 0 {
		entry.DownloadLimit--
	}

	fs.SharedLinks[token] = entry
	if fs.SharedLinks[token].DownloadLimit == 0 {
		// Remove the share link from map to keep it clean
		delete(fs.SharedLinks, token)
	}
}

func (fs *FileServer) DeleteShareHandler(w http.ResponseWriter, r *http.Request) {
	if _, token := r.URL.Query()["token"]; !token {
		http.Error(w, "error in token delete handler", 400)
	}

	token := r.URL.Query().Get("token")
	delete(fs.SharedLinks, token)

	logger.LogRequest(r, http.StatusNoContent, fs.Verbose, fs.Webhook)

	w.WriteHeader(204)
	w.Write([]byte("shared link deleted successfully"))
}
