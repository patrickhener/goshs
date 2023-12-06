package httpserver

import (
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/patrickhener/goshs/logger"
	"github.com/patrickhener/goshs/utils"
	"github.com/patrickhener/goshs/ws"
)

// static will give static content for style and function
func (fs *FileServer) static(w http.ResponseWriter, req *http.Request) {
	// Construct static path to file
	path := "static" + req.URL.Path
	// Load file with parcello
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

// handler is the function which actually handles dir or file retrieval
func (fs *FileServer) handler(w http.ResponseWriter, req *http.Request) {
	// Early break for /?ws, /?cbDown, /?bulk and /?static /?delete
	if _, ok := req.URL.Query()["ws"]; ok {
		fs.socket(w, req)
		return
	}
	if _, ok := req.URL.Query()["cbDown"]; ok {
		fs.cbDown(w, req)
		return
	}
	if _, ok := req.URL.Query()["bulk"]; ok {
		fs.bulkDownload(w, req)
		return
	}
	if _, ok := req.URL.Query()["static"]; ok {
		fs.static(w, req)
		return
	}

	if _, ok := req.URL.Query()["delete"]; ok {
		if !fs.ReadOnly && !fs.UploadOnly {
			fs.deleteFile(w, req)
			return
		}
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
	// as we want a file inclusion here
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
	logger.LogRequest(req, http.StatusOK, fs.Verbose)

	// Switch and check if dir
	stat, _ := file.Stat()
	if stat.IsDir() {
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
	} else {
		// If it is a file we need to check for .goshs one directory up
		parent := filepath.Dir(file.Name())
		config, err := fs.findSpecialFile(parent)
		if err != nil {
			logger.Errorf("error reading file based access config: %+v", err)
		}
		fs.sendFile(w, req, file, config)
	}
}

func (fs *FileServer) processDir(w http.ResponseWriter, req *http.Request, file *os.File, relpath string, jsonOutput bool, acl configFile) {
	// Read directory FileInfo
	fis, err := file.Readdir(-1)
	if err != nil {
		fs.handleError(w, req, err, http.StatusNotFound)
		return
	}

	// Cleanup for Windows Paths
	relpath = strings.TrimLeft(relpath, "\\")

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
		item.DisplaySize = utils.ByteCountDecimal(fi.Size())
		item.SortSize = fi.Size()
		item.DisplayLastModified = fi.ModTime().Format("Mon Jan _2 15:04:05 2006")
		item.SortLastModified = fi.ModTime().UTC().UnixMilli()
		item.ReadOnly = fs.ReadOnly
		// Check and resolve symlink
		if fi.Mode()&os.ModeSymlink != 0 {
			item.IsSymlink = true
			item.SymlinkTarget, err = os.Readlink(path.Join(fs.Webroot, relpath, fi.Name()))
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

	// if ?json output json listing
	if jsonOutput {
		w.Header().Add("Content-Type", "application/json")
		resJson, err := json.Marshal(items)
		if err != nil {
			logger.Errorf("error marshaling items to json: %+v", err)
		}
		_, err = w.Write(resJson)
		if err != nil {
			logger.Errorf("error writing json as response: %+v", err)
		}
		return
	}

	if fs.Silent {
		tem := &baseTemplate{
			GoshsVersion: fs.Version,
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

	} else {
		// Windows upload compatibility
		if relpath == "\\" {
			relpath = "/"
		}

		// Construct directory for template
		d := &directory{
			RelPath: relpath,
			AbsPath: filepath.Join(fs.Webroot, relpath),
			Content: items,
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

		// upload only mode empty directory
		if fs.UploadOnly {
			d = &directory{}
		}

		// Construct template
		tem := &baseTemplate{
			Directory:    d,
			GoshsVersion: fs.Version,
			Clipboard:    fs.Clipboard,
			CLI:          fs.CLI,
		}

		files := []string{"static/templates/index.html", "static/templates/header.tmpl", "static/templates/footer.tmpl", "static/templates/scripts_index.tmpl"}

		t, err := template.ParseFS(static, files...)
		if err != nil {
			logger.Errorf("Error parsing templates: %+v", err)
		}

		if err := t.Execute(w, tem); err != nil {
			logger.Errorf("Error executing template: %+v", err)
		}
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

	deletePath := filepath.Join(fs.Webroot, upath)

	err := os.RemoveAll(deletePath)
	if err != nil {
		logger.Warnf("error removing %+v", deletePath)
	}

	logger.LogRequest(req, http.StatusResetContent, fs.Verbose)
}
