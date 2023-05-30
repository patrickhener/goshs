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
	// Early break for /?ws, /?cbDown, /?bulk and /?static
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
		fs.processDir(w, req, file, upath, json)
	} else {
		fs.sendFile(w, req, file)
	}
}

func (fs *FileServer) processDir(w http.ResponseWriter, req *http.Request, file *os.File, relpath string, jsonOutput bool) {
	// Read directory FileInfo
	fis, err := file.Readdir(-1)
	if err != nil {
		fs.handleError(w, req, err, http.StatusNotFound)
		return
	}

	// Cleanup for Windows Paths
	relpath = strings.TrimLeft(relpath, "\\")

	// Create empty slice
	items := make([]item, 0, len(fis))
	// Iterate over FileInfo of dir
	for _, fi := range fis {
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
		item.SortLastModified = fi.ModTime()
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
		silentFile, err := static.ReadFile("static/templates/silent.html")
		if err != nil {
			logger.Errorf("opening embedded file: %+v", err)
		}

		tem := &silentTemplate{
			GoshsVersion: fs.Version,
		}

		t := template.New("silent")

		if _, err := t.Parse(string(silentFile)); err != nil {
			logger.Errorf("Error parsing template: %+v", err)
		}
		if err := t.Execute(w, tem); err != nil {
			logger.Errorf("Error executing template: %+v", err)
		}

	} else {
		// Template parsing and writing to browser
		indexFile, err := static.ReadFile("static/templates/index.html")
		if err != nil {
			logger.Errorf("opening embedded file: %+v", err)
		}

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
		tem := &indexTemplate{
			Directory:    d,
			GoshsVersion: fs.Version,
			Clipboard:    fs.Clipboard,
			CLI:          fs.CLI,
		}

		t := template.New("index")
		if _, err := t.Parse(string(indexFile)); err != nil {
			logger.Errorf("Error parsing template: %+v", err)
		}
		if err := t.Execute(w, tem); err != nil {
			logger.Errorf("Error executing template: %+v", err)
		}
	}
}

func (fs *FileServer) sendFile(w http.ResponseWriter, req *http.Request, file *os.File) {
	if fs.UploadOnly {
		fs.handleError(w, req, fmt.Errorf("%s", "Download not allowed due to 'upload only' option"), http.StatusForbidden)
		return
	}
	// Extract download parameter
	download := req.URL.Query()
	if _, ok := download["download"]; ok {
		stat, err := file.Stat()
		if err != nil {
			logger.Errorf("reading file stats for download: %+v", err)
		}
		contentDisposition := fmt.Sprintf("attachment; filename=\"%s\"", stat.Name())
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
		if _, err := io.Copy(w, file); err != nil {
			logger.Errorf("Error writing response to browser: %+v", err)
		}
	}
}

// socket will handle the socket connection
func (fs *FileServer) socket(w http.ResponseWriter, req *http.Request) {
	ws.ServeWS(fs.Hub, w, req)
}
