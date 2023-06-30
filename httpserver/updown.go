package httpserver

import (
	"archive/zip"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/patrickhener/goshs/logger"
)

// upload handles the POST request to upload files
func (fs *FileServer) upload(w http.ResponseWriter, req *http.Request) {
	if fs.ReadOnly {
		fs.handleError(w, req, fmt.Errorf("%s", "Upload not allowed due to 'read only' option"), http.StatusForbidden)
		return
	}
	// Get url so you can extract Headline and title
	upath := req.URL.Path

	// construct target path
	targetpath := strings.Split(upath, "/")
	targetpath = targetpath[:len(targetpath)-1]
	target := strings.Join(targetpath, "/")

	// Parse request
	// Limit memory usage to 16MB
	if err := req.ParseMultipartForm(1 << 24); err != nil {
		logger.Errorf("parsing multipart request: %+v", err)
		return
	}

	// Get ref to the parsed multipart form
	m := req.MultipartForm

	// Remove all temporary files when we return
	defer m.RemoveAll()

	for _, f := range m.File {
		file, err := f[0].Open()
		if err != nil {
			logger.Errorf("retrieving the file: %+v\n", err)
		}
		defer file.Close()

		filename := f[0].Filename

		// Sanitize filename (No path traversal)
		filenameSlice := strings.Split(filename, "/")
		filenameClean := filenameSlice[len(filenameSlice)-1]

		// Construct absolute savepath
		savepath := fmt.Sprintf("%s%s/%s", fs.Webroot, target, filenameClean)

		// Create file to write to
		// disable G304 (CWE-22): Potential file inclusion via variable
		// as we want a file inclusion here
		// #nosec G304
		if _, err := os.Create(savepath); err != nil {
			logger.Errorf("Not able to create file on disk")
			fs.handleError(w, req, err, http.StatusInternalServerError)
		}

		// Write file to disk 16MB at a time
		buffer := make([]byte, 1 << 24)

		osFile, err := os.OpenFile(savepath, os.O_WRONLY | os.O_CREATE, os.ModePerm)
		defer osFile.Close()

		for {
			// Read file from post body
			nBytes, readErr := file.Read(buffer)
			if readErr != nil && readErr != io.EOF {
				logger.Errorf("Not able to read file from request")
				fs.handleError(w, req, err, http.StatusInternalServerError)
			}

			// Write file to disk
			if _, err := osFile.Write(buffer[:nBytes]); err != nil {
				logger.Errorf("Not able to write file to disk")
				fs.handleError(w, req, err, http.StatusInternalServerError)
			}

			if readErr == io.EOF {
				break
			}
		}
	}

	// Log request
	logger.LogRequest(req, http.StatusOK, fs.Verbose)

	// Redirect back from where we came from
	http.Redirect(w, req, target, http.StatusSeeOther)
}

// bulkDownload will provide zip archived download bundle of multiple selected files
func (fs *FileServer) bulkDownload(w http.ResponseWriter, req *http.Request) {
	if fs.UploadOnly {
		fs.handleError(w, req, fmt.Errorf("%s", "Bulk download not allowed due to 'upload only' option"), http.StatusForbidden)
		return
	}
	// make slice and query files from request
	var filesCleaned []string
	files := req.URL.Query()["file"]

	// Handle if no files are selected
	if len(files) == 0 {
		fs.handleError(w, req, errors.New("you need to select a file before you can download a zip archive"), 404)
	}

	// Clean file paths and fill slice
	// Also sanitize path (No path traversal)
	// If .. in single string just skip file
	for _, file := range files {
		fileCleaned, _ := url.QueryUnescape(file)
		if strings.Contains(fileCleaned, "..") {
			// Just skip this file
			continue
		}
		filesCleaned = append(filesCleaned, fileCleaned)
	}

	// Construct filename to download
	filename := fmt.Sprintf("%+v_goshs_download.zip", int32(time.Now().Unix()))

	// Set header and serve file
	contentDispo := fmt.Sprintf("attachment; filename=\"%s\"", filename)
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", contentDispo)
	w.Header().Set("Content-Transfer-Encoding", "binary")
	w.Header().Set("Expires", "0")

	// Define Zip writer
	resultZip := zip.NewWriter(w)
	defer resultZip.Close()

	// Path walker for recursion
	walker := func(filepath string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}

		// disable G304 (CWE-22): Potential file inclusion via variable
		// as we want a file inclusion here
		// #nosec G304
		file, err := os.Open(filepath)
		if err != nil {
			return err
		}
		// disable G307 (CWE-703): Deferring unsafe method "Close" on type "*os.File"
		// #nosec G307
		defer file.Close()

		// filepath is fs.Webroot + file relative path
		// this would result in a lot of nested folders
		// so we are stripping fs.Webroot again from the structure of the zip file
		// Leaving us with the relative path of the file
		zippath := strings.ReplaceAll(filepath, fs.Webroot, "")
		f, err := resultZip.Create(zippath[1:])
		if err != nil {
			return err
		}

		_, err = io.Copy(f, file)
		if err != nil {
			return err
		}

		return nil
	}

	// Loop over files and add to zip
	for _, file := range filesCleaned {
		err := filepath.Walk(path.Join(fs.Webroot, file), walker)
		if err != nil {
			logger.Errorf("creating zip file: %+v", err)
		}
	}

	// Close Zip Writer and Flush to http.ResponseWriter
	if err := resultZip.Close(); err != nil {
		logger.Error(err)
	}
}
