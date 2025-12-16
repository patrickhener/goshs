package httpserver

import (
	"archive/zip"
	"bytes"
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

// put handles the PUT request to upload files
func (fs *FileServer) put(w http.ResponseWriter, req *http.Request) {
	if fs.ReadOnly {
		if fs.Invisible {
			fs.handleInvisible(w)
			return
		}
		fs.handleError(w, req, fmt.Errorf("%s", "Upload not allowed due to 'read only' option"), http.StatusForbidden)
		return
	}
	// Get url so you can extract Headline and title
	upath := req.URL.Path

	filename := strings.Split(upath, "/")
	outName := filename[len(filename)-1]

	// construct target path
	targetpath := strings.Split(upath, "/")
	targetpath = targetpath[:len(targetpath)-1]
	target := strings.Join(targetpath, "/")

	savepath := fmt.Sprintf("%s%s/%s", fs.UploadFolder, target, outName)

	body, err := io.ReadAll(req.Body)
	if err != nil {
		logger.Errorf("unable to read PUT request body: %+v", err)
		return
	}
	defer req.Body.Close()

	// Create file to write to
	// disable G304 (CWE-22): Potential file inclusion via variable
	// #nosec G304
	if _, err := os.Create(savepath); err != nil {
		logger.Errorf("Not able to create file on disk")
		fs.handleError(w, req, err, http.StatusInternalServerError)
	}

	reader := bytes.NewReader(body)

	osFile, err := os.OpenFile(savepath, os.O_WRONLY|os.O_CREATE, os.ModePerm)
	if err != nil {
		logger.Warnf("Error opening file: %+v", err)
	}

	if _, err := io.Copy(osFile, reader); err != nil {
		logger.Errorf("Error writing file %s to disk: %+v", savepath, err)
		fs.handleError(w, req, err, http.StatusInternalServerError)
	}

	// Log request
	logger.LogRequest(req, http.StatusOK, fs.Verbose, fs.Webhook)
}

// upload handles the POST request to upload files
func (fs *FileServer) upload(w http.ResponseWriter, req *http.Request) {
	if fs.ReadOnly {
		if fs.Invisible {
			fs.handleInvisible(w)
			return
		}
		fs.handleError(w, req, fmt.Errorf("%s", "Upload not allowed due to 'read only' option"), http.StatusForbidden)
		return
	}
	// Get url so you can extract Headline and title
	upath := req.URL.Path

	// construct target path
	targetpath := strings.Split(upath, "/")
	targetpath = targetpath[:len(targetpath)-1]
	target := strings.Join(targetpath, "/")

	reader, err := req.MultipartReader()
	if err != nil {
		logger.Errorf("reading multipart request: %+v", err)
		return
	}

	for {
		part, err := reader.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			logger.Errorf("reading multipart part: %+v", err)
			return
		}
		if part.FileName() == "" {
			continue // skip form fields
		}

		// sanitize filename (No path traversal)
		filenameSlice := strings.Split(part.FileName(), "/")
		filenameClean := filenameSlice[len(filenameSlice)-1]

		// Prepare destination file paths
		finalPath := fmt.Sprintf("%s%s/%s", fs.UploadFolder, target, filenameClean)
		tempPath := finalPath + "~"

		// Create temp file
		dst, err := os.Create(tempPath)
		if err != nil {
			logger.Errorf("creating temp file: %+v", err)
			return
		}

		// Write in chunks
		buf := make([]byte, chunkSize)
		var totalWritten int64
		for {
			n, readErr := part.Read(buf)
			if n > 0 {
				written, writeErr := dst.Write(buf[:n])
				if writeErr != nil || written != n {
					dst.Close()
					os.Remove(tempPath)
					logger.Errorf("writing file to disk: %+v", writeErr)
					return
				}
				totalWritten += int64(written)
			}
			if readErr == io.EOF {
				break
			}
			if readErr != nil {
				dst.Close()
				os.Remove(tempPath)
				logger.Errorf("reading uploaded data: %+v", readErr)
				return
			}
		}

		// Ensure file is flushed and closed
		if err := dst.Sync(); err != nil {
			dst.Close()
			os.Remove(tempPath)
			logger.Errorf("syncing file: %+v", err)
			return
		}
		if err := dst.Close(); err != nil {
			os.Remove(tempPath)
			logger.Errorf("closing file: %+v", err)
			return
		}

		// Atomically rename to final path
		if err := os.Rename(tempPath, finalPath); err != nil {
			logger.Errorf("renaming file: %+v", err)
			return
		}

		// Webhook
		logger.HandleWebhookSend(fmt.Sprintf("[WEB] File uploaded: %s", finalPath), "upload", fs.Webhook)
	}

	// Log request
	logger.LogRequest(req, http.StatusOK, fs.Verbose, fs.Webhook)

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
		header := &zip.FileHeader{
			Name:     zippath[1:],
			Method:   zip.Deflate,
			Modified: info.ModTime(),
		}
		f, err := resultZip.CreateHeader(header)
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
	} else {
		logger.LogRequest(req, http.StatusOK, fs.Verbose, fs.Webhook)
	}
}
