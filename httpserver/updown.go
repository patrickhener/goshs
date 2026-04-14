package httpserver

import (
	"archive/zip"
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/patrickhener/goshs/v2/logger"
)

// put handles the PUT request to upload files
func (fs *FileServer) put(w http.ResponseWriter, req *http.Request) {
	if fs.ReadOnly {
		fs.handleError(w, req, fmt.Errorf("%s", "Upload not allowed due to 'read only' option"), http.StatusForbidden)
		return
	}
	savepath, err := sanitizePath(fs.UploadFolder, req.URL.Path)
	if err != nil {
		fs.handleError(w, req, err, http.StatusBadRequest)
		return
	}

	// Block overwriting the .goshs ACL file
	if filepath.Base(savepath) == ".goshs" {
		fs.handleError(w, req, fmt.Errorf("cannot overwrite ACL file"), http.StatusForbidden)
		return
	}

	// Enforce .goshs ACL (recursive: walks up to webroot)
	targetDir := filepath.Dir(savepath)
	acl, aclErr := fs.findEffectiveACL(targetDir)
	if aclErr != nil {
		logger.Errorf("error reading file based access config: %+v", aclErr)
	}
	if ok := fs.applyCustomAuth(w, req, acl); !ok {
		return
	}

	body, err := io.ReadAll(req.Body)
	if err != nil {
		logger.Errorf("unable to read PUT request body: %+v", err)
		return
	}
	defer req.Body.Close()

	reader := bytes.NewReader(body)

	// disable G304 (CWE-22): Potential file inclusion via variable
	// #nosec G304
	osFile, err := os.OpenFile(savepath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		logger.Errorf("Error opening file: %+v", err)
		fs.handleError(w, req, err, http.StatusInternalServerError)
		return
	}
	defer osFile.Close()

	if _, err := io.Copy(osFile, reader); err != nil {
		logger.Errorf("Error writing file %s to disk: %+v", savepath, err)
		fs.handleError(w, req, err, http.StatusInternalServerError)
		return
	}

	// Log request
	_ = fs.emitCollabEvent(req, http.StatusOK)
	logger.LogRequest(req, http.StatusOK, fs.Verbose, fs.Webhook, body)
}

// upload handles the POST request to upload files
func (fs *FileServer) upload(w http.ResponseWriter, req *http.Request) {
	if !fs.checkCSRF(w, req) {
		return
	}
	if fs.ReadOnly {
		fs.handleError(w, req, fmt.Errorf("%s", "Upload not allowed due to 'read only' option"), http.StatusForbidden)
		return
	}
	// Derive and sanitize the target directory (strip trailing "/upload" from URL).
	upathDir := strings.TrimSuffix(req.URL.Path, "/upload")
	targetDir, err := sanitizePath(fs.UploadFolder, upathDir)
	if err != nil {
		fs.handleError(w, req, err, http.StatusBadRequest)
		return
	}

	// Enforce .goshs ACL (recursive: walks up to webroot)
	acl, aclErr := fs.findEffectiveACL(targetDir)
	if aclErr != nil {
		logger.Errorf("error reading file based access config: %+v", aclErr)
	}
	if ok := fs.applyCustomAuth(w, req, acl); !ok {
		return
	}

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

		// Block overwriting the .goshs ACL file
		if filenameClean == ".goshs" {
			logger.Warnf("blocked attempt to upload file named .goshs")
			continue
		}

		// Prepare destination file paths
		finalPath := filepath.Join(targetDir, filenameClean)
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
	body := fs.emitCollabEvent(req, http.StatusOK)
	logger.LogRequest(req, http.StatusOK, fs.Verbose, fs.Webhook, body)

	// Redirect back from where we came from
	http.Redirect(w, req, upathDir, http.StatusSeeOther)
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

	// Validate each path and collect absolute paths; skip any traversal attempts
	for _, file := range files {
		absPath, err := sanitizePath(fs.Webroot, file)
		if err != nil {
			continue
		}
		filesCleaned = append(filesCleaned, absPath)
	}

	// Construct filename to download
	filename := fmt.Sprintf("%d_goshs_download.zip", time.Now().Unix())

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

	// Loop over files and add to zip (filesCleaned contains validated absolute paths)
	for _, file := range filesCleaned {
		err := filepath.Walk(file, walker)
		if err != nil {
			logger.Errorf("creating zip file: %+v", err)
		}
	}

	// Close Zip Writer and Flush to http.ResponseWriter
	if err := resultZip.Close(); err != nil {
		logger.Error(err)
	} else {
		body := fs.emitCollabEvent(req, http.StatusOK)
		logger.LogRequest(req, http.StatusOK, fs.Verbose, fs.Webhook, body)
	}
}
