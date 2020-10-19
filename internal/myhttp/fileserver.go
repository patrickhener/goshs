package myhttp

import (
	"fmt"
	"html/template"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"path"
	"sort"
	"strings"
	"time"

	"github.com/patrickhener/goshs/internal/myca"
	"github.com/patrickhener/goshs/internal/mylog"
	"github.com/patrickhener/goshs/internal/myutils"

	"github.com/phogolabs/parcello"

	// This will import for bundling with parcello
	_ "github.com/patrickhener/goshs/static"
)

type directory struct {
	RelPath        string
	AbsPath        string
	IsSubdirectory bool
	Back           string
	Content        []item
	GoshsVersion   string
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
	IP         string
	Port       int
	Webroot    string
	SSL        bool
	SelfSigned bool
	MyKey      string
	MyCert     string
	BasicAuth  string
	Version    string
}

type httperror struct {
	ErrorCode    int
	ErrorMessage string
	AbsPath      string
	GoshsVersion string
}

// router will hook up the webroot with our fileserver
func (fs *FileServer) router() {
	http.Handle("/", fs)
}

// authRouter will hook up the webroot with the fileserver using basic auth
func (fs *FileServer) authRouter() {
	http.HandleFunc("/", fs.basicAuth(fs.ServeHTTP))
}

// basicAuth is a wrapper to handle the basic auth
func (fs *FileServer) basicAuth(handler http.HandlerFunc) func(w http.ResponseWriter, req *http.Request) {
	return func(w http.ResponseWriter, req *http.Request) {
		w.Header().Set("WWW-Authenticate", `Basic realm="Restricted"`)

		username, password, authOK := req.BasicAuth()
		if authOK == false {
			http.Error(w, "Not authorized", http.StatusUnauthorized)
			return
		}

		if username != "gopher" || password != fs.BasicAuth {
			http.Error(w, "Not authorized", http.StatusUnauthorized)
			return
		}

		fs.ServeHTTP(w, req)
	}
}

// Start will start the file server
func (fs *FileServer) Start() {
	// init router with or without auth
	if fs.BasicAuth != "" {
		if !fs.SSL {
			log.Printf("WARNING!: You are using basic auth without SSL. Your credentials will be transferred in cleartext. Consider using -s, too.\n")
		}
		log.Printf("Using 'gopher:%+v' as basic auth\n", fs.BasicAuth)
		fs.authRouter()
	} else {
		fs.router()
	}

	// construct server
	add := fmt.Sprintf("%+v:%+v", fs.IP, fs.Port)
	server := http.Server{Addr: add}

	// Check if ssl
	if fs.SSL {
		// Check if selfsigned
		if fs.SelfSigned {
			serverTLSConf, fingerprint256, fingerprint1, err := myca.Setup()
			if err != nil {
				log.Fatalf("Unable to start SSL enabled server: %+v\n", err)
			}
			server.TLSConfig = serverTLSConf
			log.Printf("Serving HTTPS on %+v port %+v from %+v with ssl enabled and self-signed certificate\n", fs.IP, fs.Port, fs.Webroot)
			log.Println("WARNING! Be sure to check the fingerprint of certificate")
			log.Printf("SHA-256 Fingerprint: %+v\n", fingerprint256)
			log.Printf("SHA-1   Fingerprint: %+v\n", fingerprint1)
			log.Panic(server.ListenAndServeTLS("", ""))
		} else {
			if fs.MyCert == "" || fs.MyKey == "" {
				log.Fatalln("You need to provide server.key and server.crt if -s and not -ss")
			}

			fingerprint256, fingerprint1, err := myca.ParseAndSum(fs.MyCert)
			if err != nil {
				log.Fatalf("Unable to start SSL enabled server: %+v\n", err)
			}

			log.Printf("Serving HTTPS on %+v port %+v from %+v with ssl enabled server key: %+v, server cert: %+v\n", fs.IP, fs.Port, fs.Webroot, fs.MyKey, fs.MyCert)
			log.Println("INFO! You provided a certificate and might want to check the fingerprint nonetheless")
			log.Printf("SHA-256 Fingerprint: %+v\n", fingerprint256)
			log.Printf("SHA-1   Fingerprint: %+v\n", fingerprint1)

			log.Panic(server.ListenAndServeTLS(fs.MyCert, fs.MyKey))
		}
	} else {
		log.Printf("Serving HTTP on %+v port %+v from %+v\n", fs.IP, fs.Port, fs.Webroot)
		log.Panic(server.ListenAndServe())
	}
}

// ServeHTTP will serve the response by leveraging our handler
func (fs *FileServer) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	defer func() {
		if err := recover(); err != nil {
			http.Error(w, fmt.Sprintf("%+v", err), http.StatusInternalServerError)
		}
	}()

	// Check if special path, then serve static
	// Realise that you will not be able to deliver content of folder
	// called 425bda8487e36deccb30dd24be590b8744e3a28a8bb5a57d9b3fcd24ae09ad3c on disk
	if strings.Contains(req.URL.Path, "425bda8487e36deccb30dd24be590b8744e3a28a8bb5a57d9b3fcd24ae09ad3c") {
		fs.static(w, req)
	} else {
		// serve files / dirs or upload
		switch req.Method {
		case "GET":
			fs.handler(w, req)
		case "POST":
			fs.upload(w, req)
		}
	}
}

// static will give static content for style and function
func (fs *FileServer) static(w http.ResponseWriter, req *http.Request) {
	// Check which file to serve
	upath := req.URL.Path
	staticPath := strings.SplitAfterN(upath, "/", 3)[2]
	// Load file with parcello
	staticFile, err := parcello.Open(staticPath)
	if err != nil {
		log.Printf("ERROR: static file: %+v cannot be loaded: %+v", staticPath, err)
	}

	// Read file
	staticContent, err := ioutil.ReadAll(staticFile)
	if err != nil {
		log.Printf("ERROR: static file: %+v cannot be read: %+v", staticPath, err)
	}

	// Get mimetype from extension
	contentType := myutils.MimeByExtension(staticPath)

	// Set mimetype and deliver to browser
	w.Header().Add("Content-Type", contentType)
	w.Write(staticContent)
}

// handler is the function which actually handles dir or file retrieval
func (fs *FileServer) handler(w http.ResponseWriter, req *http.Request) {
	// Get url so you can extract Headline and title
	upath := req.URL.Path

	// Ignore default browser call to /favicon.ico
	if upath == "/favicon.ico" {
		return
	}

	// Define absolute path
	open := fs.Webroot + path.Clean(upath)

	// Check if you are in a dir
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
		log.Println(err)
		return
	}
	defer file.Close()

	// Log request
	mylog.LogRequest(req.RemoteAddr, req.Method, req.URL.Path, req.Proto, http.StatusOK)

	// Switch and check if dir
	stat, _ := file.Stat()
	if stat.IsDir() {
		fs.processDir(w, req, file, upath)
	} else {
		fs.sendFile(w, file)
	}
}

// upload handles the POST request to upload files
func (fs *FileServer) upload(w http.ResponseWriter, req *http.Request) {
	// Get url so you can extract Headline and title
	upath := req.URL.Path

	// construct target path
	targetpath := strings.Split(upath, "/")
	targetpath = targetpath[:len(targetpath)-1]
	target := strings.Join(targetpath, "/")

	// Parse request
	if err := req.ParseMultipartForm(10 << 20); err != nil {
		log.Printf("Error parsing multipart request: %+v", err)
		return
	}

	// Get ref to the parsed multipart form
	m := req.MultipartForm

	// Get the File Headers
	files := m.File["files"]

	for i := range files {
		file, err := files[i].Open()
		defer file.Close()
		if err != nil {
			log.Printf("Error retrieving the file: %+v\n", err)
		}

		// Construct absolute savepath
		savepath := fmt.Sprintf("%s%s/%s", fs.Webroot, target, files[i].Filename)
		log.Printf("DEBUG: savepath is supposed to be: %+v", savepath)

		// Create file to write to
		if _, err := os.Create(savepath); err != nil {
			log.Println("ERROR: Not able to create file on disk")
			fs.handleError(w, req, err, http.StatusInternalServerError)
		}

		// Read file from post body
		fileBytes, err := ioutil.ReadAll(file)
		if err != nil {
			log.Println("ERROR: Not able to read file from request")
			fs.handleError(w, req, err, http.StatusInternalServerError)
		}

		// Write file to disk
		if err := ioutil.WriteFile(savepath, fileBytes, os.ModePerm); err != nil {
			log.Println("ERROR: Not able to write file to disk")
			fs.handleError(w, req, err, http.StatusInternalServerError)
		}

	}

	// Log request
	mylog.LogRequest(req.RemoteAddr, req.Method, req.URL.Path, req.Proto, http.StatusOK)

	// Redirect back from where we came from
	http.Redirect(w, req, target, http.StatusSeeOther)
}

func (fs *FileServer) processDir(w http.ResponseWriter, req *http.Request, file *os.File, relpath string) {
	// Read directory FileInfo
	fis, err := file.Readdir(-1)
	if err != nil {
		fs.handleError(w, req, err, http.StatusNotFound)
		return
	}

	// Create empty slice
	items := make([]item, 0, len(fis))
	// Iterate over FileInfo of dir
	for _, fi := range fis {
		var item = item{}
		// Need to set this up here for directories to work
		item.Name = fi.Name()
		item.Ext = strings.ToLower(myutils.ReturnExt(fi.Name()))
		// Add / to name if dir
		if fi.IsDir() {
			// Check if special path exists as dir on disk and do not add
			if fi.Name() == "425bda8487e36deccb30dd24be590b8744e3a28a8bb5a57d9b3fcd24ae09ad3c" {
				continue
			}
			item.Name += "/"
			item.IsDir = true
			item.Ext = ""
		}
		// Set item fields
		item.URI = url.PathEscape(path.Join(relpath, fi.Name()))
		item.DisplaySize = myutils.ByteCountDecimal(fi.Size())
		item.SortSize = fi.Size()
		item.DisplayLastModified = fi.ModTime().Format("Mon Jan _2 15:04:05 2006")
		item.SortLastModified = fi.ModTime()
		// Check and resolve symlink
		if fi.Mode()&os.ModeSymlink != 0 {
			item.IsSymlink = true
			item.SymlinkTarget, err = os.Readlink(path.Join(fs.Webroot, relpath, fi.Name()))
			if err != nil {
				log.Printf("Error resolving symlink: %+v", err)
			}
		}
		// Add to items slice
		items = append(items, item)
	}

	// Sort slice all lowercase
	sort.Slice(items, func(i, j int) bool {
		return strings.ToLower(items[i].Name) < strings.ToLower(items[j].Name)
	})

	// Template parsing and writing to browser
	indexFile, err := parcello.Open("templates/index.html")
	if err != nil {
		log.Printf("Error opening embedded file: %+v", err)
	}
	fileContent, err := ioutil.ReadAll(indexFile)
	if err != nil {
		log.Printf("Error opening embedded file: %+v", err)
	}

	// Construct directory for template
	d := &directory{
		RelPath:      relpath,
		AbsPath:      path.Join(fs.Webroot, relpath),
		Content:      items,
		GoshsVersion: fs.Version,
	}
	if relpath != "/" {
		d.IsSubdirectory = true
		pathSlice := strings.Split(relpath, "/")
		if len(pathSlice) > 2 {
			pathSlice = pathSlice[1 : len(pathSlice)-1]

			var backString string = ""
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

	t := template.New("index")
	t.Parse(string(fileContent))
	if err := t.Execute(w, d); err != nil {
		log.Printf("ERROR: Error parsing template: %+v", err)
	}
}

func (fs *FileServer) sendFile(w http.ResponseWriter, file *os.File) {
	// Write to browser
	io.Copy(w, file)
}

func (fs *FileServer) handleError(w http.ResponseWriter, req *http.Request, err error, status int) {
	// Set header to status
	w.WriteHeader(status)

	// Define empty error
	var e httperror

	// Log to console
	mylog.LogRequest(req.RemoteAddr, req.Method, req.URL.Path, req.Proto, status)

	// Construct error for template filling
	e.ErrorCode = status
	e.ErrorMessage = err.Error()
	e.AbsPath = path.Join(fs.Webroot, req.URL.Path)
	e.GoshsVersion = fs.Version

	// Template handling
	file, err := parcello.Open("templates/error.html")
	if err != nil {
		log.Printf("Error opening embedded file: %+v", err)
	}
	fileContent, err := ioutil.ReadAll(file)
	if err != nil {
		log.Printf("Error opening embedded file: %+v", err)
	}
	t := template.New("error")
	t.Parse(string(fileContent))
	if err := t.Execute(w, e); err != nil {
		log.Printf("Error parsing the template: %+v", err)
	}
}
