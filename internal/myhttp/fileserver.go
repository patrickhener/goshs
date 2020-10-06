package myhttp

import (
	"fmt"
	"html/template"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"path"
	"sort"
	"strings"

	"github.com/patrickhener/goshs/internal/myhtml"
	"github.com/patrickhener/goshs/internal/mylog"
)

type directory struct {
	Path    string
	Content []item
}

type item struct {
	URI  string
	Name string
}

// FileServer holds the fileserver information
type FileServer struct {
	Port    int
	Webroot string
}

// router will hook up the webroot with our fileserver
func (fs *FileServer) router() {
	http.Handle("/", fs)
}

// Start will start the file server
func (fs *FileServer) Start() {
	// init router
	fs.router()

	// Print to console
	log.Printf("Serving HTTP on 0.0.0.0 port %+v from %+v\n", fs.Port, fs.Webroot)

	add := fmt.Sprintf(":%+v", fs.Port)
	log.Panic(http.ListenAndServe(add, nil))
}

// ServeHTTP will serve the response by leveraging our handler
func (fs *FileServer) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	defer func() {
		if err := recover(); err != nil {
			http.Error(w, fmt.Sprintf("%+v", err), http.StatusInternalServerError)
		}
	}()

	fs.handler(w, req)
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
		// Handle as 404
		fs.handle404(w, req)
		return
	}
	if os.IsPermission(err) {
		// Handle as 500
		fs.handle500(w, req)
		return
	}
	if err != nil {
		// Handle general error
		log.Println(err)
		return
	}
	defer file.Close()

	// Log request
	mylog.LogRequest(req.RemoteAddr, req.Method, req.URL.Path, req.Proto, "200")

	// Switch and check if dir
	stat, _ := file.Stat()
	if stat.IsDir() {
		fs.processDir(w, req, file, upath)
	} else {
		fs.sendFile(w, file)
	}

}

func (fs *FileServer) processDir(w http.ResponseWriter, req *http.Request, file *os.File, relpath string) {
	// Read directory FileInfo
	fis, err := file.Readdir(-1)
	if err != nil {
		fs.handle404(w, req)
		return
	}

	// Create empty slice
	items := make([]item, 0, len(fis))
	// Iterate over FileInfo of dir
	for _, fi := range fis {
		// Set name and uri
		itemname := fi.Name()
		itemuri := url.PathEscape(path.Join(relpath, itemname))
		// Add / to name if dir
		if fi.IsDir() {
			itemname += "/"
		}
		// define item struct
		item := item{
			Name: itemname,
			URI:  itemuri,
		}
		// Add to items slice
		items = append(items, item)
	}

	// Sort slice all lowercase
	sort.Slice(items, func(i, j int) bool {
		return strings.ToLower(items[i].Name) < strings.ToLower(items[j].Name)
	})

	// Template parsing and writing to browser
	t := template.New("index")
	t.Parse(myhtml.GetTemplate("display"))
	d := &directory{Path: relpath, Content: items}
	t.Execute(w, d)
}

func (fs *FileServer) sendFile(w http.ResponseWriter, file *os.File) {
	// Write to browser
	io.Copy(w, file)
}

func (fs *FileServer) handle404(w http.ResponseWriter, req *http.Request) {
	mylog.LogRequest(req.RemoteAddr, req.Method, req.URL.Path, req.Proto, "404")
	mylog.LogMessage("404:   File not found")
	t := template.New("404")
	t.Parse(myhtml.GetTemplate("404"))
	t.Execute(w, nil)
}

func (fs *FileServer) handle500(w http.ResponseWriter, req *http.Request) {
	mylog.LogRequest(req.RemoteAddr, req.Method, req.URL.Path, req.Proto, "500")
	mylog.LogMessage("500:   No permission to access the file")
	t := template.New("500")
	t.Parse(myhtml.GetTemplate("500"))
	t.Execute(w, nil)
}
