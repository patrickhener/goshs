package main

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
	"time"
)

// Define custom templates
const (
	htmlTmp = `
<!DOCTYPE html PUBLIC "-//W3C//DTD HTML 4.01//EN" "http://www.w3.org/TR/html4/strict.dtd">
<html>
  <head>
    <meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
    <title>Directory listing for {{.Path}}</title>
  </head>
  <body>
    <h1>Directory listing for {{.Path}}</h1>
    <hr />
	<ul>
	  {{range .Content}}
		<li><a href="/{{.URI}}">{{.Name}}</a></li>
	  {{ end }}
	</ul>
    <hr />
  </body>
</html>
`

	notFoundTmp = `
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01//EN"
        "http://www.w3.org/TR/html4/strict.dtd">
<html>
    <head>
        <meta http-equiv="Content-Type" content="text/html;charset=utf-8">
        <title>Error response</title>
    </head>
    <body>
        <h1>Error response</h1>
        <p>Error code: 404</p>
        <p>Message: File not found.</p>
        <p>Error code explanation: HTTPStatus.NOT_FOUND - Nothing matches the given URI.</p>
    </body>
</html>
`
)

// Structs to hold the information
type directory struct {
	Path    string
	Content []item
}

type item struct {
	URI  string
	Name string
}

// 404 handler function
func handle404(w http.ResponseWriter, r *http.Request) {
	// Log the request
	timestamp := time.Now().Format("02/Jan/2006 15:04:05")

	fmt.Printf("%s - - [%s] \"%s %s %s\" %+v\n", r.RemoteAddr, timestamp, r.Method, r.URL.Path, r.Proto, "404")
	fmt.Printf("%s - - [%s] code 404, message File not found\n", r.RemoteAddr, timestamp)
	t := template.New("404")
	t.Parse(notFoundTmp)
	t.Execute(w, nil)
}

// Handler to handle server requests
// and to serve either directory listing or file content
func handler(w http.ResponseWriter, r *http.Request) {
	// Get working dir to ensure you know where you are. This marks /
	root, _ := os.Getwd() // ommitting error handling by using _

	// Get url so you can extract Headline and title
	upath := r.URL.Path

	// Ignore default browser call to /favicon.ico
	if upath == "/favicon.ico" {
		return
	}

	// Define absolute path
	open := root + path.Clean(upath)

	// Check if you are in a dir
	fi, err := os.Stat(open)
	if err != nil || os.IsNotExist(err) {
		// Handle as 404
		log.Printf("ERROR: cannot read file or folder: %+v", err)
		handle404(w, r)
		return
	}

	// Log the request
	timestamp := time.Now().Format("02/Jan/2006 15:04:05")

	fmt.Printf("%s - - [%s] \"%s %s %s\" %+v\n", r.RemoteAddr, timestamp, r.Method, r.URL.Path, r.Proto, "200")

	switch mode := fi.Mode(); {
	// If so feed dir to template engine
	case mode.IsDir():
		// Read directory
		dir, err := os.Open(open)
		if err != nil {
			// Handle as 404
			log.Printf("ERROR: Cannot read directory from disk: %+v", err)
			handle404(w, r)
			return
		}
		defer dir.Close()

		// Read directory FileInfo
		fis, err := dir.Readdir(-1)
		if err != nil {
			// Handle as 404
			log.Printf("ERROR: Cannot read directory content from disk: %+v", err)
			handle404(w, r)
			return
		}

		// Create empty slice
		items := make([]item, 0, len(fis))
		// Iterate over FileInfo of dir
		for _, fi := range fis {
			// Set name and uri
			itemname := fi.Name()
			itemuri := url.PathEscape(path.Join(upath, itemname))
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
		t.Parse(htmlTmp)
		d := &directory{Path: upath, Content: items}
		t.Execute(w, d)

	// Otherwise server static file using file server for the exact path?
	case mode.IsRegular():
		// Read in file
		openfile, err := os.Open(open)
		if err != nil || os.IsNotExist(err) {
			// Handle as 404
			log.Printf("ERROR: Cannot read file from disk: %+v", err)
			handle404(w, r)
			return
		}
		defer openfile.Close()

		// Write to browser
		io.Copy(w, openfile)
	}
}

func main() {
	// Check for port argument
	var (
		port string = "8000"
	)
	if len(os.Args) >= 2 {
		port = os.Args[1]
	}

	// Print to console
	fmt.Printf("Serving HTTP on 0.0.0.0 port %s\n", port)
	// Handle and serve - panic if something goes wrong
	http.HandleFunc("/", handler)
	log.Panic(http.ListenAndServe(":"+port, nil))
}
