package main

import (
	"flag"
	"os"

	"github.com/patrickhener/goshs/internal/myhttp"
)

var (
	port    = 8000
	webroot = "."
)

func init() {
	wd, _ := os.Getwd()

	// flags
	flag.IntVar(&port, "p", port, "The port")
	flag.StringVar(&webroot, "d", wd, "Web root directory")

	flag.Parse()
}

func main() {
	server := &myhttp.FileServer{Port: port, Webroot: webroot}
	server.Start()
}
