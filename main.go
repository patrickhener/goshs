package main

import (
	"flag"
	"os"

	"github.com/patrickhener/goshs/internal/myhttp"
)

var (
	port    = 8000
	webroot = "."
	ssl     = false
)

func init() {
	wd, _ := os.Getwd()

	// flags
	flag.IntVar(&port, "p", port, "The port")
	flag.StringVar(&webroot, "d", wd, "Web root directory")
	flag.BoolVar(&ssl, "s", ssl, "Use self-signed TLS")

	flag.Parse()
}

func main() {
	server := &myhttp.FileServer{Port: port, Webroot: webroot, SSL: ssl}
	server.Start()
}
