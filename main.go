package main

import (
	"flag"
	"os"

	"github.com/patrickhener/goshs/internal/myhttp"
)

var (
	port       = 8000
	webroot    = "."
	ssl        = false
	selfsigned = false
	myKey      = ""
	myCert     = ""
	basicAuth  = ""
)

func init() {
	wd, _ := os.Getwd()

	// flags
	flag.IntVar(&port, "p", port, "The port")
	flag.StringVar(&webroot, "d", wd, "Web root directory")
	flag.BoolVar(&ssl, "s", ssl, "Use self-signed TLS")
	flag.BoolVar(&selfsigned, "ss", selfsigned, "Use self-signed certificate")
	flag.StringVar(&myKey, "sk", myKey, "Path to own server key")
	flag.StringVar(&myCert, "sc", myCert, "Path to own server cert")
	flag.StringVar(&basicAuth, "P", basicAuth, "Use basic auth password (user: gopher)")

	flag.Parse()
}

func main() {
	// Setup the custom file server
	server := &myhttp.FileServer{
		Port:       port,
		Webroot:    webroot,
		SSL:        ssl,
		SelfSigned: selfsigned,
		MyCert:     myCert,
		MyKey:      myKey,
		BasicAuth:  basicAuth,
	}
	server.Start()
}
