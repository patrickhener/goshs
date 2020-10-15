package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/patrickhener/goshs/internal/myhttp"
)

const goshsVersion = "v0.0.5"

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
	flag.BoolVar(&ssl, "s", ssl, "Use TLS")
	flag.BoolVar(&selfsigned, "ss", selfsigned, "Use self-signed certificate")
	flag.StringVar(&myKey, "sk", myKey, "Path to server key")
	flag.StringVar(&myCert, "sc", myCert, "Path to server cert")
	flag.StringVar(&basicAuth, "P", basicAuth, "Use basic auth password (user: gopher)")
	version := flag.Bool("v", false, "Prints the current goshs version")

	flag.Parse()

	if *version {
		fmt.Printf("goshs version is: %+v\n", goshsVersion)
		os.Exit(0)
	}
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
		Version:    goshsVersion,
	}
	server.Start()
}
