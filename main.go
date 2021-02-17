package main

import (
	"flag"
	"fmt"
	"math/rand"
	"os"
	"time"

	"github.com/patrickhener/goshs/internal/myhttp"
)

const goshsVersion = "v0.0.7"

var (
	port       = 8000
	ip         = "0.0.0.0"
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
	flag.StringVar(&ip, "i", ip, "ip")
	flag.IntVar(&port, "p", port, "port")
	flag.StringVar(&webroot, "d", wd, "web root")
	flag.BoolVar(&ssl, "s", ssl, "tls")
	flag.BoolVar(&selfsigned, "ss", selfsigned, "self-signed")
	flag.StringVar(&myKey, "sk", myKey, "server key")
	flag.StringVar(&myCert, "sc", myCert, "server cert")
	flag.StringVar(&basicAuth, "P", basicAuth, "basic auth")
	version := flag.Bool("v", false, "goshs version")

	flag.Usage = func() {
		fmt.Printf("goshs %s\n", goshsVersion)
		fmt.Printf("Usage: %s [options]\n\n", os.Args[0])
		fmt.Println("Web server options:")
		fmt.Println("\t-i\tThe ip to listen on\t(default: 0.0.0.0)")
		fmt.Println("\t-p\tThe port to listen on\t(default: 8000)")
		fmt.Println("\t-d\tThe web root directory\t(default: current working path)")
		fmt.Println("")
		fmt.Println("TLS options:")
		fmt.Println("\t-s\tUse TLS")
		fmt.Println("\t-ss\tUse a self-signed certificate")
		fmt.Println("\t-sk\tPath to server key")
		fmt.Println("\t-sc\tPath to server certificate")
		fmt.Println("")
		fmt.Println("Authentication options:")
		fmt.Println("\t-P\tUse basic authentication password (user: gopher)")
		fmt.Println("")
		fmt.Println("Misc options:")
		fmt.Println("\t-v\tPrint the current goshs version")
		fmt.Println("")
		fmt.Println("Usage examples:")
		fmt.Println("\tStart with default values:\t./goshs")
		fmt.Println("\tStart with different port:\t./goshs -p 8080")
		fmt.Println("\tStart with self-signed cert:\t./goshs -s -ss")
		fmt.Println("\tStart with custom cert:\t\t./goshs -s -sk <path to key> -sc <path to cert>")
		fmt.Println("\tStart with basic auth:\t\t./goshs -P $up3r$3cur3")
	}

	flag.Parse()

	if *version {
		fmt.Printf("goshs version is: %+v\n", goshsVersion)
		os.Exit(0)
	}
}

func main() {
	// Random Seed generation (used for CA serial)
	rand.Seed(time.Now().UnixNano())
	// Setup the custom file server
	server := &myhttp.FileServer{
		IP:         ip,
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
