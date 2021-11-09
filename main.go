package main

import (
	"flag"
	"fmt"
	"log"
	"math/rand"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/patrickhener/goshs/internal/myhttp"
	"github.com/patrickhener/goshs/internal/myutils"
)

const goshsVersion = "v0.1.6"

var (
	port       = 8000
	ip         = "0.0.0.0"
	webroot    = "."
	ssl        = false
	selfsigned = false
	myKey      = ""
	myCert     = ""
	basicAuth  = ""
	webdav     = false
	webdavPort = 8001
	uploadOnly = false
	readOnly   = false
)

// Man page
func usage() func() {
	return func() {
		fmt.Printf(`
goshs %s
Usage: %s [options]

Web server options:
  -i,  --ip           The ip/if-name to listen on             (default: 0.0.0.0)
  -p,  --port         The port to listen on                   (default: 8000)
  -d,  --dir          The web root directory                  (default: current working path)
  -w,  --webdav       Also serve using webdav protocol        (default: false)
  -wp, --webdav-port  The port to listen on for webdav        (default: 8001)
  -ro, --read-only    Read only mode, no upload possible      (default: false)
  -uo, --upload-only  Upload only mode, no download possible  (default: false)

TLS options:
  -s,  --ssl          Use TLS
  -ss, --self-signed  Use a self-signed certificate
  -sk, --server-key   Path to server key
  -sc, --server-cert  Path to server certificate

Authentication options:
  -b, --basic-auth    Use basic authentication (user:pass)

Misc options:
  -v  Print the current goshs version

Usage examples:
  Start with default values:    ./goshs
  Start with wevdav support:    ./goshs -w
  Start with different port:    ./goshs -p 8080
  Start with self-signed cert:  ./goshs -s -ss
  Start with custom cert:       ./goshs -s -sk <path to key> -sc <path to cert>
  Start with basic auth:        ./goshs -b secret-user:$up3r$3cur3

`, goshsVersion, os.Args[0])
	}
}

// Flag handling
func init() {
	wd, _ := os.Getwd()

	// flags
	flag.StringVar(&ip, "i", ip, "ip")
	flag.StringVar(&ip, "ip", ip, "ip")
	flag.IntVar(&port, "p", port, "port")
	flag.IntVar(&port, "port", port, "port")
	flag.StringVar(&webroot, "d", wd, "web root")
	flag.StringVar(&webroot, "dir", wd, "web root")
	flag.BoolVar(&ssl, "s", ssl, "tls")
	flag.BoolVar(&ssl, "ssl", ssl, "tls")
	flag.BoolVar(&selfsigned, "ss", selfsigned, "self-signed")
	flag.BoolVar(&selfsigned, "self-signed", selfsigned, "self-signed")
	flag.StringVar(&myKey, "sk", myKey, "server key")
	flag.StringVar(&myKey, "server-key", myKey, "server key")
	flag.StringVar(&myCert, "sc", myCert, "server cert")
	flag.StringVar(&myCert, "server-cert", myCert, "server cert")
	flag.StringVar(&basicAuth, "b", basicAuth, "basic auth")
	flag.StringVar(&basicAuth, "basic-auth", basicAuth, "basic auth")
	flag.BoolVar(&webdav, "w", webdav, "enable webdav")
	flag.BoolVar(&webdav, "webdav", webdav, "enable webdav")
	flag.IntVar(&webdavPort, "wp", webdavPort, "webdav port")
	flag.IntVar(&webdavPort, "webdav-port", webdavPort, "webdav port")
	flag.BoolVar(&uploadOnly, "uo", uploadOnly, "upload only")
	flag.BoolVar(&uploadOnly, "upload-only", uploadOnly, "upload only")
	flag.BoolVar(&readOnly, "ro", readOnly, "read only")
	flag.BoolVar(&readOnly, "read-only", readOnly, "read only")
	version := flag.Bool("v", false, "goshs version")

	flag.Usage = usage()

	flag.Parse()

	if *version {
		fmt.Printf("goshs version is: %+v\n", goshsVersion)
		os.Exit(0)
	}

	// Check if interface name was provided as -i
	// If so, resolve to ip address of interface
	if !strings.Contains(ip, ".") {
		addr, err := myutils.GetInterfaceIpv4Addr(ip)
		if err != nil {
			log.Fatal(err)
			os.Exit(-1)
		}

		if addr == "" {
			log.Println("IP address cannot be found for provided interface")
			os.Exit(-1)
		}

		ip = addr
	}

	// Sanity check for upload only vs read only
	if uploadOnly && readOnly {
		log.Println("You can only select either 'upload only' or 'read only', not both.")
		os.Exit(-1)
	}

	if webdav {
		log.Println("WARNING: upload/read-only mode deactivated due to use of 'webdav' mode")
		uploadOnly = false
		readOnly = false
	}
}

// Sanity checks if basic auth has the right format
func parseBasicAuth() (string, string) {
	auth := strings.SplitN(basicAuth, ":", 2)
	if len(auth) < 2 {
		fmt.Println("Wrong basic auth format. Please provide user:password separated by a colon")
		os.Exit(-1)
	}
	user := auth[0]
	pass := auth[1]
	return user, pass
}

func main() {
	user := ""
	pass := ""
	// check for basic auth
	if basicAuth != "" {
		user, pass = parseBasicAuth()
	}

	done := make(chan os.Signal, 1)
	signal.Notify(done, os.Interrupt, syscall.SIGINT, syscall.SIGTERM)

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
		User:       user,
		Pass:       pass,
		UploadOnly: uploadOnly,
		ReadOnly:   readOnly,
		Version:    goshsVersion,
	}

	go server.Start("web")

	if webdav {
		server.WebdavPort = webdavPort

		go server.Start("webdav")
	}

	<-done

	log.Println("Received CTRL+C, exiting...")
}
