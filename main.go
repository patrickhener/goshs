package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/patrickhener/goshs/ca"
	"github.com/patrickhener/goshs/httpserver"
	"github.com/patrickhener/goshs/logger"
	"github.com/patrickhener/goshs/utils"
)

const goshsVersion = "v0.4.1"

var (
	port        = 8000
	ip          = "0.0.0.0"
	cli         = false
	webroot     = "."
	ssl         = false
	selfsigned  = false
	letsencrypt = false
	myKey       = ""
	myCert      = ""
	myP12       = ""
	basicAuth   = ""
	certAuth    = ""
	webdav      = false
	webdavPort  = 8001
	uploadOnly  = false
	readOnly    = false
	verbose     = false
	silent      = false
	dropuser    = ""
	leEmail     = ""
	leDomains   = ""
	leHTTPPort  = "80"
	leTLSPort   = "443"
	embedded    = false
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
  -si, --silent       Running without dir listing             (default: false)
  -c,  --cli          Enable cli (only with auth and tls)     (default: false)
  -e,  --embedded     Show embedded files in UI               (default: false)

TLS options:
  -s,   --ssl          Use TLS
  -ss,  --self-signed  Use a self-signed certificate
  -sk,  --server-key   Path to server key
  -sc,  --server-cert  Path to server certificate
  -p12, --pkcs12       Path to server p12
  -sl,  --lets-encrypt Use Let's Encrypt as certification service
  -sld, --le-domains   Domain(s) to request from Let's Encrypt		(comma separated list)
  -sle, --le-email     Email to use with Let's Encrypt
  -slh, --le-http      Port to use for Let's Encrypt HTTP Challenge	(default: 80)
  -slt, --le-tls       Port to use for Let's Encrypt TLS ALPN Challenge (default: 443)

Authentication options:
  -b,  --basic-auth    Use basic authentication (user:pass - user can be empty)
  -ca, --cert-auth     Use certificate based authentication - provide ca certificate
  -H,  --hash          Hash a password for file based ACLs

Misc options:
  -u  --user          Drop privs to user (unix only)          (default: current user)
  -V  --verbose       Activate verbose log output             (default: false)
  -v                  Print the current goshs version

Usage examples:
  Start with default values:    	./goshs
  Start with wevdav support:    	./goshs -w
  Start with different port:    	./goshs -p 8080
  Start with self-signed cert:  	./goshs -s -ss
  Start with let's encrypt:		./goshs -s -sl -sle your@mail.com -sld your.domain.com,your.seconddomain.com
  Start with custom cert:       	./goshs -s -sk <path to key> -sc <path to cert>
  Start with basic auth:        	./goshs -b secret-user:$up3r$3cur3
  Start with basic auth empty user:	./goshs -b :$up3r$3cur3
  Start with cli enabled:           	./goshs -b secret-user:$up3r$3cur3 -s -ss -c

`, goshsVersion, os.Args[0])
	}
}

func flags() (*bool, *bool, *bool) {
	wd, _ := os.Getwd()

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
	flag.StringVar(&myP12, "p12", myP12, "server p12")
	flag.StringVar(&myP12, "pkcs12", myP12, "server p12")
	flag.StringVar(&basicAuth, "b", basicAuth, "basic auth")
	flag.StringVar(&basicAuth, "basic-auth", basicAuth, "basic auth")
	flag.StringVar(&certAuth, "ca", certAuth, "cert auth")
	flag.StringVar(&certAuth, "cert-auth", certAuth, "cert auth")
	flag.BoolVar(&webdav, "w", webdav, "enable webdav")
	flag.BoolVar(&webdav, "webdav", webdav, "enable webdav")
	flag.IntVar(&webdavPort, "wp", webdavPort, "webdav port")
	flag.IntVar(&webdavPort, "webdav-port", webdavPort, "webdav port")
	flag.BoolVar(&uploadOnly, "uo", uploadOnly, "upload only")
	flag.BoolVar(&uploadOnly, "upload-only", uploadOnly, "upload only")
	flag.BoolVar(&readOnly, "ro", readOnly, "read only")
	flag.BoolVar(&readOnly, "read-only", readOnly, "read only")
	flag.BoolVar(&verbose, "V", verbose, "verbose")
	flag.BoolVar(&verbose, "verbose", verbose, "verbose")
	flag.BoolVar(&silent, "si", silent, "silent")
	flag.BoolVar(&silent, "silent", silent, "silent")
	flag.StringVar(&dropuser, "u", dropuser, "user")
	flag.StringVar(&dropuser, "user", dropuser, "user")
	flag.BoolVar(&cli, "c", cli, "cli")
	flag.BoolVar(&cli, "cli", cli, "cli")
	flag.BoolVar(&letsencrypt, "sl", letsencrypt, "letsencrypt")
	flag.BoolVar(&letsencrypt, "lets-encrypt", letsencrypt, "letsencrypt")
	flag.StringVar(&leDomains, "sld", leDomains, "")
	flag.StringVar(&leDomains, "le-domains", leDomains, "")
	flag.StringVar(&leEmail, "sle", leEmail, "")
	flag.StringVar(&leEmail, "le-email", leEmail, "")
	flag.StringVar(&leHTTPPort, "slh", leHTTPPort, "")
	flag.StringVar(&leHTTPPort, "le-http", leHTTPPort, "")
	flag.StringVar(&leTLSPort, "slt", leTLSPort, "")
	flag.StringVar(&leTLSPort, "le-tls", leTLSPort, "")
	flag.BoolVar(&embedded, "e", embedded, "")
	flag.BoolVar(&embedded, "embedded", embedded, "")
	hash := flag.Bool("H", false, "hash")
	hashLong := flag.Bool("hash", false, "hash")
	version := flag.Bool("v", false, "goshs version")

	flag.Usage = usage()

	flag.Parse()

	return hash, hashLong, version
}

func resolveInterface() {
	// Check if interface name was provided as -i
	// If so, resolve to ip address of interface
	if !strings.Contains(ip, ".") {
		addr, err := utils.GetInterfaceIpv4Addr(ip)
		if err != nil {
			logger.Fatal(err)
			os.Exit(-1)
		}

		if addr == "" {
			logger.Fatal("IP address cannot be found for provided interface")
			os.Exit(-1)
		}

		ip = addr
	}
}

func sanityChecks() {
	// Sanity check for upload only vs read only
	if uploadOnly && readOnly {
		logger.Fatal("You can only select either 'upload only' or 'read only', not both.")
	}

	// Sanity check if cli mode is combined with auth and tls
	if cli && (!ssl || basicAuth == "") {
		if cli && (!ssl || certAuth == "") {
			logger.Fatal("With cli mode you need to enable basic/cert auth and tls for security reasons.")
		}
	}

	// Sanity check if CA mode enabled you will also need TLS enabled in some way
	if certAuth != "" && !ssl {
		logger.Fatal("To use certificate based authentication with a CA cert you will need tls in any mode (-ss, -sk/-sc, -p12, -sl)")
	}
}

// Flag handling
func init() {
	wd, _ := os.Getwd()

	// flags
	hash, hashLong, version := flags()

	if *version {
		fmt.Printf("goshs version is: %+v\n", goshsVersion)
		os.Exit(0)
	}

	if *hash || *hashLong {
		utils.HashPassword()
		os.Exit(1)
	}

	// Resolve Interface
	resolveInterface()

	// Sanity checks
	sanityChecks()

	if webdav {
		logger.Warn("upload/read-only mode deactivated due to use of 'webdav' mode")
		uploadOnly = false
		readOnly = false
	}

	// Abspath for webroot
	var err error
	// Trim trailing / for linux/mac and \ for windows
	webroot = strings.TrimSuffix(webroot, "/")
	webroot = strings.TrimSuffix(webroot, "\\")
	if !filepath.IsAbs(webroot) {
		webroot, err = filepath.Abs(filepath.Join(wd, webroot))
		if err != nil {
			logger.Fatalf("Webroot cannot be constructed: %+v", err)
		}
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

	// If Let's Encrypt is in play we need to fetch the key and cert, write them to disc and set their path in MyKey and MyCert
	if letsencrypt {
		ca.GetLECertificateAndKey(leEmail, strings.Split(leDomains, ","), leHTTPPort, leTLSPort)
		myCert = "cert"
		myKey = "key"
	}

	// Setup the custom file server
	server := &httpserver.FileServer{
		IP:          ip,
		Port:        port,
		CLI:         cli,
		Webroot:     webroot,
		SSL:         ssl,
		SelfSigned:  selfsigned,
		LetsEncrypt: letsencrypt,
		MyCert:      myCert,
		MyKey:       myKey,
		MyP12:       myP12,
		User:        user,
		Pass:        pass,
		CACert:      certAuth,
		DropUser:    dropuser,
		UploadOnly:  uploadOnly,
		ReadOnly:    readOnly,
		Silent:      silent,
		Embedded:    embedded,
		Verbose:     verbose,
		Version:     goshsVersion,
	}

	go server.Start("web")

	if webdav {
		server.WebdavPort = webdavPort

		go server.Start("webdav")
	}

	<-done

	logger.Infof("Received CTRL+C, exiting...")
}
