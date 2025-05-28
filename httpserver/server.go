package httpserver

import (
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"runtime"
	"time"

	"github.com/howeyc/gopass"
	"github.com/patrickhener/goshs/ca"
	"github.com/patrickhener/goshs/clipboard"
	"github.com/patrickhener/goshs/logger"
	"github.com/patrickhener/goshs/ws"
	"golang.org/x/net/webdav"
	"software.sslmate.com/src/go-pkcs12"
)

func (fs *FileServer) SetupMux(mux *CustomMux, what string) string {
	var addr string
	switch what {
	case modeWeb:
		// Check Basic Auth and use middleware
		if (fs.User != "" || fs.Pass != "") && what == modeWeb {
			if !fs.SSL {
				logger.Warnf("You are using basic auth without SSL. Your credentials will be transferred in cleartext. Consider using -s, too.")
			}
			logger.Infof("Using basic auth with user '%s' and password '%s'", fs.User, fs.Pass)
			// Use middleware
			mux.Use(fs.BasicAuthMiddleware)
		}

		// IP Whitelist Middleware
		mux.Use(fs.IPWhitelistMiddleware)

		// Add custom server header middleware
		mux.Use(fs.ServerHeaderMiddleware)

		// Define routes
		mux.HandleFunc("POST /upload", func(w http.ResponseWriter, r *http.Request) {
			fs.upload(w, r)
			runtime.GC()
		})
		mux.HandleFunc("POST /", func(w http.ResponseWriter, r *http.Request) {
			fs.logOnly(w, r)
		})
		mux.HandleFunc("PUT /", func(w http.ResponseWriter, r *http.Request) {
			fs.put(w, r)
		})
		mux.HandleFunc("/", fs.handler)

		addr = fmt.Sprintf("%+v:%+v", fs.IP, fs.Port)
	case "webdav":
		// IP Whitelist Middleware
		mux.Use(fs.IPWhitelistMiddleware)

		// Add custom server header middleware
		mux.Use(fs.ServerHeaderMiddleware)

		wdHandler := &webdav.Handler{
			FileSystem: webdav.Dir(fs.Webroot),
			LockSystem: webdav.NewMemLS(),
			Logger: func(r *http.Request, e error) {
				if e != nil && r.Method != "PROPFIND" {
					logger.HandleWebhookSend(fmt.Sprintf("[WEBDAV] ERROR: %s - - \"%s %s %s\"", r.RemoteAddr, r.Method, r.URL.Path, r.Proto), "webdav", fs.Webhook)
					logger.Errorf("WEBDAV: %s - - \"%s %s %s\"", r.RemoteAddr, r.Method, r.URL.Path, r.Proto)
					return
				} else if r.Method != "PROPFIND" {
					logger.HandleWebhookSend(fmt.Sprintf("[WEBDAV]: %s - - \"%s %s %s\"", r.RemoteAddr, r.Method, r.URL.Path, r.Proto), "webdav", fs.Webhook)
					logger.Infof("WEBDAV:  %s - - \"%s %s %s\"", r.RemoteAddr, r.Method, r.URL.Path, r.Proto)
				}
			},
		}

		// Check Basic Auth and use middleware
		if fs.User != "" || fs.Pass != "" {
			authHandler := fs.BasicAuthMiddleware(wdHandler)
			mux.Handle("/", authHandler)
		} else {
			mux.Handle("/", wdHandler)
		}
		addr = fmt.Sprintf("%+v:%+v", fs.IP, fs.WebdavPort)
	default:
	}

	return addr
}

func (fs *FileServer) StartListener(server *http.Server, what string, listener net.Listener) {
	var err error
	// Check if ssl
	if fs.SSL {
		// Check if selfsigned
		if fs.SelfSigned {
			serverTLSConf, fingerprint256, fingerprint1, err := ca.Setup()
			if err != nil {
				logger.Fatalf("Unable to start SSL enabled server: %+v\n", err)
			}
			server.TLSConfig = serverTLSConf

			// If client-cert auth add it to TLS Config of server
			if fs.CACert != "" {
				fs.AddCertAuth(server)
			}

			fs.Fingerprint256 = fingerprint256
			fs.Fingerprint1 = fingerprint1
			fs.logStart(what)

			// Drop privs if needed
			fs.dropPrivs()

			// Webhook message
			logger.HandleWebhookSend(fmt.Sprintf("[CORE] goshs started on %s", listener.Addr()), "started", fs.Webhook)

			logger.Panic(server.ServeTLS(listener, "", ""))
		} else {
			if fs.MyCert == "" || fs.MyKey == "" {
				if fs.MyP12 == "" {
					logger.Fatal("You need to provide either server.key and server.crt or server.p12 if -s and not -ss")
				}
			}

			var cert tls.Certificate
			var fingerprint256, fingerprint1 string

			if fs.MyP12 != "" {
				p12, err := os.ReadFile(fs.MyP12)
				if err != nil {
					logger.Fatalf("Error reading pkcs12 file: %+v", err)
				}

				var password []byte
				if fs.P12NoPass {
					password = []byte("")
				} else {
					fmt.Printf("Enter password for %+v: ", fs.MyP12)
					password, err = gopass.GetPasswdMasked()
					if err != nil {
						logger.Fatalf("error reading password from stdin: %+v", err)
					}
				}
				privKey, certificate, err := pkcs12.Decode(p12, string(password))
				if err != nil {
					logger.Fatalf("error parsing the p12 file: %+v", err)
				}

				cert = tls.Certificate{
					Certificate: [][]byte{certificate.Raw},
					PrivateKey:  privKey,
					Leaf:        certificate,
				}

				fingerprint256, fingerprint1 = ca.Sum(certificate.Raw)
			} else {
				fingerprint256, fingerprint1, err = ca.ParseAndSum(fs.MyCert)
				if err != nil {
					logger.Fatalf("Unable to start SSL enabled server: %+v\n", err)
				}

				cert, err = tls.LoadX509KeyPair(fs.MyCert, fs.MyKey)
				if err != nil {
					logger.Fatalf("Failed to load provided key or certificate: %+v\n", err)
				}
			}

			server.TLSConfig = &tls.Config{
				Certificates: []tls.Certificate{cert},
				MinVersion:   tls.VersionTLS12,
			}

			// If client-cert auth add it to TLS Config of server
			if fs.CACert != "" {
				fs.AddCertAuth(server)
			}

			fs.Fingerprint256 = fingerprint256
			fs.Fingerprint1 = fingerprint1
			fs.logStart(what)

			// Drop privs if needed
			fs.dropPrivs()

			// Webhook message
			logger.HandleWebhookSend(fmt.Sprintf("[CORE] goshs started on %s", listener.Addr()), "started", fs.Webhook)

			logger.Panic(server.ServeTLS(listener, "", ""))
		}
	} else {
		fs.logStart(what)

		// Drop privs if needed
		fs.dropPrivs()

		// Webhook message
		logger.HandleWebhookSend(fmt.Sprintf("[CORE] goshs started on %s", listener.Addr()), "started", fs.Webhook)

		logger.Panic(server.Serve(listener))
	}
}

// Start will start the file server
func (fs *FileServer) Start(what string) {
	// Setup routing with gorilla/mux
	mux := NewCustomMux()

	addr := fs.SetupMux(mux, what)

	// construct and bind listener
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		logger.Fatalf("Error binding to listener '%s': %+v", addr, err)
	}
	defer func() {
		if err := listener.Close(); err != nil {
			logger.Errorf("error closing tcp listener: %+v", err)
		}
	}()

	// construct server
	server := &http.Server{
		// Addr:              addr,
		Handler:           http.AllowQuerySemicolons(mux),
		ReadHeaderTimeout: 10 * time.Second, // Mitigate Slow Loris Attack
		ErrorLog:          log.New(io.Discard, "", 0),
		// Against good practice no timeouts here, otherwise big files would be terminated when downloaded
	}

	// init clipboard
	if !fs.NoClipboard {
		fs.Clipboard = clipboard.New()

		// init websocket hub
		fs.Hub = ws.NewHub(fs.Clipboard, fs.CLI)
		go fs.Hub.Run()
	}

	// Print silent banner
	if fs.Silent {
		logger.Info("Serving in silent mode - no dir listing available at HTTP Listener")
	}

	// Print all embedded files as info to the console
	fs.PrintEmbeddedFiles()

	// Start listener
	fs.StartListener(server, what, listener)
}
