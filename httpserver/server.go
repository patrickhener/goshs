package httpserver

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/howeyc/gopass"
	"golang.org/x/net/webdav"
	"goshs.de/goshs/v2/ca"
	"goshs.de/goshs/v2/catcher"
	"goshs.de/goshs/v2/clipboard"
	"goshs.de/goshs/v2/goshsversion"
	"goshs.de/goshs/v2/logger"
	"goshs.de/goshs/v2/options"
	"goshs.de/goshs/v2/tunnel"
	"goshs.de/goshs/v2/webhook"
	"goshs.de/goshs/v2/ws"
	"software.sslmate.com/src/go-pkcs12"
)

// Shutdown gracefully stops the HTTP server, waiting up to ctx's deadline for
// in-flight requests to complete.
func (fs *FileServer) Shutdown(ctx context.Context) error {
	if fs.httpServer == nil {
		return nil
	}
	return fs.httpServer.Shutdown(ctx)
}

// logServeResult treats http.ErrServerClosed as a clean exit (graceful
// shutdown) and panics on any other error.
func logServeResult(err error) {
	if errors.Is(err, http.ErrServerClosed) {
		return
	}
	logger.Panic(err)
}

func generateCSRFToken() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic("goshs: failed to generate CSRF token: " + err.Error())
	}
	return hex.EncodeToString(b)
}

func NewHttpServer(opts *options.Options, hub *ws.Hub, clip *clipboard.Clipboard, wl *Whitelist, wh webhook.Webhook) *FileServer {
	fs := &FileServer{
		IP:           opts.IP,
		Port:         opts.Port,
		CLI:          opts.CLI,
		Webroot:      opts.Webroot,
		Clipboard:    clip,
		Hub:          hub,
		UploadFolder: opts.UploadFolder,
		SSL:          opts.SSL,
		SelfSigned:   opts.SelfSigned,
		LetsEncrypt:  opts.LetsEncrypt,
		MyCert:       opts.MyCert,
		MyKey:        opts.MyKey,
		MyP12:        opts.MyP12,
		P12NoPass:    opts.P12NoPass,
		User:         opts.Username,
		Pass:         opts.Password,
		CACert:       opts.CertAuth,
		DropUser:     opts.DropUser,
		UploadOnly:   opts.UploadOnly,
		ReadOnly:     opts.ReadOnly,
		NoClipboard:  opts.NoClipboard,
		NoDelete:     opts.NoDelete,
		Silent:       opts.Silent,
		Invisible:    opts.Invisible,
		Embedded:     opts.Embedded,
		Verbose:      opts.Verbose,
		Tunnel:       opts.Tunnel,
		Version:      goshsversion.GoshsVersion,
		MaxUpload:    opts.MaxUploadSize,
		Options:      opts,
		CSRFToken:    generateCSRFToken(),
		authCache:    make(map[string]bool),
		authFailures: make(map[string]*authFailEntry),
	}

	fs.Hub = hub
	fs.Clipboard = clip
	fs.Webhook = wh
	fs.Whitelist = wl
	fs.CatcherMgr = catcher.NewManager(hub)

	return fs
}

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
			if fs.Invisible {
				// Use invisible basic auth middleware
				mux.Use(fs.InvisibleBasicAuthMiddleware)
			} else {
				// Use middleware
				mux.Use(fs.BasicAuthMiddleware)
			}
		}

		// IP Whitelist Middleware
		mux.Use(fs.IPWhitelistMiddleware)

		// Add custom server header middleware
		mux.Use(fs.ServerHeaderMiddleware)

		// Define routes
		mux.HandleFunc("POST /", func(w http.ResponseWriter, r *http.Request) {
			if action, ok := r.URL.Query()["catcher-api"]; ok {
				if denyForTokenAccess(w, r) {
					return
				}
				fs.handleCatcherAPI(w, r, action[0])
				return
			}
			if strings.HasSuffix(r.URL.Path, "/upload") {
				if denyForTokenAccess(w, r) {
					return
				}
				fs.upload(w, r)
				runtime.GC()
			} else if strings.HasSuffix(r.URL.Path, "/") && r.URL.Path != "/" {
				if denyForTokenAccess(w, r) {
					return
				}
				if !fs.checkCSRF(w, r) {
					return
				}
				fs.handleMkdir(w, r)
			} else {
				fs.logOnly(w, r)
			}
		})
		mux.HandleFunc("PUT /", func(w http.ResponseWriter, r *http.Request) {
			if denyForTokenAccess(w, r) {
				return
			}
			fs.put(w, r)
		})
		mux.HandleFunc("DELETE /", func(w http.ResponseWriter, r *http.Request) {
			if action, ok := r.URL.Query()["catcher-api"]; ok {
				if denyForTokenAccess(w, r) {
					return
				}
				fs.handleCatcherAPI(w, r, action[0])
				return
			}
			if _, ok := r.URL.Query()["token"]; ok {
				if !fs.checkCSRF(w, r) {
					return
				}
				fs.DeleteShareHandler(w, r)
				return
			}
			if denyForTokenAccess(w, r) {
				return
			}
			if !fs.checkCSRF(w, r) {
				return
			}
			if fs.ReadOnly || fs.UploadOnly || fs.NoDelete {
				fs.handleError(w, r, fmt.Errorf("delete not allowed"), http.StatusForbidden)
				return
			}
			fs.deleteFile(w, r)
		})
		mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodOptions {
				// Handle CORS preflight
				w.Header().Set("Access-Control-Allow-Origin", "*")
				w.Header().Set("Access-Control-Allow-Methods", "POST, PUT, DELETE, OPTIONS")
				w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
				w.WriteHeader(http.StatusOK)
				fs.logOnly(w, r)
			} else {
				fs.handler(w, r)
			}
		})

		addr = net.JoinHostPort(fs.IP, strconv.Itoa(fs.Port))
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
		addr = net.JoinHostPort(fs.IP, strconv.Itoa(fs.WebdavPort))
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

			fs.Fingerprint256 = strings.TrimRight(fingerprint256, " ")
			fs.Fingerprint1 = strings.TrimRight(fingerprint1, " ")
			fs.logStart(what)

			// Drop privs if needed
			fs.dropPrivs()

			// Webhook message
			logger.HandleWebhookSend(fmt.Sprintf("[CORE] goshs started on %s", listener.Addr()), "started", fs.Webhook)

			logServeResult(server.ServeTLS(listener, "", ""))
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

			logServeResult(server.ServeTLS(listener, "", ""))
		}
	} else {
		fs.logStart(what)

		// Drop privs if needed
		fs.dropPrivs()

		// Webhook message
		logger.HandleWebhookSend(fmt.Sprintf("[CORE] goshs started on %s", listener.Addr()), "started", fs.Webhook)

		logServeResult(server.Serve(listener))
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
		if err := listener.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			logger.Errorf("error closing tcp listener: %+v", err)
		}
	}()

	// construct server
	server := &http.Server{
		Handler:           http.AllowQuerySemicolons(mux),
		ReadHeaderTimeout: 10 * time.Second, // Mitigate Slow Loris Attack
		ErrorLog:          log.New(io.Discard, "", 0),
		// Against good practice no timeouts here, otherwise big files would be terminated when downloaded
	}
	fs.httpServer = server

	// Print silent banner
	if fs.Silent {
		logger.Info("Serving in silent mode - no dir listing available at HTTP Listener")
	}

	// Print all embedded files as info to the console
	fs.PrintEmbeddedFiles()

	// Start tunnel if enabled
	if fs.Tunnel {
		t, err := tunnel.Start(fs.IP, fs.Port)
		if err != nil {
			logger.Errorf("error starting tunnel: %+v", err)
		} else {
			defer t.Close()
			logger.Infof("Public tunnel URL: %s", t.PublicURL)
			fs.TunnelURL = t.PublicURL
		}
	}

	// Create SharedLinks map
	fs.SharedLinks = make(map[string]SharedLink)

	// Go routine to cleanup SharedLinks when expired
	go func() {
		ticker := time.NewTicker(1 * time.Minute)
		defer ticker.Stop()
		for range ticker.C {
			now := time.Now()
			fs.sharedLinksMu.Lock()
			for token, link := range fs.SharedLinks {
				if link.Expires.Before(now) {
					delete(fs.SharedLinks, token)
					logger.Debugf("Expired shared link removed: %s", token)
				}
			}
			fs.sharedLinksMu.Unlock()
		}
	}()

	// Start listener
	fs.StartListener(server, what, listener)
}
