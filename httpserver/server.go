package httpserver

import (
	"fmt"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/patrickhener/goshs/ca"
	"github.com/patrickhener/goshs/clipboard"
	"github.com/patrickhener/goshs/logger"
	"github.com/patrickhener/goshs/ws"
	"golang.org/x/net/webdav"
)

// Start will start the file server
func (fs *FileServer) Start(what string) {
	var addr string
	// Setup routing with gorilla/mux
	mux := mux.NewRouter()

	switch what {
	case modeWeb:
		mux.PathPrefix("/425bda8487e36deccb30dd24be590b8744e3a28a8bb5a57d9b3fcd24ae09ad3c/").HandlerFunc(fs.static)
		// Websocket
		mux.PathPrefix("/14644be038ea0118a1aadfacca2a7d1517d7b209c4b9674ee893b1944d1c2d54/ws").HandlerFunc(fs.socket)
		// Clipboard
		mux.PathPrefix("/14644be038ea0118a1aadfacca2a7d1517d7b209c4b9674ee893b1944d1c2d54/download").HandlerFunc(fs.cbDown)
		mux.PathPrefix("/cf985bddf28fed5d5c53b069d6a6ebe601088ca6e20ec5a5a8438f8e1ffd9390/").HandlerFunc(fs.bulkDownload)
		mux.Methods(http.MethodPost).HandlerFunc(fs.upload)
		mux.PathPrefix("/").HandlerFunc(fs.handler)

		addr = fmt.Sprintf("%+v:%+v", fs.IP, fs.Port)
	case "webdav":
		wdHandler := &webdav.Handler{
			FileSystem: webdav.Dir(fs.Webroot),
			LockSystem: webdav.NewMemLS(),
			Logger: func(r *http.Request, e error) {
				if e != nil && r.Method != "PROPFIND" {
					logger.Errorf("WEBDAV: %s - - \"%s %s %s\"", r.RemoteAddr, r.Method, r.URL.Path, r.Proto)
					return
				} else if r.Method != "PROPFIND" {
					logger.Infof("WEBDAV:  %s - - \"%s %s %s\"", r.RemoteAddr, r.Method, r.URL.Path, r.Proto)
				}
			},
		}

		mux.PathPrefix("/").Handler(wdHandler)
		addr = fmt.Sprintf("%+v:%+v", fs.IP, fs.WebdavPort)
	default:
	}

	// construct server
	server := http.Server{
		Addr:    addr,
		Handler: http.AllowQuerySemicolons(mux),
		// Against good practice no timeouts here, otherwise big files would be terminated when downloaded
	}

	// init clipboard
	fs.Clipboard = clipboard.New()

	// init websocket hub
	fs.Hub = ws.NewHub(fs.Clipboard)
	go fs.Hub.Run()

	// Check BasicAuth and use middleware
	if fs.User != "" && what == modeWeb {
		if !fs.SSL {
			logger.Warnf("You are using basic auth without SSL. Your credentials will be transferred in cleartext. Consider using -s, too.")
		}
		logger.Infof("Using basic auth with user '%s' and password '%s'", fs.User, fs.Pass)
		// Use middleware
		mux.Use(fs.BasicAuthMiddleware)
	}

	if fs.Silent {
		logger.Info("Serving in silent mode - no dir listing available at HTTP Listener")
	}

	// Check if ssl
	if fs.SSL {
		// Check if selfsigned
		if fs.SelfSigned {
			serverTLSConf, fingerprint256, fingerprint1, err := ca.Setup()
			if err != nil {
				logger.Fatalf("Unable to start SSL enabled server: %+v\n", err)
			}
			server.TLSConfig = serverTLSConf
			fs.Fingerprint256 = fingerprint256
			fs.Fingerprint1 = fingerprint1
			fs.logStart(what)

			logger.Panic(server.ListenAndServeTLS("", ""))
		} else {
			if fs.MyCert == "" || fs.MyKey == "" {
				logger.Fatal("You need to provide server.key and server.crt if -s and not -ss")
			}

			fingerprint256, fingerprint1, err := ca.ParseAndSum(fs.MyCert)
			if err != nil {
				logger.Fatalf("Unable to start SSL enabled server: %+v\n", err)
			}
			fs.Fingerprint256 = fingerprint256
			fs.Fingerprint1 = fingerprint1
			fs.logStart(what)

			logger.Panic(server.ListenAndServeTLS(fs.MyCert, fs.MyKey))
		}
	} else {
		fs.logStart(what)
		logger.Panic(server.ListenAndServe())
	}
}
