package mywebdav

import (
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/gorilla/mux"
	"github.com/patrickhener/goshs/internal/myca"
	"golang.org/x/net/webdav"
)

// WebdavServer will handle webdav connections
type WebdavServer struct {
	IP         string
	Port       int
	Webroot    string
	SSL        bool
	SelfSigned bool
	MyCert     string
	MyKey      string
	BasicAuth  string
}

// BasicAuthMiddleware is a middleware to handle the basic auth
func (wd *WebdavServer) BasicAuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("WWW-Authenticate", `Basic realm="Restricted"`)

		username, password, authOK := r.BasicAuth()
		if !authOK {
			http.Error(w, "Not authorized", http.StatusUnauthorized)
			return
		}

		if username != "gopher" || password != wd.BasicAuth {
			http.Error(w, "Not authorized", http.StatusUnauthorized)
			return
		}

		next.ServeHTTP(w, r)
	})

}

func (wd *WebdavServer) Start() {
	wdHandler := &webdav.Handler{
		FileSystem: webdav.Dir(wd.Webroot),
		LockSystem: webdav.NewMemLS(),
		Logger: func(r *http.Request, e error) {
			if e != nil {
				log.Printf("WEBDAV ERROR: %s - - \"%s %s %s\"", r.RemoteAddr, r.Method, r.URL.Path, r.Proto)
				return
			} else {
				if r.Method != "PROPFIND" {
					log.Printf("WEBDAV:  %s - - \"%s %s %s\"", r.RemoteAddr, r.Method, r.URL.Path, r.Proto)
				}
			}
		},
	}

	mux := mux.NewRouter()
	mux.PathPrefix("/").Handler(wdHandler)

	// construct server
	add := fmt.Sprintf("%+v:%+v", wd.IP, wd.Port)
	server := http.Server{
		Addr:    add,
		Handler: mux,
		// Good practice: enforce timeouts for servers you create!
		WriteTimeout: 120 * time.Second,
		ReadTimeout:  120 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Check BasicAuth and use middleware
	if wd.BasicAuth != "" {
		// Use middleware
		mux.Use(wd.BasicAuthMiddleware)
	}

	// Check if ssl
	if wd.SSL {
		// Check if selfsigned
		if wd.SelfSigned {
			serverTLSConf, fingerprint256, fingerprint1, err := myca.Setup()
			if err != nil {
				log.Fatalf("Unable to start SSL enabled webdav: %+v\n", err)
			}
			server.TLSConfig = serverTLSConf
			log.Printf("Serving WEBDAV on %+v port %+v from %+v with ssl enabled and self-signed certificate\n", wd.IP, wd.Port, wd.Webroot)
			log.Println("WARNING! Be sure to check the fingerprint of certificate")
			log.Printf("SHA-256 Fingerprint: %+v\n", fingerprint256)
			log.Printf("SHA-1   Fingerprint: %+v\n", fingerprint1)

			log.Panic(server.ListenAndServeTLS("", ""))
		} else {
			if wd.MyCert == "" || wd.MyKey == "" {
				log.Fatalln("You need to provide server.key and server.crt if -s and not -ss")
			}

			fingerprint256, fingerprint1, err := myca.ParseAndSum(wd.MyCert)
			if err != nil {
				log.Fatalf("Unable to start SSL enabled webdav: %+v\n", err)
			}

			log.Printf("Serving WEBDAV on %+v port %+v from %+v with ssl enabled server key: %+v, server cert: %+v\n", wd.IP, wd.Port, wd.Webroot, wd.MyKey, wd.MyCert)
			log.Println("INFO! You provided a certificate and might want to check the fingerprint nonetheless")
			log.Printf("SHA-256 Fingerprint: %+v\n", fingerprint256)
			log.Printf("SHA-1   Fingerprint: %+v\n", fingerprint1)

			log.Panic(server.ListenAndServeTLS(wd.MyCert, wd.MyKey))
		}
	} else {
		log.Printf("Serving WEBDAV on %+v port %+v from %+v\n", wd.IP, wd.Port, wd.Webroot)
		log.Panic(server.ListenAndServe())
	}
}
