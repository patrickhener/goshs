package httpserver

import (
	"fmt"
	"net/http"
	"runtime"
	"strings"
	"sync"

	"golang.org/x/crypto/bcrypt"
)

var (
	authCache      = make(map[string]bool)
	authCacheMutex = sync.RWMutex{}
)

// BasicAuthMiddleware is a middleware to handle the basic auth
func (fs *FileServer) BasicAuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("WWW-Authenticate", `Basic realm="Restricted"`)

		auth := r.Header.Get("Authorization")
		if !strings.HasPrefix(auth, "Basic ") {
			fmt.Println("No Authorization header")
			http.Error(w, "Not authorized", http.StatusUnauthorized)
			return
		}

		authVal := auth[len("Basic "):]
		// Cache check
		authCacheMutex.RLock()
		cachedOK := authCache[authVal]
		authCacheMutex.RUnlock()

		if cachedOK {
			next.ServeHTTP(w, r)
			return
		}

		//Check if provided password is a bcrypt hash
		if strings.HasPrefix(fs.Pass, "$2a$") {
			username, password, authOK := r.BasicAuth()
			if !authOK {
				http.Error(w, "Not authorized", http.StatusUnauthorized)
				return
			}

			if username != fs.User {
				http.Error(w, "Not authorized", http.StatusUnauthorized)
				return
			}

			if err := bcrypt.CompareHashAndPassword([]byte(fs.Pass), []byte(password)); err != nil {
				http.Error(w, "Not authorized", http.StatusUnauthorized)
				return
			}
		} else {
			username, password, authOK := r.BasicAuth()
			if !authOK {
				http.Error(w, "Not authorized", http.StatusUnauthorized)
				return
			}

			if username != fs.User || password != fs.Pass {
				http.Error(w, "Not authorized", http.StatusUnauthorized)
				return
			}
		}

		authCacheMutex.Lock()
		authCache[authVal] = true
		authCacheMutex.Unlock()

		next.ServeHTTP(w, r)
	})
}

// ServerHeaderMiddleware sets a custom Server header for all responses
func (fs *FileServer) ServerHeaderMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		serverHeader := fmt.Sprintf("goshs/%s (%s; %s)", fs.Version, runtime.GOOS, runtime.Version())
		w.Header().Set("Server", serverHeader)
		next.ServeHTTP(w, r)
	})
}

func checkPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}
