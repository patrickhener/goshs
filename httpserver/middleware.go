package httpserver

import (
	"fmt"
	"net"
	"net/http"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/patrickhener/goshs/logger"
	"golang.org/x/crypto/bcrypt"
)

var (
	authCache      = make(map[string]bool)
	authCacheMutex = sync.RWMutex{}
)

// BasicAuthMiddleware is a middleware to handle the basic auth
func (fs *FileServer) BasicAuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := r.URL.Query().Get("token")

		if token != "" {
			share, ok := fs.SharedLinks[token]
			if ok && time.Now().Before(share.Expires) {
				next.ServeHTTP(w, r)
				return
			}
		}

		w.Header().Set("WWW-Authenticate", `Basic realm="Restricted"`)

		auth := r.Header.Get("Authorization")
		if !strings.HasPrefix(auth, "Basic ") {
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

// IPWhitelistMiddleware checks if the request's IP is in the whitelist
func (fs *FileServer) IPWhitelistMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Implement check for IP whitelist
		clientIP := GetClientIP(r, fs.Whitelist)

		if !fs.Whitelist.IsAllowed(clientIP) {
			logger.Warnf("[WHITELIST] Access denied for IP: %s", clientIP)
			http.Error(w, "Access Denied", http.StatusForbidden)
			return
		}

		// logger.Infof("[WHITELIST] Access granted for IP: %s", clientIP)
		next.ServeHTTP(w, r)
	})
}

func checkPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

func GetClientIP(r *http.Request, whitelist *Whitelist) string {
	// Get RemoteIP
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}

	if whitelist.IsTrustedProxy(host) {
		// Check X-Forwarded-For header first (for proxies)
		xff := r.Header.Get("X-Forwarded-For")
		if xff != "" {
			// Take the first IP in case of multiple
			ips := strings.Split(xff, ",")
			return strings.TrimSpace(ips[0])
		}

		// Check X-Real-IP header
		xri := r.Header.Get("X-Real-IP")
		if xri != "" {
			return xri
		}
	}

	return host
}
