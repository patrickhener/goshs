package httpserver

import (
	"crypto/subtle"
	"fmt"
	"net"
	"net/http"
	"runtime"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
	"goshs.de/goshs/v2/logger"
)

const (
	authMaxFailures  = 5
	authLockDuration = 30 * time.Second
)

// verifyCredentials checks the Authorization header against the configured
// username/password (plaintext or bcrypt). Returns the raw header value on
// success so it can be cached, or an empty string on failure.
// Repeated failures from the same IP are rate-limited.
func (fs *FileServer) verifyCredentials(r *http.Request) (authVal string, ok bool) {
	auth := r.Header.Get("Authorization")
	if !strings.HasPrefix(auth, "Basic ") {
		return "", false
	}
	authVal = auth[len("Basic "):]

	// Fast path: already verified this credential in this instance
	fs.authCacheMu.RLock()
	cached := fs.authCache[authVal]
	fs.authCacheMu.RUnlock()
	if cached {
		return authVal, true
	}

	// Rate-limit check: reject IPs that have exceeded the failure threshold
	clientIP, _, _ := net.SplitHostPort(r.RemoteAddr)
	if clientIP == "" {
		clientIP = r.RemoteAddr
	}
	fs.authFailMu.Lock()
	if fs.authFailures == nil {
		fs.authFailures = make(map[string]*authFailEntry)
	}
	entry := fs.authFailures[clientIP]
	if entry != nil && time.Now().Before(entry.lockedUntil) {
		fs.authFailMu.Unlock()
		logger.Warnf("[AUTH] %s is locked out due to repeated failures", clientIP)
		return "", false
	}
	fs.authFailMu.Unlock()

	username, password, authOK := r.BasicAuth()
	if !authOK {
		return "", false
	}

	var verified bool
	if strings.HasPrefix(fs.Pass, "$2a$") {
		if username == fs.User {
			verified = bcrypt.CompareHashAndPassword([]byte(fs.Pass), []byte(password)) == nil
		}
	} else {
		verified = subtle.ConstantTimeCompare([]byte(username), []byte(fs.User)) == 1 &&
			subtle.ConstantTimeCompare([]byte(password), []byte(fs.Pass)) == 1
	}

	if !verified {
		fs.authFailMu.Lock()
		if fs.authFailures == nil {
			fs.authFailures = make(map[string]*authFailEntry)
		}
		if entry == nil {
			entry = &authFailEntry{}
			fs.authFailures[clientIP] = entry
		}
		entry.count++
		if entry.count >= authMaxFailures {
			entry.lockedUntil = time.Now().Add(authLockDuration)
			logger.Warnf("[AUTH] %s locked out after %d failed attempts", clientIP, entry.count)
		}
		fs.authFailMu.Unlock()
		return "", false
	}

	// Success: clear failure record and cache the credential
	fs.authFailMu.Lock()
	delete(fs.authFailures, clientIP)
	fs.authFailMu.Unlock()

	fs.authCacheMu.Lock()
	if fs.authCache == nil {
		fs.authCache = make(map[string]bool)
	}
	fs.authCache[authVal] = true
	fs.authCacheMu.Unlock()

	return authVal, true
}

// BasicAuthMiddleware is a middleware to handle the basic auth
func (fs *FileServer) BasicAuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := r.URL.Query().Get("token")
		if token != "" {
			fs.sharedLinksMu.RLock()
			_, ok := fs.SharedLinks[token]
			fs.sharedLinksMu.RUnlock()
			if ok {
				next.ServeHTTP(w, r)
				return
			}
		}

		w.Header().Set("WWW-Authenticate", `Basic realm="Restricted"`)
		if _, ok := fs.verifyCredentials(r); !ok {
			http.Error(w, "Not authorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// InvisibleBasicAuthMiddleware is a middleware to handle basic auth in invisible mode
func (fs *FileServer) InvisibleBasicAuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, ok := fs.verifyCredentials(r); !ok {
			fs.handleInvisible(w)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// ServerHeaderMiddleware sets a custom Server header for all responses
func (fs *FileServer) ServerHeaderMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Invisible mode
		if fs.Invisible {
			next.ServeHTTP(w, r)
			return
		}
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
			if !fs.Invisible {
				http.Error(w, "Access Denied", http.StatusForbidden)
				return
			} else {
				fs.handleInvisible(w)
				return
			}
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
