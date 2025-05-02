package httpserver

import (
	"net/http"
)

// NewCustomMux creates a new CustomMux instance.
func NewCustomMux() *CustomMux {
	return &CustomMux{
		mux: http.NewServeMux(),
	}
}

// Use simulates the behavior of http.ServeMux.Use, allowing you to add middleware to the CustomMux.
func (cm *CustomMux) Use(mw Middleware) {
	cm.middleware = append(cm.middleware, mw)
}

// Handle registers a new route with the CustomMux, applying all middleware in reverse order.
func (cm *CustomMux) Handle(pattern string, handler http.Handler) {
	final := handler
	for i := len(cm.middleware) - 1; i >= 0; i-- {
		final = cm.middleware[i](final)
	}

	cm.mux.Handle(pattern, final)
}

// HandleFunc registers a new route with the CustomMux, applying all middleware in reverse order.
func (cm *CustomMux) HandleFunc(pattern string, handler http.HandlerFunc) {
	cm.Handle(pattern, handler)
}

// ServeHTTP implements the http.Handler interface, allowing the CustomMux to be used as an HTTP server.
func (cm *CustomMux) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	cm.mux.ServeHTTP(w, r)
}
