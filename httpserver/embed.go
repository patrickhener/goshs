package httpserver

import "embed"

// Static will provide the embedded files as http.FS
//
//go:embed static
var static embed.FS
