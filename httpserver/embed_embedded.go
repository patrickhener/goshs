package httpserver

import "embed"

// Embedded will provide additional embedded files as http.FS
//
//go:embed embedded
var embedded embed.FS
