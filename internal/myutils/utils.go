package myutils

import (
	"fmt"
	"math/rand"
	"mime"
	"strings"
)

// ByteCountDecimal generates human readable file sizes and returns a string
func ByteCountDecimal(b int64) string {
	const unit = 1000
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := int64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(b)/float64(div), "kMGTPE"[exp])
}

// MimeByExtension returns the mimetype string depending on the filename and its extension
func MimeByExtension(n string) string {
	return mime.TypeByExtension(ReturnExt(n))
}

// ReturnExt returns the extension without from a filename
func ReturnExt(n string) string {
	extSlice := strings.Split(n, ".")
	return "." + extSlice[len(extSlice)-1]
}

// RandomNumber returns a random int64
func RandomNumber() int64 {
	return rand.Int63()
}
