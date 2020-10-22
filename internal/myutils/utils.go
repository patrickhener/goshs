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

// CheckSpecialPath will check a slice of special paths against
// a folder on disk and return true if it matches
func CheckSpecialPath(check string) bool {
	specialPaths := []string{"425bda8487e36deccb30dd24be590b8744e3a28a8bb5a57d9b3fcd24ae09ad3c", "cf985bddf28fed5d5c53b069d6a6ebe601088ca6e20ec5a5a8438f8e1ffd9390", "14644be038ea0118a1aadfacca2a7d1517d7b209c4b9674ee893b1944d1c2d54"}

	for _, item := range specialPaths {
		if item == check {
			return true
		}
	}

	return false
}
