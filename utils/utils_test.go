package utils

import (
	"math/big"
	"runtime"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

const (
	cssCorrectMime       string = "text/css; charset=utf-8"
	jsCorrectMime        string = "text/javascript; charset=utf-8"
	htmlCorrectMime      string = "text/html; charset=utf-8"
	jpgCorretMime        string = "image/jpeg"
	correctExt           string = ".txt"
	filename             string = "test.csv.txt"
	loopbackInterface    string = "lo"
	loopbackInterfaceMac string = "lo0"
	correctIP                   = "127.0.0.1"
)

func TestByteCountDecimal(t *testing.T) {
	res100 := ByteCountDecimal(100)
	if res100 != "100 B" {
		t.Errorf("Error in ByteCountDecimal, got: %s  - want %s", res100, "100 B")
	}

	res1024 := ByteCountDecimal(1024)
	if res1024 != "1.0 kB" {
		t.Errorf("Error in ByteCountDecimal, got: %s  - want %s", res1024, "1.0 kB")
	}

	res1024000 := ByteCountDecimal(1024000)
	if res1024000 != "1.0 MB" {
		t.Errorf("Error in ByteCountDecimal, got: %s  - want %s", res1024000, "1.0 MB")
	}

	res1024000000 := ByteCountDecimal(1024000000)
	if res1024000000 != "1.0 GB" {
		t.Errorf("Error in ByteCountDecimal, got: %s  - want %s", res1024000000, "1.0 GB")
	}
}
func TestMimeByExtension(t *testing.T) {
	tests := []struct {
		filename string
		expected string
	}{
		{"file.txt", "text/plain; charset=utf-8"},
		{"index.html", "text/html; charset=utf-8"},
		{"style.css", "text/css; charset=utf-8"},
		{"script.js", "text/javascript; charset=utf-8"},
		{"image.jpg", "image/jpeg"},
		{"archive.zip", "application/zip"},
		{"unknownfile", ""},
		{"", ""},
	}

	for _, test := range tests {
		actual := MimeByExtension(test.filename)
		require.Equal(t, test.expected, actual, "failed on %s", test.filename)
	}
}

func TestReturnExt(t *testing.T) {
	ext := ReturnExt(filename)
	if ext != correctExt {
		t.Errorf("Error in ReturnExt: want %s - got %s", correctExt, ext)
	}
}

func TestRandomNumber(t *testing.T) {
	n, err := RandomNumber()
	require.NoError(t, err, "RandomNumber should not return an error")
	require.True(t, n.Cmp(big.NewInt(0)) >= 0, "Random number should be >= 0")
	require.True(t, n.Cmp(big.NewInt(1000)) < 0, "Random number should be < 1000")
}

func TestGetIPv4Addr(t *testing.T) {
	os := runtime.GOOS
	var lo string
	if os == "darwin" {
		lo = loopbackInterfaceMac
	} else {
		lo = loopbackInterface
	}
	res, err := GetInterfaceIpv4Addr(lo)
	if err != nil {
		t.Fatal(err)
	}
	if res != correctIP {
		t.Errorf("Error in GetIPv4Addr: want %s - got %s", correctIP, res)
	}

	// Test invalid interface
	addr, err := GetInterfaceIpv4Addr("foobar0")
	require.Error(t, err)
	require.Empty(t, addr)
}

func TestContains(t *testing.T) {
	slice := []string{"test1", "test2", "test3"}
	result := Contains(slice, "test2")
	if !result {
		t.Errorf("Error in Contains: want true - got %+v", result)
	}

	negative := Contains(slice, "foo")
	if negative {
		t.Errorf("Error in Contains: want false - got %+v", result)
	}
}

func TestGenerateHashedPassword(t *testing.T) {
	password := []byte("test1234")

	result := GenerateHashedPassword(password)

	if !strings.HasPrefix(result, "$2a$14$") {
		t.Errorf("Error in GenerateHashedPassword: want suffix $2a$14$ - got: %s", result[:6])
	}

	if len(result) != 60 {
		t.Errorf("Error in GenerateHashedPassword: Resulting length should be 66 - got: %d", len(result))
	}
}

func TestGetAllIPAdresses(t *testing.T) {
	ifacesMap, err := GetAllIPAdresses()
	require.NoError(t, err)
	require.NotNil(t, ifacesMap)

	// If there are interfaces, each key should map to a non-empty IP string
	for iface, ip := range ifacesMap {
		require.NotEmpty(t, iface, "Interface name should not be empty")
		require.NotEmpty(t, ip, "IP address should not be empty")
	}
}
