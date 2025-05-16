// Package utils has general utility functions
package utils

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"mime"
	"net"
	"os"
	"strings"

	"github.com/grandcat/zeroconf"
	"github.com/patrickhener/goshs/goshsversion"
	"github.com/patrickhener/goshs/logger"
	"golang.org/x/crypto/bcrypt"
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
func RandomNumber() (big.Int, error) {
	n, err := rand.Int(rand.Reader, big.NewInt(1000))
	if err != nil {
		logger.Errorf("when generating random number: %+v", err)
		return *big.NewInt(0), err
	}
	return *n, err
}

// GetInterfaceIpv4Addr will return the ip address by name
func GetInterfaceIpv4Addr(interfaceName string) (addr string, err error) {
	var (
		ief      *net.Interface
		addrs    []net.Addr
		ipv4Addr net.IP
	)
	if ief, err = net.InterfaceByName(interfaceName); err != nil { // get interface
		return
	}
	if addrs, err = ief.Addrs(); err != nil { // get addresses
		return
	}
	for _, addr := range addrs { // get ipv4 address
		if ipv4Addr = addr.(*net.IPNet).IP.To4(); ipv4Addr != nil {
			break
		}
	}
	if ipv4Addr == nil {
		return "", fmt.Errorf("interface %s doesn't have an ipv4 address", interfaceName)
	}
	return ipv4Addr.String(), nil
}

// GetAllIPAdresses will return a map of interface and associated ipv4 addresses for displaying reasons
func GetAllIPAdresses() (map[string]string, error) {
	ifaceAddress := make(map[string]string)

	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	for _, i := range ifaces {
		ip, err := GetInterfaceIpv4Addr(i.Name)
		if err != nil {
			continue
		}

		ifaceAddress[i.Name] = ip

	}
	return ifaceAddress, nil
}

// GenerateHashPassword will take a plaintext masked password and return a bcrypt hash
// This is meant to be used with the filebased access via .goshs file
func GenerateHashedPassword(password []byte) string {
	bytes, err := bcrypt.GenerateFromPassword(password, 14)
	if err != nil {
		logger.Fatalf("error hashing password: %+v", err)
	}
	fmt.Printf("Hash: %s\n", string(bytes))

	return string(bytes)
}

// Contains checks if a string is in a slice of strings
func Contains(slice []string, item string) bool {
	for _, a := range slice {
		if a == item {
			return true
		}
	}
	return false
}

func RegisterZeroconfMDNS(ssl bool, webPort int, webdav bool, webdavPort int, sftp bool, sftpPort int) error {
	// Register zeroconf mDNS
	hostname, err := os.Hostname()
	if err != nil {
		return fmt.Errorf("cannot get hostname for mDNS: %+v", err)
	}
	// Register webPort
	var serviceType string
	var out string
	switch ssl {
	case true:
		serviceType = "_https._tcp"
		out = "https"
	default:
		serviceType = "_http._tcp"
		out = "http"
	}
	zero, err := zeroconf.Register(
		"goshs WebInterface",
		serviceType,
		"local.",
		webPort,
		[]string{fmt.Sprintf("host=%s.local", hostname), "path=/", fmt.Sprintf("version=%s", goshsversion.GoshsVersion)},
		nil,
	)
	if err != nil {
		return fmt.Errorf("zeroconf mDNS did not register successfully: %+v", err)
	}
	defer zero.Shutdown()

	logger.Infof("mDSN service registered as %s://%s.local:%d", out, hostname, webPort)

	// Register webdav if enabled
	if webdav {
		switch ssl {
		case true:
			serviceType = "_webdavs._tcp"
			out = "webdavs"
		default:
			serviceType = "_webdav._tcp"
			out = "webdav"
		}

		zeroDav, err := zeroconf.Register(
			"goshs WebDAV",
			serviceType,
			"local.",
			webdavPort,
			[]string{fmt.Sprintf("host=%s.local", hostname), "path=/", fmt.Sprintf("version=%s", goshsversion.GoshsVersion)},
			nil,
		)
		if err != nil {
			return fmt.Errorf("zeroconf mDNS did not register successfully: %+v", err)
		}
		defer zeroDav.Shutdown()

		logger.Infof("mDSN service registered as %s://%s.local:%d", out, hostname, webdavPort)
	}

	// Register sftp if enabled
	if sftp {
		zeroDav, err := zeroconf.Register(
			"goshs WebDAV",
			"_ssh._tcp",
			"local.",
			webdavPort,
			[]string{fmt.Sprintf("host=%s.local", hostname), "subsystem=sftp", "path=/", fmt.Sprintf("version=%s", goshsversion.GoshsVersion)},
			nil,
		)
		if err != nil {
			return fmt.Errorf("zeroconf mDNS did not register successfully: %+v", err)
		}
		defer zeroDav.Shutdown()

		logger.Infof("mDSN service registered as ssh://%s.local:%d", hostname, sftpPort)
	}

	return nil
}
