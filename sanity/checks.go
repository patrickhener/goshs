package sanity

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"goshs.de/goshs/ca"
	"goshs.de/goshs/goshsversion"
	"goshs.de/goshs/logger"
	"goshs.de/goshs/options"
	"goshs.de/goshs/update"
)

func Sanitize(opts *options.Options) (*options.Options, error) {
	var err error
	wd, _ := os.Getwd()

	// Abspath for webroot
	// Trim trailing / for linux/mac and \ for windows
	opts.Webroot = strings.TrimSuffix(opts.Webroot, "/")
	opts.Webroot = strings.TrimSuffix(opts.Webroot, "\\")
	if !filepath.IsAbs(opts.Webroot) {
		opts.Webroot, err = filepath.Abs(filepath.Join(wd, opts.Webroot))
		if err != nil {
			return opts, fmt.Errorf("Webroot cannot be constructed: %w", err)
		}
	}

	return opts, nil
}

func Check(opts *options.Options) (*options.Options, error) {
	if opts.ConfigFile != "" {
		if opts.Webroot == filepath.Dir(opts.ConfigPath) {
			logger.Warn("You are hosting your config file in the webroot of goshs. This is not recommended.")
			// Check if the process user can write the config file
			file, err := os.OpenFile(opts.ConfigPath, os.O_WRONLY|os.O_APPEND, 0600)
			if err != nil {
				return opts, err
			}
			file.Close()
			return opts, fmt.Errorf("%s", "The config file is accessible via goshs and is writeable by the user running goshs. This is a security issue. Read the docs at https://goshs.de/en/usage/config/index.html")
		}

		if !strings.Contains(opts.BasicAuth, "$2a$") {
			logger.Warn("The password in the config file is not hashed. This is not recommended. Use goshs -H to hash the password.")
		}
	}
	// Sanity check for invisible mode
	if opts.Invisible {
		if opts.SFTP || opts.WebDav {
			opts.SFTP = false
			opts.WebDav = false
			opts.MDNS = false
			opts.Silent = false
			opts.DNS = false
			opts.SMTP = false
			logger.Warn("Invisible mode activated, disabling SFTP, WebDAV, silent mode, DNS, SMTP and mDNS support")
		}
	}

	// Sanity check for upload only vs read only
	if opts.UploadOnly && opts.ReadOnly {
		logger.Fatal("You can only select either 'upload only' or 'read only', not both.")
	}

	// Sanity check if cli mode is combined with auth and tls
	if opts.CLI && (!opts.SSL || opts.BasicAuth == "") {
		if opts.CLI && (!opts.SSL || opts.CertAuth == "") {
			logger.Fatal("With cli mode you need to enable basic/cert auth and tls for security reasons.")
		}
	}

	// Sanity check if CA mode enabled you will also need TLS enabled in some way
	if opts.CertAuth != "" && !opts.SSL {
		logger.Fatal("To use certificate based authentication with a CA cert you will need tls in any mode (-ss, -sk/-sc, -p12, -sl)")
	}

	// Sanity check either user:pass or keyfile when using sftp
	if opts.SFTP && (opts.BasicAuth == "" && opts.SFTPKeyFile == "") {
		logger.Fatal("When using SFTP you need to either specify an authorized keyfile using -sfk or username and password using -b")
	}

	// Sanity check: empty username is not valid for SFTP password auth
	if opts.SFTP && strings.HasPrefix(opts.BasicAuth, ":") {
		logger.Fatal("When using SFTP with password authentication, the username cannot be empty. Please provide a non-empty username with -b 'user:pass'.")
	}

	if yes, out := update.CheckForUpdates(goshsversion.GoshsVersion); yes {
		logger.Warnf("There is a newer Version (%s) of goshs available. Run --update to update goshs.", out)
	} else {
		if out != "" {
			logger.Warnf("Failed to check for updates: %+v", out)
		} else {
			logger.Infof("You are running the newest version (%s) of goshs", goshsversion.GoshsVersion)
		}
	}

	return opts, nil
}

func FurtherProcessing(opts *options.Options) (*options.Options, error) {
	// check for basic auth
	if opts.BasicAuth != "" {
		auth := strings.SplitN(opts.BasicAuth, ":", 2)
		if len(auth) < 2 {
			fmt.Println("Wrong basic auth format. Please provide user:password separated by a colon")
			os.Exit(-1)
		}
		opts.Username = auth[0]
		opts.Password = auth[1]
	}

	// If Let's Encrypt is in play we need to fetch the key and cert, write them to disc and set their path in MyKey and MyCert
	if opts.LetsEncrypt {
		ca.GetLECertificateAndKey(opts.LEEmail, strings.Split(opts.LEDomains, ","), opts.LEHTTPPort, opts.LETLSPort)
		opts.MyCert = "cert"
		opts.MyKey = "key"
	}

	// If a logpath/-file is provided via -o/--output set the multiwriter to output both
	if opts.Output != "" {
		if !filepath.IsAbs(opts.Output) {
			// If the provided path is not an abspath then merge with CWD
			wd, _ := os.Getwd()
			opts.Output = filepath.Join(wd, opts.Output)
		}

		logFile, err := os.OpenFile(opts.Output, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
		if err != nil {
			logger.Panicf("Cannot open file to write output logfile: %s - %+v", opts.Output, err)
		}

		multiWriter := io.MultiWriter(os.Stdout, logFile)
		logger.LogFile(multiWriter)
	}

	return opts, nil
}
