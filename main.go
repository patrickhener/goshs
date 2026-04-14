package main

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"goshs.de/goshs/config"
	"goshs.de/goshs/logger"
	"goshs.de/goshs/options"
	"goshs.de/goshs/sanity"
	"goshs.de/goshs/server"
)

func main() {
	var err error

	// flags
	opts, print := options.Parse()

	// Print config
	if print {
		config, err := config.PrintExample()
		if err != nil {
			panic(err)
		}
		fmt.Println(config)
		os.Exit(0)
	}

	// Load config
	if opts.ConfigFile != "" {
		opts, err = config.LoadConfig(opts)
		if err != nil {
			logger.Fatalf("Failed to load config: %+v", err)
		}
	}

	// Sanitize webroot and check sanity
	opts, err = sanity.Sanitize(opts)
	if err != nil {
		logger.Fatalf("Failed to sanitize webroot: %+v", err)
	}

	opts, err = sanity.Check(opts)
	if err != nil {
		logger.Fatalf("Sanity check failed: %+v", err)
	}

	// Further processing of options
	opts, err = sanity.FurtherProcessing(opts)
	if err != nil {
		logger.Fatalf("Further processing failed: %+v", err)
	}

	// Start all server
	server.StartAll(opts)

	done := make(chan os.Signal, 1)
	signal.Notify(done, os.Interrupt, syscall.SIGINT, syscall.SIGTERM)
	<-done
	logger.Infof("Received CTRL+C, exiting...")
}
