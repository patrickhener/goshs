package update

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"net/http"
	"runtime"
	"strings"
	"time"

	"github.com/google/go-github/v42/github"
	"github.com/inconshreveable/go-update"
	"github.com/patrickhener/goshs/logger"
)

const (
	owner             = "patrickhener"
	repo              = "goshs"
	GOSHS_WINDOWS_64  = "goshs_windows_x86_64.tar.gz"
	GOSHS_WINDOWS_32  = "goshs_windows_386.tar.gz"
	GOSHS_WINDOWS_ARM = "goshs_windows_arm64.tar.gz"
	GOSHS_LINUX_64    = "goshs_linux_x86_64.tar.gz"
	GOSHS_LINUX_32    = "goshs_linux_386.tar.gz"
	GOSHS_LINUX_ARM   = "goshs_linux_arm64.tar.gz"
	GOSHS_DARWIN_64   = "goshs_darwin_x86_64.tar.gz"
	GOSHS_DARWIN_ARM  = "goshs_darwin_arm64.tar.gz"
)

func CheckForUpdates(version string) (bool, string) {
	latestRelease, err := getLatestRelease(owner, repo)
	if err != nil {
		return false, err.Error()
	}

	if latestRelease.GetTagName() != version {
		return true, latestRelease.GetTagName()
	}
	return false, ""
}

func UpdateTool(version string) error {
	latestRelease, err := getLatestRelease(owner, repo)
	if err != nil {
		return fmt.Errorf("failed to fetch latest release: %+v", err)
	}

	if latestRelease.GetTagName() == version {
		logger.Infof("You are already running the newest version (%s) of goshs", version)
		return nil
	}

	logger.Infof("Updating goshs to version %s...", latestRelease.GetTagName())

	assetURL, err := getAssetURL(latestRelease)
	if err != nil {
		return fmt.Errorf("failed to get latest release: %+v", err)
	}

	err = applyUpdate(assetURL)
	if err != nil {
		return fmt.Errorf("failed to apply update: %+v", err)
	}

	logger.Info("Goshs was updated successfully")
	return nil
}

func getLatestRelease(owner string, repo string) (*github.RepositoryRelease, error) {
	client := github.NewClient(nil)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	release, _, err := client.Repositories.GetLatestRelease(ctx, owner, repo)
	if err != nil {
		return nil, err
	}
	return release, nil
}

func getAssetURL(release *github.RepositoryRelease) (string, error) {
	assets := release.Assets
	for _, asset := range assets {
		assetName := asset.GetName()
		if assetMatchesOSAndArch(assetName) {
			return asset.GetBrowserDownloadURL(), nil
		}
	}
	return "", fmt.Errorf("no suitable release asset found for OS: %s, ARCH: %s", runtime.GOOS, runtime.GOARCH)
}

func applyUpdate(assetURL string) error {
	resp, err := http.Get(assetURL)
	if err != nil {
		return fmt.Errorf("failed to download update: %+v", err)
	}
	defer resp.Body.Close()

	goshsReader, err := tarXVZF(resp)
	if err != nil {
		return fmt.Errorf("failed to decompress the downloaded file: %+v", err)
	}

	err = update.Apply(goshsReader, update.Options{})
	if err != nil {
		return fmt.Errorf("failed to apply update: %+v", err)
	}

	return nil
}

func assetMatchesOSAndArch(assetName string) bool {
	return (runtime.GOOS == "windows" && runtime.GOARCH == "amd64" && assetName == GOSHS_WINDOWS_64) ||
		(runtime.GOOS == "windows" && runtime.GOARCH == "386" && assetName == GOSHS_WINDOWS_32) ||
		(runtime.GOOS == "windows" && runtime.GOARCH == "arm64" && assetName == GOSHS_WINDOWS_ARM) ||
		(runtime.GOOS == "linux" && runtime.GOARCH == "amd64" && assetName == GOSHS_LINUX_64) ||
		(runtime.GOOS == "linux" && runtime.GOARCH == "386" && assetName == GOSHS_LINUX_32) ||
		(runtime.GOOS == "linux" && runtime.GOARCH == "arm64" && assetName == GOSHS_LINUX_ARM) ||
		(runtime.GOOS == "darwin" && runtime.GOARCH == "amd64" && assetName == GOSHS_DARWIN_64) ||
		(runtime.GOOS == "darwin" && runtime.GOARCH == "arm64" && assetName == GOSHS_DARWIN_ARM)
}

func tarXVZF(response *http.Response) (io.Reader, error) {
	gzipReader, err := gzip.NewReader(response.Body)
	if err != nil {
		return nil, err
	}
	defer gzipReader.Close()

	tarReader := tar.NewReader(gzipReader)

	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		}

		if err != nil {
			return nil, err
		}

		if strings.Contains(header.Name, "goshs") {
			return io.LimitReader(tarReader, header.Size), nil
		}
	}

	return nil, fmt.Errorf("%s", "end of function - should not happen")
}
