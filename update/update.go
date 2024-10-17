package update

import (
	"context"
	"fmt"
	"net/http"
	"runtime"
	"time"

	"github.com/google/go-github/v42/github"
	"github.com/inconshreveable/go-update"
	"github.com/patrickhener/goshs/logger"
)

const (
	owner             = "patrickhener"
	repo              = "goshs"
	GOSHS_WINDOWS_64  = "goshs_windows_x86_64.exe"
	GOSHS_WINDOWS_32  = "goshs_windows_386.exe"
	GOSHS_WINDOWS_ARM = "goshs_windows_arm64.exe"
	GOSHS_LINUX_64    = "goshs_linux_x86_64"
	GOSHS_LINUX_32    = "goshs_linux_386"
	GOSHS_LINUX_ARM   = "goshs_linux_arm64"
	GOSHS_DARWIN_64   = "goshs_darwin_x86_64"
	GOSHS_DARWIN_ARM  = "goshs_darwin_arm64"
)

func CheckForUpdates(version string) (bool, string) {
	latestRelease, err := getLatestRelease()
	if err != nil {
		return false, err.Error()
	}

	if latestRelease.GetTagName() != version {
		return true, latestRelease.GetTagName()
	}
	return false, ""
}

func UpdateTool(version string) error {
	latestRelease, err := getLatestRelease()
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

func getLatestRelease() (*github.RepositoryRelease, error) {
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

	err = update.Apply(resp.Body, update.Options{})
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
