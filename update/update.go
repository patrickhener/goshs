package update

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"runtime"
	"strings"
	"time"

	"github.com/charmbracelet/glamour"
	"github.com/google/go-github/v85/github"
	"github.com/inconshreveable/go-update"
	"goshs.de/goshs/v2/logger"
)

const (
	owner             = "patrickhener"
	repo              = "goshs"
	GOSHS_CHECKSUMS   = "checksums.txt"
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

	assetURL, assetName, err := getAssetURL(latestRelease)
	if err != nil {
		return fmt.Errorf("failed to get latest release: %+v", err)
	}

	expectedSum, err := fetchChecksum(latestRelease, assetName)
	if err != nil {
		return fmt.Errorf("failed to fetch checksum: %+v", err)
	}

	if err = applyUpdate(assetURL, expectedSum); err != nil {
		return fmt.Errorf("failed to apply update: %+v", err)
	}

	logger.Infof("goshs updated successfully to %s", latestRelease.GetTagName())

	changelogs, err := getChangelogsBetweenVersions(version, latestRelease.GetTagName())
	if err != nil {
		// Fallback to just showing the latest release changelog
		renderChangelog(version, latestRelease.GetTagName(), []releaseNotes{
			{tag: latestRelease.GetTagName(), body: latestRelease.GetBody()},
		})
	} else {
		renderChangelog(version, latestRelease.GetTagName(), changelogs)
	}

	return nil
}

type releaseNotes struct {
	tag  string
	body string
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

func getReleases(owner string, repo string) ([]*github.RepositoryRelease, error) {
	client := github.NewClient(nil)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	var allReleases []*github.RepositoryRelease
	opts := &github.ListOptions{PerPage: 50}

	for {
		releases, resp, err := client.Repositories.ListReleases(ctx, owner, repo, opts)
		if err != nil {
			return nil, err
		}
		allReleases = append(allReleases, releases...)
		if resp.NextPage == 0 {
			break
		}
		opts.Page = resp.NextPage
	}
	return allReleases, nil
}

func getChangelogsBetweenVersions(currentVersion, targetVersion string) ([]releaseNotes, error) {
	releases, err := getReleases(owner, repo)
	if err != nil {
		return nil, err
	}

	var notes []releaseNotes
	for _, r := range releases {
		tag := r.GetTagName()
		if isVersionBetween(tag, currentVersion, targetVersion) {
			notes = append(notes, releaseNotes{tag: tag, body: r.GetBody()})
		}
	}

	return notes, nil
}

func isVersionBetween(tag, current, target string) bool {
	cv := parseSemver(current)
	tv := parseSemver(target)
	v := parseSemver(tag)

	if cv == nil || tv == nil || v == nil {
		return false
	}

	// Include target, exclude current
	if compareSemver(v, cv) <= 0 {
		return false
	}
	if compareSemver(v, tv) > 0 {
		return false
	}
	return true
}

type semver struct {
	major, minor, patch int
}

func parseSemver(s string) *semver {
	s = strings.TrimPrefix(s, "v")
	parts := strings.SplitN(s, ".", 3)
	if len(parts) != 3 {
		return nil
	}
	sv := &semver{}
	if _, err := fmt.Sscanf(parts[0], "%d", &sv.major); err != nil {
		return nil
	}
	if _, err := fmt.Sscanf(parts[1], "%d", &sv.minor); err != nil {
		return nil
	}
	if _, err := fmt.Sscanf(parts[2], "%d", &sv.patch); err != nil {
		return nil
	}
	return sv
}

func compareSemver(a, b *semver) int {
	if a.major != b.major {
		return a.major - b.major
	}
	if a.minor != b.minor {
		return a.minor - b.minor
	}
	return a.patch - b.patch
}

func renderChangelog(currentVersion, targetVersion string, notes []releaseNotes) {
	var md strings.Builder
	md.WriteString(fmt.Sprintf("# Changelog %s → %s\n\n", currentVersion, targetVersion))

	for i := len(notes) - 1; i >= 0; i-- {
		n := notes[i]
		md.WriteString(fmt.Sprintf("## %s\n\n%s\n\n", n.tag, n.body))
	}

	rendered, err := glamour.Render(md.String(), "dark")
	if err != nil {
		// Fallback to raw markdown
		fmt.Printf("\n%s\n", md.String())
		return
	}
	fmt.Print(rendered)
}

func getAssetURL(release *github.RepositoryRelease) (url string, name string, err error) {
	for _, asset := range release.Assets {
		n := asset.GetName()
		if assetMatchesOSAndArch(n) {
			return asset.GetBrowserDownloadURL(), n, nil
		}
	}
	return "", "", fmt.Errorf("no suitable release asset found for OS: %s, ARCH: %s", runtime.GOOS, runtime.GOARCH)
}

// fetchChecksum downloads checksums.txt from the release and returns the
// SHA-256 digest (raw bytes) for the named asset. goreleaser writes each
// line as "<hex>  <filename>".
func fetchChecksum(release *github.RepositoryRelease, assetName string) ([]byte, error) {
	var checksumURL string
	for _, asset := range release.Assets {
		if asset.GetName() == GOSHS_CHECKSUMS {
			checksumURL = asset.GetBrowserDownloadURL()
			break
		}
	}
	if checksumURL == "" {
		return nil, fmt.Errorf("no %s asset found in release", GOSHS_CHECKSUMS)
	}

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Get(checksumURL)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil {
		return nil, err
	}

	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 2 && fields[1] == assetName {
			return hex.DecodeString(fields[0])
		}
	}
	return nil, fmt.Errorf("no checksum found for %s in %s", assetName, GOSHS_CHECKSUMS)
}

func applyUpdate(assetURL string, expectedSum []byte) error {
	client := &http.Client{Timeout: 5 * time.Minute}
	resp, err := client.Get(assetURL)
	if err != nil {
		return fmt.Errorf("failed to download update: %+v", err)
	}
	defer resp.Body.Close()

	// Buffer the entire archive so we can verify its checksum before extraction.
	archiveData, err := io.ReadAll(io.LimitReader(resp.Body, 200*1024*1024))
	if err != nil {
		return fmt.Errorf("failed to read update archive: %+v", err)
	}

	sum := sha256.Sum256(archiveData)
	if !bytes.Equal(sum[:], expectedSum) {
		return fmt.Errorf("checksum mismatch: expected %x, got %x — aborting update", expectedSum, sum[:])
	}
	logger.Infof("update archive checksum verified: %x", sum)

	goshsReader, err := tarXVZFFromBytes(archiveData)
	if err != nil {
		return fmt.Errorf("failed to decompress the downloaded file: %+v", err)
	}

	if err = update.Apply(goshsReader, update.Options{}); err != nil {
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

func tarXVZFFromBytes(archiveData []byte) (io.Reader, error) {
	gzipReader, err := gzip.NewReader(bytes.NewReader(archiveData))
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
			data, err := io.ReadAll(io.LimitReader(tarReader, header.Size))
			if err != nil {
				return nil, err
			}
			return bytes.NewReader(data), nil
		}
	}

	return nil, fmt.Errorf("no goshs binary found in release archive")
}
