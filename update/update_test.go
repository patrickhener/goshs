package update

import (
	"testing"

	"github.com/google/go-github/v42/github"
	"github.com/patrickhener/goshs/goshsversion"
	"github.com/stretchr/testify/require"
)

func TestCheckForUpdates(t *testing.T) {
	oldVersion := "v1.0.0"

	result, _ := CheckForUpdates(oldVersion)
	require.Equal(t, result, true)

	result, _ = CheckForUpdates(goshsversion.GoshsVersion)
	require.Equal(t, result, false)
}

func TestGetLatestReleaseInvalid(t *testing.T) {
	_, err := getLatestRelease("invalid", "invalid")
	require.Error(t, err)
}

func TestUpdateTool(t *testing.T) {
	oldVersion := "v1.0.0"

	err := UpdateTool(oldVersion)
	require.NoError(t, err)

	err = UpdateTool(goshsversion.GoshsVersion)
	require.NoError(t, err)
}

func TestGetAssetURLErr(t *testing.T) {
	name := "invalidAsset"
	release := &github.RepositoryRelease{
		Assets: []*github.ReleaseAsset{
			{
				Name: &name,
			},
		},
	}

	_, err := getAssetURL(release)
	require.Error(t, err)
}

func TestInvalidApplyUpdate(t *testing.T) {
	err := applyUpdate("http://invalid")
	require.Error(t, err)

	err = applyUpdate("https://hesec.de")
	require.Error(t, err)
}
