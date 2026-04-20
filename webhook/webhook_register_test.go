package webhook

import (
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRegister_Discord(t *testing.T) {
	wh := Register(true, "http://example.com", "discord", []string{"upload", "download"})
	require.NotNil(t, wh)
	require.True(t, (*wh).GetEnabled())
	require.Equal(t, []string{"upload", "download"}, (*wh).GetEvents())
	require.True(t, (*wh).Contains("upload"))
	require.False(t, (*wh).Contains("delete"))
}

func TestRegister_Slack(t *testing.T) {
	wh := Register(true, "http://example.com", "slack", []string{"all"})
	require.NotNil(t, wh)
	require.True(t, (*wh).GetEnabled())
	require.Equal(t, []string{"all"}, (*wh).GetEvents())
	require.True(t, (*wh).Contains("all"))
}

func TestRegister_Mattermost(t *testing.T) {
	wh := Register(true, "http://example.com", "mattermost", []string{"verbose"})
	require.NotNil(t, wh)
	require.True(t, (*wh).GetEnabled())
	require.Equal(t, []string{"verbose"}, (*wh).GetEvents())
	require.True(t, (*wh).Contains("verbose"))
}

func TestRegister_Default(t *testing.T) {
	wh := Register(true, "http://example.com", "unknown", []string{})
	require.NotNil(t, wh)
	require.False(t, (*wh).GetEnabled())
}

func TestDiscordWebhook_GetEnabled(t *testing.T) {
	d := &DiscordWebhook{Enabled: true}
	require.True(t, d.GetEnabled())
	d.Enabled = false
	require.False(t, d.GetEnabled())
}

func TestDiscordWebhook_GetEvents(t *testing.T) {
	d := &DiscordWebhook{Events: []string{"upload", "delete"}}
	require.Equal(t, []string{"upload", "delete"}, d.GetEvents())
}

func TestDiscordWebhook_Contains(t *testing.T) {
	d := &DiscordWebhook{Events: []string{"upload"}}
	require.True(t, d.Contains("upload"))
	require.False(t, d.Contains("delete"))
}

func TestSlackWebhook_GetEnabled(t *testing.T) {
	s := &SlackWebhook{Enabled: true}
	require.True(t, s.GetEnabled())
}

func TestSlackWebhook_GetEvents(t *testing.T) {
	s := &SlackWebhook{Events: []string{"all"}}
	require.Equal(t, []string{"all"}, s.GetEvents())
}

func TestSlackWebhook_Contains(t *testing.T) {
	s := &SlackWebhook{Events: []string{"upload"}}
	require.True(t, s.Contains("upload"))
	require.False(t, s.Contains("delete"))
}

func TestMattermostWebhook_GetEnabled(t *testing.T) {
	m := &MattermostWebhook{Enabled: true}
	require.True(t, m.GetEnabled())
}

func TestMattermostWebhook_GetEvents(t *testing.T) {
	m := &MattermostWebhook{Events: []string{"verbose"}}
	require.Equal(t, []string{"verbose"}, m.GetEvents())
}

func TestMattermostWebhook_Contains(t *testing.T) {
	m := &MattermostWebhook{Events: []string{"verbose"}}
	require.True(t, m.Contains("verbose"))
	require.False(t, m.Contains("upload"))
}

func TestMattermostWebhook_Send_NoIcon(t *testing.T) {
	ts := httptest.NewServer(nil)
	ts.Close()
	m := &MattermostWebhook{URL: "http://127.0.0.1:1", Username: "bot"}
	err := m.Send("test")
	require.Error(t, err)
}
