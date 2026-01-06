package notify

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/yetanotherparticipant/PipeSec/dynamic/internal/dynscan"
)

func TestChannelsFromEnv(t *testing.T) {
	t.Setenv("TELEGRAM_BOT_TOKEN", "token")
	t.Setenv("TELEGRAM_CHAT_ID", "chat")
	t.Setenv("PIPESEC_WEBHOOK_URL", "https://example.test/webhook")
	t.Setenv("PIPESEC_WEBHOOK_HEADERS", `{"X-Test":"1"}`)

	channels := ChannelsFromEnv()
	if len(channels) != 2 {
		t.Fatalf("expected 2 channels, got %d", len(channels))
	}
}

func TestWebhookChannelSend(t *testing.T) {
	var gotHeader string
	var gotCount int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHeader = r.Header.Get("X-Token")
		defer r.Body.Close()
		var payload map[string]any
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Fatalf("failed to decode payload: %v", err)
		}
		gotCount = int(payload["count"].(float64))
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	channel := NewWebhookChannel(server.URL, map[string]string{"X-Token": "abc"})
	channel.Send("summary", []dynscan.Finding{{Severity: dynscan.SeverityHigh}})

	if gotHeader != "abc" {
		t.Fatalf("expected header abc, got %s", gotHeader)
	}
	if gotCount != 1 {
		t.Fatalf("expected count 1, got %d", gotCount)
	}
}

func TestParseWebhookHeadersEnvInvalidJSON(t *testing.T) {
	t.Setenv("PIPESEC_WEBHOOK_HEADERS", "{bad-json")
	headers := parseWebhookHeadersEnv()
	if len(headers) != 0 {
		t.Fatalf("expected empty headers, got %#v", headers)
	}
}

func TestMain(m *testing.M) {
	os.Exit(m.Run())
}
