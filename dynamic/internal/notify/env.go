package notify

import (
	"encoding/json"
	"os"
	"strings"
)

func ChannelsFromEnv() []Channel {
	channels := make([]Channel, 0, 2)

	token := strings.TrimSpace(os.Getenv("TELEGRAM_BOT_TOKEN"))
	chatID := strings.TrimSpace(os.Getenv("TELEGRAM_CHAT_ID"))
	if token != "" && chatID != "" {
		channels = append(channels, NewTelegramChannel(token, chatID))
	}

	webhookURL := strings.TrimSpace(os.Getenv("PIPESEC_WEBHOOK_URL"))
	if webhookURL != "" {
		channels = append(channels, NewWebhookChannel(webhookURL, parseWebhookHeadersEnv()))
	}

	return channels
}

func parseWebhookHeadersEnv() map[string]string {
	raw := strings.TrimSpace(os.Getenv("PIPESEC_WEBHOOK_HEADERS"))
	if raw == "" {
		return map[string]string{}
	}

	var data map[string]string
	if err := json.Unmarshal([]byte(raw), &data); err != nil {
		return map[string]string{}
	}
	out := map[string]string{}
	for k, v := range data {
		if strings.TrimSpace(k) == "" {
			continue
		}
		out[k] = v
	}
	return out
}
