package notify

import (
	"bytes"
	"encoding/json"
	"net/http"
	"time"

	"github.com/yetanotherparticipant/PipeSec/dynamic/internal/dynscan"
)

type TelegramChannel struct {
	token  string
	chatID string
	client *http.Client
}

func NewTelegramChannel(token, chatID string) *TelegramChannel {
	return &TelegramChannel{
		token:  token,
		chatID: chatID,
		client: &http.Client{Timeout: 5 * time.Second},
	}
}

func (t *TelegramChannel) Send(msg string, findings []dynscan.Finding) {
	if t == nil || t.token == "" || t.chatID == "" {
		return
	}
	body, _ := json.Marshal(map[string]string{
		"chat_id":    t.chatID,
		"text":       msg,
		"parse_mode": "Markdown",
	})
	req, err := http.NewRequest(
		http.MethodPost,
		"https://api.telegram.org/bot"+t.token+"/sendMessage",
		bytes.NewReader(body),
	)
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := t.client.Do(req)
	if err != nil {
		return
	}
	resp.Body.Close()
}
