package notify

import (
	"bytes"
	"encoding/json"
	"net/http"
	"time"

	"github.com/yetanotherparticipant/PipeSec/dynamic/internal/dynscan"
)

type WebhookChannel struct {
	url     string
	headers map[string]string
	client  *http.Client
}

func NewWebhookChannel(url string, headers map[string]string) *WebhookChannel {
	normalized := map[string]string{}
	for k, v := range headers {
		if k == "" {
			continue
		}
		normalized[k] = v
	}
	return &WebhookChannel{
		url:     url,
		headers: normalized,
		client:  &http.Client{Timeout: 5 * time.Second},
	}
}

func (w *WebhookChannel) Send(msg string, findings []dynscan.Finding) {
	if w == nil || w.url == "" {
		return
	}
	body, _ := json.Marshal(map[string]any{
		"summary":  msg,
		"findings": findings,
		"count":    len(findings),
	})
	req, err := http.NewRequest(http.MethodPost, w.url, bytes.NewReader(body))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range w.headers {
		req.Header.Set(k, v)
	}
	resp, err := w.client.Do(req)
	if err != nil {
		return
	}
	resp.Body.Close()
}
