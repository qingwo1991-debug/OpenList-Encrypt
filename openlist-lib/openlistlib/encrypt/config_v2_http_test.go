package encrypt

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
)

func TestHandleConfigV2Schema(t *testing.T) {
	p := &ProxyServer{config: DefaultConfig()}
	req := httptest.NewRequest(http.MethodGet, "/api/encrypt/v2/config/schema", nil)
	w := httptest.NewRecorder()
	p.handleConfigV2Schema(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("unexpected status: %d", w.Code)
	}
	var payload map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &payload); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}
	data, _ := payload["data"].(map[string]interface{})
	if data == nil {
		t.Fatalf("missing data")
	}
	docs, _ := data["docs"].([]interface{})
	if len(docs) == 0 {
		t.Fatalf("docs should not be empty")
	}
}

func TestHandleConfigV2PostClampsAndPersists(t *testing.T) {
	cfg := DefaultConfig()
	cfg.ConfigPath = filepath.Join(t.TempDir(), "encrypt_config.json")
	p := &ProxyServer{config: cfg}

	body := map[string]interface{}{
		"config": map[string]interface{}{
			"probeTimeoutSeconds":         999,
			"rangeCompatMinFailures":      -1,
			"parallelDecryptConcurrency":  99,
			"dbExportSyncIntervalSeconds": 1,
		},
	}
	raw, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/api/encrypt/v2/config", bytes.NewReader(raw))
	w := httptest.NewRecorder()
	p.handleConfigV2(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("unexpected status: %d body=%s", w.Code, w.Body.String())
	}
	if p.config.ProbeTimeoutSeconds != 30 {
		t.Fatalf("probe timeout clamp failed: %d", p.config.ProbeTimeoutSeconds)
	}
	if p.config.RangeCompatMinFailures != 1 {
		t.Fatalf("range failures clamp failed: %d", p.config.RangeCompatMinFailures)
	}
	if p.config.ParallelDecryptConcurrency != 32 {
		t.Fatalf("parallel clamp failed: %d", p.config.ParallelDecryptConcurrency)
	}
	if p.config.DBExportSyncIntervalSeconds != minDBExportSyncIntervalSecs {
		t.Fatalf("sync interval clamp failed: %d", p.config.DBExportSyncIntervalSeconds)
	}
}
