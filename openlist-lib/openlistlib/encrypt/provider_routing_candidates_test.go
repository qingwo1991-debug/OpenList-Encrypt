package encrypt

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestTryFetchRemoteProviderRoutingCandidates(t *testing.T) {
	remote := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/encrypt/provider-routing-candidates" {
			http.NotFound(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"code": 200,
			"data": map[string]interface{}{
				"providers": []string{"china_mobile_cloud", "googledrive"},
				"provider_labels": map[string]string{
					"china_mobile_cloud": "移动云盘",
					"googledrive":        "Google Drive",
				},
			},
		})
	}))
	defer remote.Close()

	p := &ProxyServer{
		config: &ProxyConfig{
			DBExportBaseURL:     remote.URL + "/enc-api",
			DBExportAuthEnabled: false,
			ProxyPort:           5344,
		},
	}
	providers, labels, degraded := p.tryFetchRemoteProviderRoutingCandidates(context.Background())
	if degraded {
		t.Fatalf("expected non-degraded remote fetch")
	}
	if len(providers) != 2 {
		t.Fatalf("expected 2 providers, got %d (%v)", len(providers), providers)
	}
	if labels["china_mobile_cloud"] != "移动云盘" {
		t.Fatalf("unexpected label map: %+v", labels)
	}
}

func TestHandleProviderRoutingCandidatesMergesRemoteFallback(t *testing.T) {
	remote := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/encrypt/provider-routing-candidates" {
			http.NotFound(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"code": 200,
			"data": map[string]interface{}{
				"providers": []string{"china_unicom_cloud", "googledrive"},
				"provider_labels": map[string]string{
					"china_unicom_cloud": "联通云盘",
					"googledrive":        "Google Drive",
				},
			},
		})
	}))
	defer remote.Close()

	p := &ProxyServer{
		config: &ProxyConfig{
			AlistHost:                "127.0.0.1",
			AlistPort:                1,
			AlistHttps:               false,
			DBExportBaseURL:          remote.URL,
			DBExportAuthEnabled:      false,
			StorageMapRefreshMinutes: 30,
			ProxyPort:                5344,
		},
		httpClient: &http.Client{Timeout: time.Second},
		seenProviders: map[string]time.Time{
			"baidunetdisk": time.Now(),
		},
		seenDrivers:      map[string]time.Time{},
		storageDriverMap: map[string]string{},
	}

	req := httptest.NewRequest(http.MethodGet, "/api/encrypt/provider-routing-candidates", nil)
	w := httptest.NewRecorder()
	p.handleProviderRoutingCandidates(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("unexpected status: %d body=%s", w.Code, w.Body.String())
	}
	var payload map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode failed: %v", err)
	}
	data, _ := payload["data"].(map[string]interface{})
	if data == nil {
		t.Fatalf("missing data")
	}
	rawProviders, _ := data["providers"].([]interface{})
	foundRemote := false
	for _, raw := range rawProviders {
		if raw.(string) == "china_unicom_cloud" || raw.(string) == "googledrive" {
			foundRemote = true
			break
		}
	}
	if !foundRemote {
		t.Fatalf("expected remote providers merged, got %v", rawProviders)
	}
	meta, _ := data["meta"].(map[string]interface{})
	if meta == nil {
		t.Fatalf("missing meta")
	}
	if used, _ := meta["remote_used"].(bool); !used {
		t.Fatalf("expected remote_used=true, got meta=%v", meta)
	}
}
