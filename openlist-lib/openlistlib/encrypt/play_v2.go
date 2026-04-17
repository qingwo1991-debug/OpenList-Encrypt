package encrypt

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
)

type PlayOrchestrator struct {
	proxy *ProxyServer
}

func newPlayOrchestrator(p *ProxyServer) *PlayOrchestrator {
	return &PlayOrchestrator{proxy: p}
}

func (p *ProxyServer) streamEngineVersion() int {
	p.mutex.RLock()
	defer p.mutex.RUnlock()
	if p.config == nil || p.config.StreamEngineVersion <= 0 {
		return defaultStreamEngineVersion
	}
	return p.config.StreamEngineVersion
}

func (p *ProxyServer) streamEngineV2Enabled() bool {
	return p.streamEngineVersion() >= 2
}

func remapRequestPath(r *http.Request, fromPrefix, toPrefix string) *http.Request {
	if r == nil || r.URL == nil {
		return r
	}
	if !strings.HasPrefix(r.URL.Path, fromPrefix) {
		return r
	}
	cloned := r.Clone(r.Context())
	clonedURL := *r.URL
	clonedURL.Path = toPrefix + strings.TrimPrefix(r.URL.Path, fromPrefix)
	if r.URL.RawPath != "" && strings.HasPrefix(r.URL.RawPath, fromPrefix) {
		clonedURL.RawPath = toPrefix + strings.TrimPrefix(r.URL.RawPath, fromPrefix)
	}
	cloned.URL = &clonedURL
	return cloned
}

func cloneHeader(dst http.Header, src http.Header) {
	for k, vals := range src {
		for _, v := range vals {
			dst.Add(k, v)
		}
	}
}

func recorderToResponse(w http.ResponseWriter, rec *httptest.ResponseRecorder) {
	for k, vals := range rec.Header() {
		for _, v := range vals {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(rec.Code)
	_, _ = w.Write(rec.Body.Bytes())
}

func rewriteRawURLForV2(body []byte, host, scheme string) []byte {
	var payload map[string]interface{}
	if err := json.Unmarshal(body, &payload); err != nil {
		return body
	}
	data, ok := payload["data"].(map[string]interface{})
	if !ok {
		return body
	}
	rawURL, _ := data["raw_url"].(string)
	if strings.TrimSpace(rawURL) == "" {
		return body
	}
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return body
	}
	pathParts := strings.Split(strings.Trim(parsed.Path, "/"), "/")
	if len(pathParts) < 2 || pathParts[0] != "redirect" || strings.TrimSpace(pathParts[1]) == "" {
		return body
	}
	token := pathParts[1]
	data["play_token"] = token
	playURL := fmt.Sprintf("%s://%s/api/play/stream/%s", scheme, host, token)
	if parsed.RawQuery != "" {
		playURL += "?" + parsed.RawQuery
	}
	data["raw_url"] = playURL
	data["stream_engine"] = "v2"
	payload["data"] = data
	out, err := json.Marshal(payload)
	if err != nil {
		return body
	}
	return out
}

func (o *PlayOrchestrator) resolveViaFsGet(ctx context.Context, host, scheme string, srcHeaders http.Header, body []byte) (int, []byte) {
	if o == nil || o.proxy == nil {
		return http.StatusInternalServerError, []byte(`{"code":500,"message":"play orchestrator unavailable"}`)
	}
	targetURL := fmt.Sprintf("%s://%s/api/fs/get", scheme, host)
	req := httptest.NewRequest(http.MethodPost, targetURL, bytes.NewReader(body)).WithContext(ctx)
	cloneHeader(req.Header, srcHeaders)
	rec := httptest.NewRecorder()
	o.proxy.handleFsGet(rec, req)
	respBody := rewriteRawURLForV2(rec.Body.Bytes(), host, scheme)
	return rec.Code, respBody
}

func (o *PlayOrchestrator) streamViaRedirect(ctx context.Context, srcReq *http.Request, token string) *httptest.ResponseRecorder {
	if o == nil || o.proxy == nil {
		rec := httptest.NewRecorder()
		rec.WriteHeader(http.StatusInternalServerError)
		_, _ = rec.Write([]byte("play orchestrator unavailable"))
		return rec
	}
	host := srcReq.Host
	if strings.TrimSpace(host) == "" {
		host = "127.0.0.1"
	}
	redirectURL := fmt.Sprintf("http://%s/redirect/%s", host, token)
	if srcReq.URL != nil && srcReq.URL.RawQuery != "" {
		redirectURL += "?" + srcReq.URL.RawQuery
	}
	req := httptest.NewRequest(srcReq.Method, redirectURL, srcReq.Body).WithContext(ctx)
	cloneHeader(req.Header, srcReq.Header)
	rec := httptest.NewRecorder()
	o.proxy.handleRedirectLegacy(rec, req)
	return rec
}

func (o *PlayOrchestrator) ServePlayback(w http.ResponseWriter, r *http.Request) {
	if o == nil || o.proxy == nil {
		http.Error(w, "play orchestrator unavailable", http.StatusInternalServerError)
		return
	}
	path := ""
	if r != nil && r.URL != nil {
		path = r.URL.Path
	}
	switch {
	case strings.HasPrefix(path, "/redirect/"):
		o.proxy.handleRedirectLegacy(w, r)
	case strings.HasPrefix(path, "/dav2/") || path == "/dav2":
		o.proxy.handleWebDAVLegacy(w, remapRequestPath(r, "/dav2", "/dav"))
	case strings.HasPrefix(path, "/dav/") || path == "/dav":
		o.proxy.handleWebDAVLegacy(w, r)
	case strings.HasPrefix(path, "/d/") || strings.HasPrefix(path, "/p/"):
		o.proxy.handleDownloadLegacy(w, r)
	default:
		http.Error(w, "unsupported playback route", http.StatusNotFound)
	}
}

func (p *ProxyServer) handlePlayResolve(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if len(bytes.TrimSpace(body)) == 0 {
		http.Error(w, "empty body", http.StatusBadRequest)
		return
	}
	host := r.Host
	if strings.TrimSpace(host) == "" {
		host = "127.0.0.1"
	}
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	orch := newPlayOrchestrator(p)
	status, respBody := orch.resolveViaFsGet(r.Context(), host, scheme, r.Header, body)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(respBody)
}

func (p *ProxyServer) handlePlayStream(w http.ResponseWriter, r *http.Request) {
	token := strings.TrimSpace(strings.TrimPrefix(r.URL.Path, "/api/play/stream/"))
	if token == "" {
		http.Error(w, "invalid token", http.StatusBadRequest)
		return
	}
	orch := newPlayOrchestrator(p)
	rec := orch.streamViaRedirect(r.Context(), r, token)
	recorderToResponse(w, rec)
}

func (p *ProxyServer) handlePlayStats(w http.ResponseWriter, r *http.Request) {
	p.rangeProbeMu.Lock()
	targetCount := len(p.rangeProbeTargets)
	p.rangeProbeMu.Unlock()

	p.rangeCompatMu.RLock()
	rangeCompatCount := len(p.rangeCompat)
	p.rangeCompatMu.RUnlock()

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"code": 200,
		"data": map[string]interface{}{
			"streamEngineVersion": p.streamEngineVersion(),
			"rangeCompatEntries":  rangeCompatCount,
			"rangeProbeTargets":   targetCount,
		},
	})
}

func (p *ProxyServer) handleWebDAVV2(w http.ResponseWriter, r *http.Request) {
	newPlayOrchestrator(p).ServePlayback(w, remapRequestPath(r, "/dav2", "/dav"))
}
