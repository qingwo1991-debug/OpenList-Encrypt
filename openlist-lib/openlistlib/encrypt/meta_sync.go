package encrypt

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/OpenListTeam/OpenList/v4/openlistlib/internal"
	log "github.com/sirupsen/logrus"
)

const (
	dbExportCheckpointName          = "db_export_meta"
	defaultDBExportSyncIntervalSecs = 300
	minDBExportSyncIntervalSecs     = 30
	defaultDBExportPageLimit        = 1000
	maxDBExportPageLimit            = 5000
	maxDBExportPagesPerCycle        = 200
)

var dbExportSyncHTTPClient = &http.Client{Timeout: 20 * time.Second}

type dbExportSyncConfig struct {
	Enabled         bool
	BaseURL         string
	IntervalSeconds int
	AuthEnabled     bool
	Username        string
	Password        string
}

type dbExportLoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type dbExportLoginResponse struct {
	Code int    `json:"code"`
	Msg  string `json:"msg"`
	Data struct {
		JWTToken string `json:"jwtToken"`
	} `json:"data"`
}

type dbExportFileMetaResponse struct {
	Code int    `json:"code"`
	Msg  string `json:"msg"`
	Data struct {
		Items []struct {
			KeyHash      string `json:"KeyHash"`
			ProviderHost string `json:"ProviderHost"`
			OriginalPath string `json:"OriginalPath"`
			Size         int64  `json:"Size"`
			UpdatedAt    string `json:"UpdatedAt"`
			LastAccessed string `json:"LastAccessed"`
		} `json:"items"`
		HasMore    bool   `json:"has_more"`
		NextSince  int64  `json:"next_since"`
		NextCursor string `json:"next_cursor"`
	} `json:"data"`
}

func normalizeDBExportBaseURL(raw string) string {
	baseURL := strings.TrimSpace(raw)
	if baseURL == "" {
		return ""
	}
	baseURL = strings.TrimRight(baseURL, "/")
	if !strings.HasPrefix(baseURL, "http://") && !strings.HasPrefix(baseURL, "https://") {
		baseURL = "http://" + baseURL
	}
	return baseURL
}

func buildDBExportAPIURL(baseURL, endpoint string) string {
	b := strings.TrimRight(baseURL, "/")
	if strings.HasSuffix(b, "/enc-api") {
		return b + strings.TrimPrefix(endpoint, "/enc-api")
	}
	return b + endpoint
}

func parseRFC3339Unix(raw string, fallback int64) int64 {
	if strings.TrimSpace(raw) == "" {
		return fallback
	}
	parsed, err := time.Parse(time.RFC3339, raw)
	if err != nil {
		return fallback
	}
	return parsed.Unix()
}

func (p *ProxyServer) readDBExportSyncConfig() dbExportSyncConfig {
	cfg := dbExportSyncConfig{
		Enabled: false,
	}
	if p == nil {
		return cfg
	}
	p.mutex.RLock()
	defer p.mutex.RUnlock()
	if p.config == nil {
		return cfg
	}
	cfg.Enabled = p.config.EnableDBExportSync
	cfg.BaseURL = normalizeDBExportBaseURL(p.config.DBExportBaseURL)
	cfg.IntervalSeconds = p.config.DBExportSyncIntervalSeconds
	cfg.AuthEnabled = p.config.DBExportAuthEnabled
	cfg.Username = strings.TrimSpace(p.config.DBExportUsername)
	cfg.Password = p.config.DBExportPassword
	return cfg
}

func (p *ProxyServer) dbExportSyncInterval() time.Duration {
	cfg := p.readDBExportSyncConfig()
	secs := cfg.IntervalSeconds
	if secs <= 0 {
		secs = defaultDBExportSyncIntervalSecs
	}
	if secs < minDBExportSyncIntervalSecs {
		secs = minDBExportSyncIntervalSecs
	}
	return time.Duration(secs) * time.Second
}

func (p *ProxyServer) startDBExportSyncLoop() {
	if p == nil || p.metaSyncDone == nil || p.localStore == nil {
		return
	}
	p.metaSyncWG.Add(1)
	go func() {
		defer p.metaSyncWG.Done()
		timer := time.NewTimer(3 * time.Second)
		defer timer.Stop()
		for {
			select {
			case <-p.metaSyncDone:
				return
			case <-timer.C:
				p.syncDBExportMetaOnce(context.Background())
				timer.Reset(p.dbExportSyncInterval())
			}
		}
	}()
}

func (p *ProxyServer) stopDBExportSyncLoop() {
	if p == nil {
		return
	}
	if p.metaSyncDone != nil {
		close(p.metaSyncDone)
		p.metaSyncDone = nil
	}
	p.metaSyncWG.Wait()
}

func (p *ProxyServer) dbExportLogin(ctx context.Context, cfg dbExportSyncConfig) (string, error) {
	loginURL := buildDBExportAPIURL(cfg.BaseURL, "/enc-api/login")
	payload := dbExportLoginRequest{
		Username: cfg.Username,
		Password: cfg.Password,
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, loginURL, bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := dbExportSyncHTTPClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	var loginResp dbExportLoginResponse
	if err := json.Unmarshal(respBody, &loginResp); err != nil {
		return "", err
	}

	if loginResp.Code != 0 && loginResp.Code != 200 {
		msg := strings.TrimSpace(loginResp.Msg)
		if msg == "" {
			msg = string(respBody)
		}
		return "", fmt.Errorf("login failed: code=%d msg=%s", loginResp.Code, msg)
	}
	token := strings.TrimSpace(loginResp.Data.JWTToken)
	if token == "" {
		return "", fmt.Errorf("login failed: empty token")
	}
	return token, nil
}

func (p *ProxyServer) fetchDBExportPage(
	ctx context.Context,
	cfg dbExportSyncConfig,
	token string,
	since int64,
	cursor string,
) (*dbExportFileMetaResponse, error) {
	exportURL := buildDBExportAPIURL(cfg.BaseURL, "/enc-api/exportFileMeta")
	parsedURL, err := url.Parse(exportURL)
	if err != nil {
		return nil, err
	}
	q := parsedURL.Query()
	limit := defaultDBExportPageLimit
	if limit > maxDBExportPageLimit {
		limit = maxDBExportPageLimit
	}
	q.Set("limit", strconv.Itoa(limit))
	q.Set("since", strconv.FormatInt(since, 10))
	if strings.TrimSpace(cursor) != "" {
		q.Set("cursor", cursor)
	}
	parsedURL.RawQuery = q.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, parsedURL.String(), nil)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(token) != "" {
		req.Header.Set("Authorizetoken", token)
	}

	resp, err := dbExportSyncHTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	var apiResp dbExportFileMetaResponse
	if err := json.Unmarshal(respBody, &apiResp); err != nil {
		return nil, err
	}
	if apiResp.Code != 0 && apiResp.Code != 200 {
		msg := strings.TrimSpace(apiResp.Msg)
		if msg == "" {
			msg = string(respBody)
		}
		return nil, fmt.Errorf("exportFileMeta failed: code=%d msg=%s", apiResp.Code, msg)
	}
	return &apiResp, nil
}

func (p *ProxyServer) syncDBExportMetaOnce(ctx context.Context) {
	if p == nil || p.localStore == nil {
		return
	}
	if GetNetworkState() == NetworkStateOffline {
		return
	}
	cfg := p.readDBExportSyncConfig()
	if !cfg.Enabled {
		return
	}
	if cfg.BaseURL == "" {
		log.Warnf("[%s] DB_EXPORT sync enabled but base URL is empty", internal.TagCache)
		return
	}
	if cfg.AuthEnabled && (cfg.Username == "" || cfg.Password == "") {
		log.Warnf("[%s] DB_EXPORT sync auth enabled but username/password is empty", internal.TagCache)
		return
	}

	since, cursor, err := p.localStore.GetSyncCheckpoint(dbExportCheckpointName)
	if err != nil {
		log.Warnf("[%s] DB_EXPORT sync checkpoint load failed: %v", internal.TagCache, err)
		since = 0
		cursor = ""
	}

	token := ""
	if cfg.AuthEnabled {
		token, err = p.dbExportLogin(ctx, cfg)
		if err != nil {
			log.Warnf("[%s] DB_EXPORT sync login failed: %v", internal.TagCache, err)
			return
		}
	}

	pageCount := 0
	importedCount := 0
	changedCheckpoint := false

	for pageCount < maxDBExportPagesPerCycle {
		pageCount++
		resp, err := p.fetchDBExportPage(ctx, cfg, token, since, cursor)
		if err != nil {
			log.Warnf("[%s] DB_EXPORT sync fetch failed: %v", internal.TagCache, err)
			return
		}

		payload := &LocalExport{Sizes: make([]LocalSizeRecord, 0, len(resp.Data.Items))}
		nowUnix := time.Now().Unix()
		for _, item := range resp.Data.Items {
			key := strings.TrimSpace(item.KeyHash)
			providerHost := strings.TrimSpace(item.ProviderHost)
			originalPath := strings.TrimSpace(item.OriginalPath)
			if key == "" && providerHost != "" && originalPath != "" {
				key = buildLocalKey(providerHost, originalPath)
			}
			if key == "" || providerHost == "" || originalPath == "" || item.Size <= 0 {
				continue
			}
			updatedAt := parseRFC3339Unix(item.UpdatedAt, nowUnix)
			lastAccessed := parseRFC3339Unix(item.LastAccessed, updatedAt)
			payload.Sizes = append(payload.Sizes, LocalSizeRecord{
				Key:          key,
				ProviderHost: providerHost,
				OriginalPath: originalPath,
				Size:         item.Size,
				LastAccessed: lastAccessed,
				UpdatedAt:    updatedAt,
			})
		}
		if len(payload.Sizes) > 0 {
			if err := p.localStore.Import(payload); err != nil {
				log.Warnf("[%s] DB_EXPORT sync import failed: %v", internal.TagCache, err)
				return
			}
			importedCount += len(payload.Sizes)
		}

		prevSince, prevCursor := since, cursor
		if resp.Data.NextSince > 0 {
			since = resp.Data.NextSince
		}
		cursor = strings.TrimSpace(resp.Data.NextCursor)
		if since != prevSince || cursor != prevCursor {
			changedCheckpoint = true
		}

		if !resp.Data.HasMore {
			break
		}
		if since == prevSince && cursor == prevCursor {
			log.Warnf("[%s] DB_EXPORT sync pagination made no forward progress, stop this cycle", internal.TagCache)
			break
		}
	}

	if changedCheckpoint {
		if err := p.localStore.SaveSyncCheckpoint(dbExportCheckpointName, since, cursor); err != nil {
			log.Warnf("[%s] DB_EXPORT sync checkpoint save failed: %v", internal.TagCache, err)
		}
	}
	if importedCount > 0 {
		log.Infof("[%s] DB_EXPORT sync imported %d records, checkpoint since=%d cursor=%s", internal.TagCache, importedCount, since, cursor)
	}
}
