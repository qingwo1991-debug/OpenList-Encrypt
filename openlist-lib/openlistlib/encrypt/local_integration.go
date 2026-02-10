package encrypt

import (
	"path/filepath"
	"time"

	"github.com/OpenListTeam/OpenList/v4/openlistlib/internal"
	log "github.com/sirupsen/logrus"
)

func (p *ProxyServer) initLocalStore() {
	if p == nil || p.config == nil || p.config.ConfigPath == "" {
		return
	}
	baseDir := filepath.Dir(p.config.ConfigPath)
	store, err := newLocalStore(baseDir)
	if err != nil {
		log.Warnf("[%s] Local store init failed: %v", internal.TagCache, err)
		return
	}
	p.localStore = store
	if p.localStore != nil {
		if err := p.localStore.Cleanup(30 * 24 * time.Hour); err != nil {
			log.Warnf("[%s] Local store cleanup failed: %v", internal.TagCache, err)
		}
	}
}

func (p *ProxyServer) closeLocalStore() {
	if p == nil || p.localStore == nil {
		return
	}
	if err := p.localStore.Close(); err != nil {
		log.Warnf("[%s] Local store close failed: %v", internal.TagCache, err)
	}
	p.localStore = nil
}

func (p *ProxyServer) localKeyFromURLs(providerURL, originalURL string) (string, string, string, bool) {
	providerHost, originalPath, ok := parseProviderAndPath(providerURL, originalURL)
	if !ok {
		return "", "", "", false
	}
	key := buildLocalKey(providerHost, originalPath)
	if key == "" {
		return "", "", "", false
	}
	return key, providerHost, originalPath, true
}

func (p *ProxyServer) lookupLocalSize(providerURL, originalURL string) (int64, bool) {
	if p == nil || p.localStore == nil {
		return 0, false
	}
	key, _, _, ok := p.localKeyFromURLs(providerURL, originalURL)
	if !ok {
		return 0, false
	}
	return p.localStore.GetSize(key)
}

func (p *ProxyServer) lookupLocalStrategy(providerURL, originalURL string) (StreamStrategy, bool) {
	if p == nil || p.localStore == nil {
		return "", false
	}
	key, _, _, ok := p.localKeyFromURLs(providerURL, originalURL)
	if !ok {
		return "", false
	}
	networkType := string(GetNetworkState())
	return p.localStore.GetStrategy(key, networkType)
}

func (p *ProxyServer) recordLocalObservation(providerURL, originalURL string, size int64, statusCode int, contentType string, strategy StreamStrategy) {
	if p == nil || p.localStore == nil {
		return
	}
	if !isValidMediaResponse(statusCode, contentType, size) {
		return
	}
	key, providerHost, originalPath, ok := p.localKeyFromURLs(providerURL, originalURL)
	if !ok {
		return
	}
	now := time.Now()
	p.localStore.AddSize(key, providerHost, originalPath, size, now)
	if strategy != "" {
		networkType := string(GetNetworkState())
		p.localStore.AddStrategy(key, providerHost, originalPath, networkType, strategy, now)
	}
}
