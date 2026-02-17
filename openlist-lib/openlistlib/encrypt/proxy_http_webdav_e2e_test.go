package encrypt

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
)

func TestHTTPAndWebDAVPlaybackCompatibility(t *testing.T) {
	password := "123456"
	encType := EncTypeAESCTR
	plainPath := "/enc/demo-video.mp4"
	plainContent := []byte("this is a compatibility playback payload from old alist-encrypt")
	fileSize := int64(len(plainContent))

	flow, err := NewFlowEncryptor(password, encType, fileSize)
	if err != nil {
		t.Fatalf("new flow encryptor: %v", err)
	}
	encryptedContent, err := flow.Encrypt(plainContent)
	if err != nil {
		t.Fatalf("encrypt payload: %v", err)
	}
	encryptedName := ConvertRealName(password, encType, plainPath)

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		expectedDownloadPath := "/d/enc/" + encryptedName
		expectedDavPath := "/dav/enc/" + encryptedName
		if r.URL.Path != expectedDownloadPath && r.URL.Path != expectedDavPath {
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte("not found"))
			return
		}
		w.Header().Set("Content-Type", "video/mp4")
		w.Header().Set("Content-Length", strconv.Itoa(len(encryptedContent)))
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(encryptedContent)
	}))
	defer upstream.Close()

	u, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("parse upstream url: %v", err)
	}
	host := u.Hostname()
	port, _ := strconv.Atoi(u.Port())

	p, err := NewProxyServer(&ProxyConfig{
		AlistHost:  host,
		AlistPort:  port,
		ProxyPort:  5344,
		AlistHttps: false,
		EncryptPaths: []*EncryptPath{
			{
				Path:     "/enc/*",
				Password: password,
				EncType:  encType,
				EncName:  true,
				Enable:   true,
			},
		},
		ProbeOnDownload: true,
	})
	if err != nil {
		t.Fatalf("new proxy server: %v", err)
	}
	defer p.stopCacheCleanup()
	defer p.closeLocalStore()

	httpReq := httptest.NewRequest(http.MethodGet, "http://proxy.local/d/enc/demo-video.mp4", nil)
	httpResp := httptest.NewRecorder()
	p.handleDownload(httpResp, httpReq)
	if httpResp.Code != http.StatusOK {
		t.Fatalf("http playback status=%d body=%s", httpResp.Code, httpResp.Body.String())
	}
	if got := httpResp.Body.Bytes(); string(got) != string(plainContent) {
		t.Fatalf("http playback mismatch: got=%q want=%q", string(got), string(plainContent))
	}

	davReq := httptest.NewRequest(http.MethodGet, "http://proxy.local/dav/enc/demo-video.mp4", nil)
	davResp := httptest.NewRecorder()
	p.handleWebDAV(davResp, davReq)
	if davResp.Code != http.StatusOK {
		t.Fatalf("webdav playback status=%d body=%s", davResp.Code, davResp.Body.String())
	}
	if got := davResp.Body.Bytes(); string(got) != string(plainContent) {
		t.Fatalf("webdav playback mismatch: got=%q want=%q", string(got), string(plainContent))
	}

	// sanity: upstream really served encrypted bytes, not plaintext
	rawReq, err := http.NewRequest(http.MethodGet, upstream.URL+"/d/enc/"+encryptedName, nil)
	if err != nil {
		t.Fatalf("build raw upstream request failed: %v", err)
	}
	rawResp, err := upstream.Client().Do(rawReq)
	if err != nil {
		t.Fatalf("raw upstream request failed: %v", err)
	}
	defer rawResp.Body.Close()
	rawBody, _ := io.ReadAll(rawResp.Body)
	if strings.Contains(string(rawBody), string(plainContent)) {
		t.Fatalf("raw upstream unexpectedly contains plaintext")
	}
}
