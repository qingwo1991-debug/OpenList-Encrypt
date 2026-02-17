package encrypt

import (
	"bytes"
	"fmt"
	"net/url"
	"strings"
	"testing"
)

func TestPathPatternMatchesLeadingSlash(t *testing.T) {
	cfg := &ProxyConfig{
		AlistHost:    "localhost",
		AlistPort:    80,
		AlistHttps:   false,
		ProxyPort:    0,
		EncryptPaths: []*EncryptPath{{Path: "移动云盘156/encrypt/*", Password: "p", Enable: true}},
	}

	p, err := NewProxyServer(cfg)
	if err != nil {
		t.Fatalf("NewProxyServer failed: %v", err)
	}

	if len(p.config.EncryptPaths) == 0 || p.config.EncryptPaths[0].regex == nil {
		t.Fatalf("regex not compiled")
	}

	tests := []string{
		"移动云盘156/encrypt/file.txt",
		"/移动云盘156/encrypt/file.txt",
		"移动云盘156/encrypt/subdir/another",
		"/移动云盘156/encrypt/",
	}

	for _, s := range tests {
		if !p.config.EncryptPaths[0].regex.MatchString(s) {
			t.Fatalf("pattern did not match %s", s)
		}
	}
}

func TestUpdateConfigCompilesPattern(t *testing.T) {
	p, err := NewProxyServer(&ProxyConfig{EncryptPaths: []*EncryptPath{}})
	if err != nil {
		t.Fatalf("NewProxyServer empty failed: %v", err)
	}

	cfg := &ProxyConfig{
		AlistHost:    "localhost",
		AlistPort:    80,
		AlistHttps:   false,
		ProxyPort:    0,
		EncryptPaths: []*EncryptPath{{Path: "/移动云盘156/encrypt/*", Password: "p", Enable: true}},
	}

	p.UpdateConfig(cfg)

	if len(p.config.EncryptPaths) == 0 || p.config.EncryptPaths[0].regex == nil {
		t.Fatalf("regex not compiled after UpdateConfig")
	}

	if !p.config.EncryptPaths[0].regex.MatchString("/移动云盘156/encrypt/file") {
		t.Fatalf("UpdateConfig pattern did not match")
	}
}

// TestFindEncryptPath 测试通过 findEncryptPath 方法查找匹配的加密路径
func TestFindEncryptPath(t *testing.T) {
	cfg := &ProxyConfig{
		AlistHost:  "localhost",
		AlistPort:  80,
		AlistHttps: false,
		ProxyPort:  0,
		EncryptPaths: []*EncryptPath{
			{Path: "移动云盘156/encrypt/*", Password: "test123", EncType: EncTypeAESCTR, Enable: true},
			{Path: "/天翼云盘156/encrypt/*", Password: "test456", EncType: EncTypeAESCTR, Enable: true},
		},
	}

	p, err := NewProxyServer(cfg)
	if err != nil {
		t.Fatalf("NewProxyServer failed: %v", err)
	}

	tests := []struct {
		filePath string
		expected bool
		desc     string
	}{
		{"/移动云盘156/encrypt/test.mp4", true, "带前导/访问不带前导/配置"},
		{"移动云盘156/encrypt/test.mp4", true, "不带前导/访问不带前导/配置"},
		{"/移动云盘156/encrypt/subdir/video.mkv", true, "子目录文件"},
		{"/天翼云盘156/encrypt/test.mp4", true, "带前导/访问带前导/配置"},
		{"/其他盘/encrypt/test.mp4", false, "不匹配的路径"},
	}

	for _, tc := range tests {
		ep := p.findEncryptPath(tc.filePath)
		found := ep != nil
		if found != tc.expected {
			t.Errorf("%s: findEncryptPath(%q) = %v, expected %v", tc.desc, tc.filePath, found, tc.expected)
		}
	}
}

func TestProcessPropfindResponse(t *testing.T) {
	p := &ProxyServer{fileCache: newShardedAnyMap(cacheShardCount)}

	passwd := "testpass123"
	encType := EncTypeMix
	original := "video_sample.mp4"

	enc := EncodeName(passwd, encType, original)
	encName := enc + ".mp4"
	rawHref := "/dav/folder/" + encName
	encodedHref := (&url.URL{Path: rawHref}).EscapedPath()

	xml := fmt.Sprintf(`<?xml version="1.0"?>
<multistatus>
  <response>
    <href>%s</href>
    <propstat>
      <prop>
        <getcontentlength>12345</getcontentlength>
      </prop>
    </propstat>
  </response>
</multistatus>`, encodedHref)

	var out bytes.Buffer
	err := p.processPropfindResponse(strings.NewReader(xml), &out, &EncryptPath{Password: passwd, EncType: encType, EncName: true})
	if err != nil {
		t.Fatalf("processPropfindResponse error: %v", err)
	}

	s := out.String()
	if !strings.Contains(s, original) {
		t.Fatalf("expected original name %s in output, got %s", original, s)
	}

	// check cache
	if v, ok := p.fileCache.Load(rawHref); !ok {
		t.Fatalf("expected file info cached for %s", rawHref)
	} else {
		fi := v.(*CachedFileInfo)
		if fi.Info.Size != 12345 {
			t.Fatalf("expected size 12345, got %d", fi.Info.Size)
		}
	}
}
