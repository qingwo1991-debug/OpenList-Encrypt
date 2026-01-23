package encrypt

import (
	"bytes"
	"fmt"
	"net/url"
	"strings"
	"sync"
	"testing"
)

func TestProcessPropfindResponse(t *testing.T) {
	p := &ProxyServer{fileCache: sync.Map{}}

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
		fi := v.(*FileInfo)
		if fi.Size != 12345 {
			t.Fatalf("expected size 12345, got %d", fi.Size)
		}
	}
}
