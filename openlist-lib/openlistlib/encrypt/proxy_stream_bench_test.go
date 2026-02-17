package encrypt

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"os"
	"strconv"
	"testing"
)

func buildFsListPayload(n int) []byte {
	content := make([]map[string]interface{}, 0, n)
	for i := 0; i < n; i++ {
		content = append(content, map[string]interface{}{
			"name":   fmt.Sprintf("file-%06d.mp4", i),
			"is_dir": false,
			"size":   1024 + i,
			"path":   fmt.Sprintf("/enc/file-%06d.mp4", i),
		})
	}
	body := map[string]interface{}{
		"code":    200,
		"message": "success",
		"data": map[string]interface{}{
			"content": content,
			"total":   n,
		},
	}
	b, _ := json.Marshal(body)
	return b
}

func BenchmarkStreamRewriteFsListResponse(b *testing.B) {
	cases := []int{1000, 10000, 50000}
	for _, n := range cases {
		b.Run(fmt.Sprintf("n=%d", n), func(b *testing.B) {
			p := &ProxyServer{config: &ProxyConfig{}}
			p.ensureRuntimeCaches()
			src := buildFsListPayload(n)
			b.ReportAllocs()
			b.SetBytes(int64(len(src)))
			for i := 0; i < b.N; i++ {
				w := httptest.NewRecorder()
				if _, err := p.streamRewriteFsListResponse(w, bytes.NewReader(src), "/enc", nil); err != nil {
					b.Fatalf("stream rewrite failed: %v", err)
				}
			}
		})
	}
}

func TestStreamRewriteFsListResponseMalformed(t *testing.T) {
	p := &ProxyServer{config: &ProxyConfig{}}
	p.ensureRuntimeCaches()
	w := httptest.NewRecorder()
	_, err := p.streamRewriteFsListResponse(w, bytes.NewBufferString(`{"code":200,"data":{"content":[}`), "/enc", nil)
	if err == nil {
		t.Fatalf("expected malformed json error")
	}
}

func TestStreamRewriteFsListResponseAllocBudget(t *testing.T) {
	maxAllocs := 20000.0
	if raw := os.Getenv("OPENLIST_STREAM_REWRITE_MAX_ALLOCS"); raw != "" {
		if v, err := strconv.ParseFloat(raw, 64); err == nil && v > 0 {
			maxAllocs = v
		}
	}
	p := &ProxyServer{config: &ProxyConfig{}}
	p.ensureRuntimeCaches()
	src := buildFsListPayload(200)
	allocs := testing.AllocsPerRun(3, func() {
		w := httptest.NewRecorder()
		if _, err := p.streamRewriteFsListResponse(w, bytes.NewReader(src), "/enc", nil); err != nil {
			t.Fatalf("stream rewrite failed: %v", err)
		}
	})
	if allocs > maxAllocs {
		t.Fatalf("alloc budget exceeded: allocs=%.2f max=%.2f", allocs, maxAllocs)
	}
}
