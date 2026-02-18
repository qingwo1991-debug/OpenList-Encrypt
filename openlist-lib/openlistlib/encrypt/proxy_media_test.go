package encrypt

import "testing"

func TestNormalizeDecryptedMediaFields(t *testing.T) {
	t.Run("video extension fixes path and type", func(t *testing.T) {
		item := map[string]interface{}{
			"path": "/enc/xxxx.bin",
			"type": float64(0),
		}
		normalizeDecryptedMediaFields(item, "ocewwe ewrw+ 测试のans.mp4")

		if got, _ := item["path"].(string); got != "/enc/ocewwe ewrw+ 测试のans.mp4" {
			t.Fatalf("path mismatch: got %q", got)
		}
		if got, _ := item["type"].(float64); got != 2 {
			t.Fatalf("type mismatch: got %v want 2", got)
		}
	})

	t.Run("unknown extension keeps type", func(t *testing.T) {
		item := map[string]interface{}{
			"path": "/enc/xxxx.bin",
			"type": float64(0),
		}
		normalizeDecryptedMediaFields(item, "doc.xyz")

		if got, _ := item["path"].(string); got != "/enc/doc.xyz" {
			t.Fatalf("path mismatch: got %q", got)
		}
		if got, _ := item["type"].(float64); got != 0 {
			t.Fatalf("type should stay unchanged: got %v want 0", got)
		}
	})
}

