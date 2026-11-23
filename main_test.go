package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestUploadDownloadExpiry(t *testing.T) {
	s := server{dir: t.TempDir(), spaceAvailable: func(string) (uint64, error) { return minFreeSpace + maxSize, nil }}
	h := s.handler()
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("POST", "/api/upload?name=test.txt", strings.NewReader("hello")))
	if w.Code != 201 {
		t.Fatalf("upload: %d %s", w.Code, w.Body)
	}
	var result struct {
		URL     string    `json:"url"`
		Expires time.Time `json:"expires"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if remaining := time.Until(result.Expires); remaining < lifetime-time.Minute || remaining > lifetime {
		t.Fatalf("expiry: %v", remaining)
	}
	data, err := os.ReadFile(filepath.Join(s.dir, "uploads.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	var record uploadRecord
	if err := json.Unmarshal(data, &record); err != nil {
		t.Fatal(err)
	}
	if record.IP != "192.0.2.1" || record.Name != "test.txt" || record.Size != 5 || record.URL != "http://example.com"+result.URL || !record.Expires.Equal(result.Expires) {
		t.Fatalf("unexpected upload log: %+v", record)
	}
	w = httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("GET", result.URL, nil))
	if w.Code != 200 || w.Body.String() != "hello" {
		t.Fatalf("download: %d %s", w.Code, w.Body)
	}
	if !strings.HasPrefix(w.Header().Get("Content-Disposition"), "attachment;") {
		t.Fatal("download must be an attachment")
	}
	id := testLinkID(result.URL)
	expired, _ := json.Marshal(fileInfo{Name: "test.txt", Expires: time.Now().Add(-time.Second)})
	if err := os.WriteFile(filepath.Join(s.dir, id+".json"), expired, 0600); err != nil {
		t.Fatal(err)
	}
	w = httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("GET", result.URL, nil))
	if w.Code != 410 {
		t.Fatalf("expired download: %d", w.Code)
	}
	s.cleanup()
	if _, err := os.Stat(filepath.Join(s.dir, "uploads.jsonl")); err != nil {
		t.Fatal("cleanup removed audit log", err)
	}
	for _, suffix := range []string{".json", ".bin"} {
		if _, err := os.Stat(filepath.Join(s.dir, id+suffix)); !os.IsNotExist(err) {
			t.Fatalf("expired file remains: %v", err)
		}
	}
}

type repeatedReader struct{}

func (repeatedReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = 'x'
	}
	return len(p), nil
}

func TestUploadLimit(t *testing.T) {
	for _, size := range []int64{maxSize, maxSize + 1} {
		t.Run(stringSize(size), func(t *testing.T) {
			s := server{dir: t.TempDir(), spaceAvailable: func(string) (uint64, error) { return minFreeSpace + maxSize, nil }}
			req := httptest.NewRequest("POST", "/api/upload?name=large.bin", io.LimitReader(repeatedReader{}, size))
			req.ContentLength = -1 // Exercise streamed uploads with no declared size.
			w := httptest.NewRecorder()
			s.handler().ServeHTTP(w, req)
			want := http.StatusCreated
			if size > maxSize {
				want = http.StatusRequestEntityTooLarge
			}
			if w.Code != want {
				t.Fatalf("got %d, want %d: %s", w.Code, want, w.Body)
			}
			entries, err := os.ReadDir(s.dir)
			if err != nil {
				t.Fatal(err)
			}
			if size > maxSize && len(entries) != 0 {
				t.Fatal("rejected upload left files behind")
			}
		})
	}
}
func stringSize(n int64) string {
	if n == maxSize {
		return "at_limit"
	}
	return "over_limit"
}

func TestCrossSiteUploadRejected(t *testing.T) {
	s := server{dir: t.TempDir(), spaceAvailable: func(string) (uint64, error) { return minFreeSpace + maxSize, nil }}
	req := httptest.NewRequest("POST", "/api/upload?name=test.txt", strings.NewReader("hello"))
	req.Header.Set("Sec-Fetch-Site", "cross-site")
	w := httptest.NewRecorder()
	s.handler().ServeHTTP(w, req)
	if w.Code != http.StatusForbidden {
		t.Fatalf("cross-site upload: %d", w.Code)
	}
}
