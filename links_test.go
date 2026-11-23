package main

import (
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestSameFilenameSeparateLinks(t *testing.T) {
	s := server{dir: t.TempDir(), spaceAvailable: func(string) (uint64, error) { return minFreeSpace + maxSize, nil }}
	h := s.handler()
	seen := map[string]bool{}
	for _, content := range []string{"first file", "second file"} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest("POST", "/api/upload?name=same.txt", strings.NewReader(content)))
		if w.Code != 201 {
			t.Fatalf("upload: %d %s", w.Code, w.Body)
		}
		var result struct {
			URL string `json:"url"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
			t.Fatal(err)
		}
		id := testLinkID(result.URL)
		if len(id) > 10 || !tokenPattern.MatchString(id) || seen[id] {
			t.Fatalf("invalid or repeated ID: %s", id)
		}
		seen[id] = true
		w = httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest("GET", result.URL, nil))
		if w.Code != 200 || w.Body.String() != content {
			t.Fatalf("download: %d %s", w.Code, w.Body)
		}
	}
	// Both contents survive the second upload.
	for id := range seen {
		if _, err := os.Stat(filepath.Join(s.dir, id+".bin")); err != nil {
			t.Fatal(err)
		}
	}
}

func TestLegacyLink(t *testing.T) {
	s := server{dir: t.TempDir()}
	id := strings.Repeat("a", 32)
	data, _ := json.Marshal(fileInfo{Name: "old.txt", Expires: time.Now().Add(time.Hour)})
	if err := os.WriteFile(filepath.Join(s.dir, id+".json"), data, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(s.dir, id+".bin"), []byte("old file"), 0600); err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	s.handler().ServeHTTP(w, httptest.NewRequest("GET", "/f/"+id, nil))
	if w.Code != 200 || w.Body.String() != "old file" {
		t.Fatalf("legacy download: %d %s", w.Code, w.Body)
	}
}

func testLinkID(path string) string { return strings.TrimPrefix(strings.TrimPrefix(path, "/f/"), "/") }
