package main

import (
	"encoding/json"
	"html"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestMessage(t *testing.T) {
	for _, tc := range []struct {
		name, content string
		status        int
	}{
		{"200_lines", strings.Repeat("Привет\n", 199) + "Конец", 201},
		{"201_lines", strings.Repeat("строка\n", 200) + "Конец", 400},
		{"long_line", strings.Repeat("a", 100000), 201},
		{"escaped_html", "<script>alert('x')</script>\n<b>Текст</b>", 201},
		{"empty", "", 400},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := server{dir: t.TempDir(), spaceAvailable: func(string) (uint64, error) { return minFreeSpace + maxSize, nil }}
			w := httptest.NewRecorder()
			s.handler().ServeHTTP(w, httptest.NewRequest("POST", "/api/upload?name=message.txt&kind=message", strings.NewReader(tc.content)))
			if w.Code != tc.status {
				t.Fatalf("got %d: %s", w.Code, w.Body)
			}
			if w.Code == 201 {
				var result struct {
					URL string `json:"url"`
				}
				if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
					t.Fatal(err)
				}
				w = httptest.NewRecorder()
				s.handler().ServeHTTP(w, httptest.NewRequest("GET", result.URL, nil))
				if w.Code != 200 || !strings.Contains(w.Body.String(), "<pre id=\"message-text\">"+html.EscapeString(tc.content)+"</pre>") {
					t.Fatal("saved message differs")
				}
				if w.Header().Get("Content-Disposition") != "" || !strings.HasPrefix(w.Header().Get("Content-Type"), "text/html") {
					t.Fatal("message should be displayed, not downloaded")
				}
			} else {
				entries, err := os.ReadDir(s.dir)
				if err != nil {
					t.Fatal(err)
				}
				if len(entries) != 0 {
					t.Fatal("invalid message left files or audit entry")
				}
			}
		})
	}
}

func TestLegacyMessageView(t *testing.T) {
	s := server{dir: t.TempDir()}
	id := strings.Repeat("b", 32)
	info := fileInfo{Name: "message-2026-11-06T18-52-27-012Z.txt", Expires: time.Now().Add(time.Hour)}
	metadata, _ := json.Marshal(info)
	if err := os.WriteFile(filepath.Join(s.dir, id+".json"), metadata, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(s.dir, id+".bin"), []byte("Старое сообщение"), 0600); err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	s.handler().ServeHTTP(w, httptest.NewRequest("GET", "/f/"+id, nil))
	if w.Code != 200 || w.Header().Get("Content-Disposition") != "" || !strings.Contains(w.Body.String(), "<pre id=\"message-text\">Старое сообщение</pre>") {
		t.Fatal("legacy message was not displayed")
	}
}
