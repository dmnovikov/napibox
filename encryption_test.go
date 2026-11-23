package main

import (
	"bytes"
	"encoding/json"
	"html"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func encryptedTestServer(t *testing.T) server {
	t.Helper()
	return server{dir: t.TempDir(), spaceAvailable: func(string) (uint64, error) { return minFreeSpace + maxSize, nil }}
}

func uploadEncrypted(t *testing.T, s server, pin, content string) string {
	t.Helper()
	r := httptest.NewRequest("POST", "/api/upload?name=secret.txt&kind=message&encrypt=1", strings.NewReader(content))
	r.Header.Set("X-Napibox-Pin", pin)
	w := httptest.NewRecorder()
	s.handler().ServeHTTP(w, r)
	if w.Code != 201 {
		t.Fatalf("encrypted upload: %d %s", w.Code, w.Body)
	}
	var result struct {
		URL string `json:"url"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	return result.URL
}

func submitPIN(s server, path, pin string) *httptest.ResponseRecorder {
	r := httptest.NewRequest("POST", path, strings.NewReader(url.Values{"pin": {pin}}.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	s.handler().ServeHTTP(w, r)
	return w
}

func TestEncryptedMessage(t *testing.T) {
	s := encryptedTestServer(t)
	content := "Секретное сообщение\nВторая строка"
	path := uploadEncrypted(t, s, "0427", content)
	id := testLinkID(path)
	stored, err := os.ReadFile(filepath.Join(s.dir, id+".bin"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(stored, []byte(content)) {
		t.Fatal("message stored as plaintext")
	}
	for _, name := range []string{id + ".json", "uploads.jsonl"} {
		data, err := os.ReadFile(filepath.Join(s.dir, name))
		if err != nil {
			t.Fatal(err)
		}
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(data, &fields); err != nil {
			t.Fatal(err)
		}
		for key := range fields {
			if strings.Contains(strings.ToLower(key), "pin") {
				t.Fatal("PIN in metadata or audit")
			}
		}
		if bytes.Contains(data, []byte(content)) {
			t.Fatal("plaintext in metadata or audit")
		}
	}
	st, err := os.Stat(filepath.Join(s.dir, ".encryption-key"))
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0600 {
		t.Fatalf("key permissions: %v", st.Mode())
	}
	w := httptest.NewRecorder()
	s.handler().ServeHTTP(w, httptest.NewRequest("GET", path+"?pin=0427", nil))
	if w.Code != 200 || !strings.Contains(w.Body.String(), "Сообщение доступно по PIN-коду") || strings.Contains(w.Body.String(), content) {
		t.Fatal("GET bypassed PIN protection")
	}
	w = submitPIN(s, path, "9999")
	if w.Code != 401 || strings.Contains(w.Body.String(), content) {
		t.Fatalf("wrong PIN: %d", w.Code)
	}
	// Re-create the server to verify that the encryption key survives restarts.
	restarted := server{dir: s.dir}
	w = submitPIN(restarted, path, "0427")
	if w.Code != 200 || !strings.Contains(w.Body.String(), "<pre id=\"message-text\">"+html.EscapeString(content)+"</pre>") {
		t.Fatalf("correct PIN: %d %s", w.Code, w.Body)
	}
	if w.Header().Get("Content-Disposition") != "" || !strings.HasPrefix(w.Header().Get("Content-Type"), "text/html") {
		t.Fatal("decrypted message should be displayed, not downloaded")
	}
	if strings.Contains(w.Header().Get("Content-Security-Policy"), "form-action 'none'") {
		t.Fatal("PIN form blocked by CSP")
	}
	info := fileInfo{Name: "secret.txt", Expires: time.Now().Add(-time.Second), Encrypted: true}
	data, _ := json.Marshal(info)
	if err := os.WriteFile(filepath.Join(s.dir, id+".json"), data, 0600); err != nil {
		t.Fatal(err)
	}
	w = submitPIN(s, path, "0427")
	if w.Code != 410 {
		t.Fatalf("expired PIN download: %d", w.Code)
	}
}

func TestPINValidationAndRateLimit(t *testing.T) {
	for _, pin := range []string{"", "123", "12345", "abcd", "１２３４"} {
		s := encryptedTestServer(t)
		r := httptest.NewRequest("POST", "/api/upload?name=secret.txt&kind=message&encrypt=1", strings.NewReader("secret"))
		r.Header.Set("X-Napibox-Pin", pin)
		w := httptest.NewRecorder()
		s.handler().ServeHTTP(w, r)
		if w.Code != 400 {
			t.Fatalf("invalid PIN %q: %d", pin, w.Code)
		}
		entries, _ := os.ReadDir(s.dir)
		if len(entries) != 0 {
			t.Fatal("invalid PIN created files")
		}
	}
	s := encryptedTestServer(t)
	path := uploadEncrypted(t, s, "0123", "secret")
	for i := 0; i < 5; i++ {
		if w := submitPIN(s, path, "9999"); w.Code != 401 {
			t.Fatalf("attempt %d: %d", i, w.Code)
		}
	}
	w := submitPIN(s, path, "0123")
	if w.Code != http.StatusTooManyRequests || w.Header().Get("Retry-After") == "" {
		t.Fatalf("unlimited PIN attempts: %d", w.Code)
	}
}

func TestEncryptedTampering(t *testing.T) {
	s := encryptedTestServer(t)
	path := uploadEncrypted(t, s, "1234", "secret payload")
	file := filepath.Join(s.dir, testLinkID(path)+".bin")
	data, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	data[len(data)-1] ^= 1
	if err := os.WriteFile(file, data, 0600); err != nil {
		t.Fatal(err)
	}
	w := submitPIN(s, path, "1234")
	if w.Code != 401 || strings.Contains(w.Body.String(), "secret payload") {
		t.Fatal("tampered ciphertext accepted")
	}
}

func TestMissingEncryptionKeyDoesNotRegenerate(t *testing.T) {
	s := encryptedTestServer(t)
	path := uploadEncrypted(t, s, "1234", "secret payload")
	keyPath := filepath.Join(s.dir, ".encryption-key")
	if err := os.Remove(keyPath); err != nil {
		t.Fatal(err)
	}
	w := submitPIN(s, path, "1234")
	if w.Code != 500 {
		t.Fatalf("missing key: %d", w.Code)
	}
	if _, err := os.Stat(keyPath); !os.IsNotExist(err) {
		t.Fatal("missing key was silently replaced")
	}
}
