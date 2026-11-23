package main

import (
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestMemorableIDs(t *testing.T) {
	pattern := regexp.MustCompile(`^[a-z]{3,7}[0-9]{3}$`)
	for i := 0; i < 2000; i++ {
		id, err := randomShortID()
		if err != nil {
			t.Fatal(err)
		}
		if len(id) > 10 || !pattern.MatchString(id) || !tokenPattern.MatchString(id) {
			t.Fatalf("bad short ID: %s", id)
		}
		base := strings.TrimRight(id, "0123456789")
		found := false
		for _, word := range shortWords {
			if base == word {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("ID does not contain exactly one dictionary word: %s", id)
		}
	}
}

func TestReservationCollisionAndExpiry(t *testing.T) {
	s := server{dir: t.TempDir()}
	id, _, err := reserveShortID(s.dir, func() (string, error) { return "prettycat1", nil })
	if err != nil {
		t.Fatal(err)
	}
	meta, _ := json.Marshal(fileInfo{Name: "old.txt", Expires: time.Now().Add(-time.Second)})
	if err := os.WriteFile(filepath.Join(s.dir, id+".json"), meta, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(s.dir, id+".bin"), []byte("old content"), 0600); err != nil {
		t.Fatal(err)
	}
	s.cleanup()
	if _, err := os.Stat(filepath.Join(s.dir, id+".used")); err != nil {
		t.Fatal("expiry removed reserved ID", err)
	}
	calls := 0
	next := func() (string, error) {
		calls++
		if calls == 1 {
			return "prettycat1", nil
		}
		return "angrydog12", nil
	}
	second, _, err := reserveShortID(s.dir, next)
	if err != nil || second != "angrydog12" || calls != 2 {
		t.Fatalf("collision not retried: %s %v", second, err)
	}
	w := httptest.NewRecorder()
	s.handler().ServeHTTP(w, httptest.NewRequest("GET", "/prettycat1", nil))
	if w.Code != 404 {
		t.Fatalf("expired link unexpectedly reused: %d", w.Code)
	}
}

func TestConcurrentReservations(t *testing.T) {
	dir := t.TempDir()
	var wait sync.WaitGroup
	ids := make(chan string, 32)
	for i := 0; i < 32; i++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			calls := 0
			id, _, err := reserveShortID(dir, func() (string, error) { calls++; return "bluefox" + strconv.Itoa(calls), nil })
			if err != nil {
				t.Error(err)
				return
			}
			ids <- id
		}()
	}
	wait.Wait()
	close(ids)
	seen := map[string]bool{}
	for id := range ids {
		if seen[id] {
			t.Fatalf("duplicate reservation: %s", id)
		}
		seen[id] = true
	}
	if len(seen) != 32 {
		t.Fatalf("only %d reservations succeeded", len(seen))
	}
}

func TestExistingBlobNeverOverwritten(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "prettycat1.bin")
	if err := os.WriteFile(path, []byte("existing file"), 0600); err != nil {
		t.Fatal(err)
	}
	calls := 0
	id, _, err := reserveShortID(dir, func() (string, error) {
		calls++
		if calls == 1 {
			return "prettycat1", nil
		}
		return "madcat123", nil
	})
	if err != nil || id != "madcat123" {
		t.Fatalf("occupied ID not skipped: %s %v", id, err)
	}
	data, err := os.ReadFile(path)
	if err != nil || string(data) != "existing file" {
		t.Fatal("existing file changed")
	}
}

func TestLegacyBase64Link(t *testing.T) {
	s := server{dir: t.TempDir()}
	id := strings.Repeat("b", 16)
	meta, _ := json.Marshal(fileInfo{Name: "old.txt", Expires: time.Now().Add(time.Hour)})
	if err := os.WriteFile(filepath.Join(s.dir, id+".json"), meta, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(s.dir, id+".bin"), []byte("old file"), 0600); err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	s.handler().ServeHTTP(w, httptest.NewRequest("GET", "/f/"+id, nil))
	if w.Code != 200 || w.Body.String() != "old file" {
		t.Fatalf("legacy16 download: %d", w.Code)
	}
}

func TestLegacyTwoWordLinks(t *testing.T) {
	for _, id := range []string{"prettycat1", "angrydog12"} {
		t.Run(id, func(t *testing.T) {
			s := server{dir: t.TempDir()}
			meta, _ := json.Marshal(fileInfo{Name: "existing.txt", Expires: time.Now().Add(time.Hour)})
			if err := os.WriteFile(filepath.Join(s.dir, id+".json"), meta, 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(s.dir, id+".bin"), []byte("existing content"), 0600); err != nil {
				t.Fatal(err)
			}
			w := httptest.NewRecorder()
			s.handler().ServeHTTP(w, httptest.NewRequest("GET", "/"+id, nil))
			if w.Code != 200 || w.Body.String() != "existing content" {
				t.Fatalf("old link failed: %d", w.Code)
			}
		})
	}
}
