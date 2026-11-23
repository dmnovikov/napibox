package main

import (
	"errors"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

func TestDiskReserve(t *testing.T) {
	for _, tc := range []struct {
		name   string
		free   uint64
		fail   bool
		status int
	}{
		{"below", minFreeSpace - 1, false, 507},
		{"at_reserve", minFreeSpace, false, 507},
		{"enough", minFreeSpace + 5, false, 201},
		{"check_failure", 0, true, 503},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := server{dir: t.TempDir(), spaceAvailable: func(string) (uint64, error) {
				if tc.fail {
					return 0, errors.New("disk unavailable")
				}
				return tc.free, nil
			}}
			w := httptest.NewRecorder()
			s.handler().ServeHTTP(w, httptest.NewRequest("POST", "/api/upload?name=test.txt", strings.NewReader("hello")))
			if w.Code != tc.status {
				t.Fatalf("got %d: %s", w.Code, w.Body)
			}
			if tc.status == 507 && !strings.Contains(w.Body.String(), lowSpaceMessage) {
				t.Fatal("missing low space message")
			}
			if tc.status != 201 {
				entries, err := os.ReadDir(s.dir)
				if err != nil {
					t.Fatal(err)
				}
				if len(entries) != 0 {
					t.Fatal("rejected upload left files")
				}
			}
		})
	}
}

func TestDiskFillsDuringUpload(t *testing.T) {
	calls := 0
	s := server{dir: t.TempDir(), spaceAvailable: func(string) (uint64, error) {
		calls++
		if calls > 2 {
			return minFreeSpace - 1, nil
		}
		return minFreeSpace + maxSize, nil
	}}
	w := httptest.NewRecorder()
	s.handler().ServeHTTP(w, httptest.NewRequest("POST", "/api/upload?name=test.bin", strings.NewReader(strings.Repeat("x", 128*1024))))
	if w.Code != 507 {
		t.Fatalf("got %d: %s", w.Code, w.Body)
	}
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatal("partial upload left files or log records")
	}
}
