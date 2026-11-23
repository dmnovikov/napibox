package main

import (
	"net/http/httptest"
	"testing"
)

func TestHTTPSRedirect(t *testing.T) {
	h, err := httpsRedirect("https://files.example.com/")
	if err != nil {
		t.Fatal(err)
	}
	for _, method := range []string{"GET", "POST"} {
		r := httptest.NewRequest(method, "http://untrusted.example/f/abc?test=1", nil)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != 308 || w.Header().Get("Location") != "https://files.example.com/f/abc?test=1" {
			t.Fatalf("redirect: %d %s", w.Code, w.Header().Get("Location"))
		}
	}
}

func TestTLSConfiguration(t *testing.T) {
	for _, config := range []listenerConfig{
		{CertFile: "cert.pem"},
		{KeyFile: "key.pem"},
		{HTTPAddr: ":80"},
		{CertFile: "cert.pem", KeyFile: "key.pem", HTTPAddr: ":80", PublicURL: "http://files.example.com"},
		{CertFile: "cert.pem", KeyFile: "key.pem", HTTPAddr: ":80", PublicURL: "https://user:password@files.example.com"},
	} {
		if config.validate() == nil {
			t.Fatalf("invalid config accepted: %+v", config)
		}
	}
	for _, config := range []listenerConfig{
		{Addr: ":8080"},
		{Addr: ":443", CertFile: "cert.pem", KeyFile: "key.pem"},
		{Addr: ":443", CertFile: "cert.pem", KeyFile: "key.pem", HTTPAddr: ":80", PublicURL: "https://files.example.com"},
	} {
		if err := config.validate(); err != nil {
			t.Fatal(err)
		}
	}
}
