package main

import (
	"crypto/tls"
	"net/http/httptest"
	"testing"
)

func TestTrustedProxyHeaders(t *testing.T) {
	trusted, err := parseTrustedProxies("192.0.2.10/32")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ name, peer, header, proto, wantIP, wantProto string }{
		{"trusted", "192.0.2.10:1234", "198.51.100.7", "https", "198.51.100.7", "https"},
		{"untrusted", "192.0.2.254:1234", "10.1.2.3", "https", "192.0.2.254", "http"},
		{"invalid-ip", "192.0.2.10:1234", "198.51.100.7, 10.1.2.3", "https", "192.0.2.10", "https"},
		{"invalid-proto", "192.0.2.10:1234", "198.51.100.7", "https,http", "198.51.100.7", "http"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := server{trustedProxies: trusted}
			r := httptest.NewRequest("GET", "/", nil)
			r.RemoteAddr = tc.peer
			r.Header.Set("X-Real-IP", tc.header)
			r.Header.Set("X-Forwarded-Proto", tc.proto)
			ip, proto := s.clientRequestInfo(r)
			if ip != tc.wantIP || proto != tc.wantProto {
				t.Fatalf("got %s %s", ip, proto)
			}
		})
	}
	r := httptest.NewRequest("GET", "/", nil)
	r.TLS = &tls.ConnectionState{}
	r.Header.Set("X-Forwarded-Proto", "http")
	if _, scheme := (server{}).clientRequestInfo(r); scheme != "https" {
		t.Fatal("untrusted header downgraded TLS")
	}
}

func TestTrustedProxyConfiguration(t *testing.T) {
	for _, bad := range []string{"*", "invalid", "192.0.2.10", "127.0.0.1/32,,192.168.1.0/24"} {
		if _, err := parseTrustedProxies(bad); err == nil {
			t.Fatalf("accepted %q", bad)
		}
	}
}
