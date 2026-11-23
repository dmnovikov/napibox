package main

import (
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strings"
)

type trustedProxyRanges []netip.Prefix

func parseTrustedProxies(value string) (trustedProxyRanges, error) {
	if strings.TrimSpace(value) == "" {
		return nil, nil
	}
	var result trustedProxyRanges
	for _, item := range strings.Split(value, ",") {
		prefix, err := netip.ParsePrefix(strings.TrimSpace(item))
		if err != nil {
			return nil, fmt.Errorf("invalid NAPIBOX_TRUSTED_PROXIES entry: %w", err)
		}
		result = append(result, prefix.Masked())
	}
	return result, nil
}

func (s server) clientRequestInfo(r *http.Request) (string, string) {
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		ip = r.RemoteAddr
	}
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	peer, err := netip.ParseAddr(ip)
	if err != nil {
		return ip, scheme
	}
	trusted := false
	for _, prefix := range s.trustedProxies {
		if prefix.Contains(peer.Unmap()) {
			trusted = true
			break
		}
	}
	if !trusted {
		return ip, scheme
	}
	if forwarded, err := netip.ParseAddr(strings.TrimSpace(r.Header.Get("X-Real-IP"))); err == nil && forwarded.Zone() == "" {
		ip = forwarded.Unmap().String()
	}
	if forwarded := r.Header.Get("X-Forwarded-Proto"); forwarded == "http" || forwarded == "https" {
		scheme = forwarded
	}
	return ip, scheme
}
