package main

import (
	"crypto/tls"
	"errors"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type listenerConfig struct {
	Addr      string
	CertFile  string
	KeyFile   string
	HTTPAddr  string
	PublicURL string
}

func httpsRedirect(publicURL string) (http.Handler, error) {
	u, err := url.Parse(publicURL)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.Hostname() == "" || u.User != nil || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" {
		return nil, errors.New("NAPIBOX_PUBLIC_URL must be an HTTPS origin without a path or credentials")
	}
	origin := strings.TrimSuffix(u.String(), "/")
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		http.Redirect(w, r, origin+r.URL.RequestURI(), http.StatusPermanentRedirect)
	}), nil
}

func (c listenerConfig) validate() error {
	if (c.CertFile == "") != (c.KeyFile == "") {
		return errors.New("both NAPIBOX_TLS_CERT and NAPIBOX_TLS_KEY are required")
	}
	if c.HTTPAddr != "" {
		if c.CertFile == "" {
			return errors.New("HTTP redirect listener requires TLS")
		}
		if _, err := httpsRedirect(c.PublicURL); err != nil {
			return err
		}
	}
	return nil
}

func newHTTPServer(addr string, h http.Handler) *http.Server {
	return &http.Server{Addr: addr, Handler: h, ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 10 * time.Minute, WriteTimeout: 10 * time.Minute, IdleTimeout: time.Minute, MaxHeaderBytes: 16 * 1024}
}

func (c listenerConfig) serve(h http.Handler) error {
	if err := c.validate(); err != nil {
		return err
	}
	srv := newHTTPServer(c.Addr, h)
	if c.CertFile == "" {
		return srv.ListenAndServe()
	}
	// Fail before starting redirects if the certificate is unavailable or invalid.
	if _, err := tls.LoadX509KeyPair(c.CertFile, c.KeyFile); err != nil {
		return err
	}
	srv.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	listener, err := net.Listen("tcp", c.Addr)
	if err != nil {
		return err
	}
	defer listener.Close()
	if c.HTTPAddr != "" {
		redirectHandler, _ := httpsRedirect(c.PublicURL)
		redirect := newHTTPServer(c.HTTPAddr, redirectHandler)
		httpListener, err := net.Listen("tcp", c.HTTPAddr)
		if err != nil {
			return err
		}
		defer httpListener.Close()
		defer redirect.Close()
		go func() {
			if err := redirect.Serve(httpListener); err != nil && !errors.Is(err, http.ErrServerClosed) {
				log.Printf("HTTP redirect listener failed: %v", err)
				srv.Close()
			}
		}()
		log.Printf("HTTP redirects on %s to %s", c.HTTPAddr, c.PublicURL)
	}
	return srv.ServeTLS(listener, c.CertFile, c.KeyFile)
}
