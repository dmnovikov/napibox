package main

import (
	"bytes"
	"embed"
	"encoding/json"
	"errors"
	"io"
	"log"
	"mime"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

const maxSize = 350 * 1024 * 1024
const lifetime = 72 * time.Hour

//go:embed web/*.html
var assets embed.FS

type fileInfo struct {
	Name      string    `json:"name"`
	Expires   time.Time `json:"expires"`
	Encrypted bool      `json:"encrypted,omitempty"`
	Message   bool      `json:"message,omitempty"`
}
type server struct {
	dir            string
	spaceAvailable func(string) (uint64, error)
	trustedProxies trustedProxyRanges
}

var tokenPattern = regexp.MustCompile(`^([a-z]{3,7}[0-9]{3}|[a-z]{4,7}[0-9]{1,3}|[a-z]{8}[0-9]{1,2}|[a-z]{9}[0-9]|[A-Za-z0-9_-]{16}|[a-f0-9]{32})$`)
var uploadLogMu sync.Mutex

type uploadRecord struct {
	Time    time.Time `json:"time"`
	IP      string    `json:"ip"`
	Name    string    `json:"name"`
	Size    int64     `json:"size"`
	URL     string    `json:"url"`
	Expires time.Time `json:"expires"`
}

func (s server) logUpload(r *http.Request, id string, info fileInfo, size int64) error {
	ip, scheme := s.clientRequestInfo(r)
	link := (&url.URL{Scheme: scheme, Host: r.Host, Path: "/" + id}).String()
	data, err := json.Marshal(uploadRecord{time.Now().UTC(), ip, info.Name, size, link, info.Expires})
	if err != nil {
		return err
	}
	uploadLogMu.Lock()
	defer uploadLogMu.Unlock()
	f, err := os.OpenFile(filepath.Join(s.dir, "uploads.jsonl"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err := f.Write(append(data, '\n')); err != nil {
		return err
	}
	return f.Sync()
}

func (s server) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		b, _ := assets.ReadFile("web/index.html")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write(b)
	})
	mux.HandleFunc("POST /api/upload", s.upload)
	mux.HandleFunc("GET /f/{id}", s.download)
	mux.HandleFunc("POST /f/{id}", s.download)
	mux.HandleFunc("GET /{id}", s.download)
	mux.HandleFunc("POST /{id}", s.download)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
		mux.ServeHTTP(w, r)
	})
}

func (s server) upload(w http.ResponseWriter, r *http.Request) {
	// Browser uploads must originate from this application.
	if site := r.Header.Get("Sec-Fetch-Site"); site != "" && site != "same-origin" && site != "none" {
		http.Error(w, "Загрузка разрешена только с этой страницы", http.StatusForbidden)
		return
	}
	if r.ContentLength > maxSize {
		http.Error(w, "Максимальный размер файла — 350 МБ", 413)
		return
	}
	encrypted := r.URL.Query().Get("encrypt") == "1"
	pin := r.Header.Get("X-Napibox-Pin")
	if encrypted && (r.URL.Query().Get("kind") != "message" || !validPIN(pin)) {
		http.Error(w, "Для шифрования сообщения введите PIN из 4 цифр", 400)
		return
	}
	name := filepath.Base(strings.ReplaceAll(r.URL.Query().Get("name"), "\\", "/"))
	if name == "." || name == "/" || name == "" || len(name) > 255 || strings.ContainsAny(name, "\r\n\x00") {
		http.Error(w, "Некорректное имя файла", 400)
		return
	}
	if err := s.checkSpace(0); err != nil {
		s.spaceError(w, err)
		return
	}
	id, marker, err := reserveShortID(s.dir, randomShortID)
	if err != nil {
		http.Error(w, "Ошибка сервера", 500)
		return
	}
	published := false
	defer func() {
		if !published {
			os.Remove(marker)
		}
	}()
	var source io.Reader = http.MaxBytesReader(w, r.Body, maxSize)
	var plainSize int64
	if encrypted {
		plain, err := io.ReadAll(source)
		if err != nil {
			var tooLarge *http.MaxBytesError
			if errors.As(err, &tooLarge) {
				http.Error(w, "Максимальный размер файла — 350 МБ", 413)
			} else {
				http.Error(w, "Загрузка прервана", 400)
			}
			return
		}
		if len(plain) == 0 || bytes.Count(plain, []byte{'\n'}) >= 200 {
			http.Error(w, "Введите сообщение не длиннее 200 строк", 400)
			return
		}
		plainSize = int64(len(plain))
		ciphertext, err := s.encryptMessage(id, pin, plain)
		if err != nil {
			log.Printf("Encryption failed: %v", err)
			http.Error(w, "Не удалось зашифровать сообщение", 500)
			return
		}
		source = bytes.NewReader(ciphertext)
	}
	f, err := os.CreateTemp(s.dir, ".upload-")
	if err != nil {
		http.Error(w, "Не удалось сохранить файл", 500)
		return
	}
	defer os.Remove(f.Name())
	n, copyErr := io.Copy(spaceWriter{s: s, file: f}, source)
	if encrypted {
		n = plainSize
	}
	closeErr := f.Close()
	if copyErr != nil {
		if errors.Is(copyErr, errLowSpace) || errors.Is(copyErr, errSpaceCheck) {
			s.spaceError(w, copyErr)
			return
		}
		var tooLarge *http.MaxBytesError
		if errors.As(copyErr, &tooLarge) {
			http.Error(w, "Максимальный размер файла — 350 МБ", 413)
		} else {
			http.Error(w, "Загрузка прервана", 400)
		}
		return
	}
	if closeErr != nil {
		http.Error(w, "Не удалось сохранить файл", 500)
		return
	}
	if n == 0 {
		http.Error(w, "Файл пуст", 400)
		return
	}
	if !encrypted && r.URL.Query().Get("kind") == "message" {
		if err := validateMessage(f.Name()); err != nil {
			if errors.Is(err, errMessageLines) {
				http.Error(w, "В сообщении должно быть не больше 200 строк", 400)
			} else {
				http.Error(w, "Не удалось прочитать сообщение", 500)
			}
			return
		}
	}
	// Link publishes the completed file atomically and refuses to replace an existing ID.
	if err := os.Link(f.Name(), filepath.Join(s.dir, id+".bin")); err != nil {
		http.Error(w, "Не удалось сохранить файл", 500)
		return
	}
	info := fileInfo{Name: name, Expires: time.Now().UTC().Add(lifetime), Encrypted: encrypted, Message: r.URL.Query().Get("kind") == "message"}
	data, _ := json.Marshal(info)
	if err := os.WriteFile(filepath.Join(s.dir, id+".json"), data, 0600); err != nil {
		os.Remove(filepath.Join(s.dir, id+".bin"))
		http.Error(w, "Не удалось сохранить файл", 500)
		return
	}
	if err := s.logUpload(r, id, info, n); err != nil {
		log.Printf("Unable to log upload: %v", err)
		os.Remove(filepath.Join(s.dir, id+".json"))
		os.Remove(filepath.Join(s.dir, id+".bin"))
		http.Error(w, "Не удалось записать журнал загрузки", 500)
		return
	}
	// Keep this tombstone after expiry so an old link never points to new content.
	published = true
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(struct {
		URL     string    `json:"url"`
		Expires time.Time `json:"expires"`
	}{"/" + id, info.Expires})
}

var errMessageLines = errors.New("message exceeds 200 lines")

func validateMessage(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	buf := make([]byte, 32*1024)
	lines := 1
	for {
		n, err := f.Read(buf)
		lines += bytes.Count(buf[:n], []byte{'\n'})
		if lines > 200 {
			return errMessageLines
		}
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
	}
}

func (s server) download(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if !tokenPattern.MatchString(id) {
		http.NotFound(w, r)
		return
	}
	data, err := os.ReadFile(filepath.Join(s.dir, id+".json"))
	var info fileInfo
	if err != nil || json.Unmarshal(data, &info) != nil {
		http.NotFound(w, r)
		return
	}
	if !time.Now().Before(info.Expires) {
		http.Error(w, "Срок хранения файла истёк", http.StatusGone)
		return
	}
	if info.Encrypted {
		s.protectedDownload(w, r, id, info)
		return
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "Method not allowed", 405)
		return
	}
	f, err := os.Open(filepath.Join(s.dir, id+".bin"))
	if err != nil {
		http.NotFound(w, r)
		return
	}
	defer f.Close()
	stat, err := f.Stat()
	if err != nil {
		http.Error(w, "Ошибка чтения файла", 500)
		return
	}
	if isMessage(info) {
		if r.Method == http.MethodHead {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			return
		}
		text, err := io.ReadAll(io.LimitReader(f, maxSize+1))
		if err != nil || len(text) > maxSize {
			http.Error(w, "Не удалось прочитать сообщение", 500)
			return
		}
		showMessage(w, info, text)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", mime.FormatMediaType("attachment", map[string]string{"filename": info.Name}))
	http.ServeContent(w, r, info.Name, stat.ModTime(), f)
}

func (s server) cleanup() {
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		log.Print(err)
		return
	}
	for _, entry := range entries {
		path := filepath.Join(s.dir, entry.Name())
		if strings.HasSuffix(entry.Name(), ".json") {
			id := strings.TrimSuffix(entry.Name(), ".json")
			if !tokenPattern.MatchString(id) {
				continue
			}
			data, err := os.ReadFile(path)
			var info fileInfo
			if err != nil {
				log.Print(err)
				continue
			}
			if json.Unmarshal(data, &info) != nil {
				log.Printf("Invalid metadata: %s", entry.Name())
				continue
			}
			if !time.Now().Before(info.Expires) {
				if err := os.Remove(filepath.Join(s.dir, id+".bin")); err != nil && !os.IsNotExist(err) {
					log.Print(err)
					continue
				}
				if err := os.Remove(path); err != nil {
					log.Print(err)
				}
			}
		} else if strings.HasPrefix(entry.Name(), ".upload-") || strings.HasSuffix(entry.Name(), ".bin") {
			// Recover incomplete uploads left by an interrupted process.
			st, err := entry.Info()
			if err != nil || time.Since(st.ModTime()) < 24*time.Hour {
				continue
			}
			if strings.HasSuffix(entry.Name(), ".bin") {
				_, err = os.Stat(strings.TrimSuffix(path, ".bin") + ".json")
				if !os.IsNotExist(err) {
					continue
				}
			}
			if err := os.Remove(path); err != nil {
				log.Print(err)
			}
		}
	}
}

func main() {
	dir := os.Getenv("NAPIBOX_DATA")
	if dir == "" {
		dir = "data"
	}
	addr := os.Getenv("NAPIBOX_ADDR")
	if addr == "" {
		addr = "127.0.0.1:8080"
	}
	listeners := listenerConfig{Addr: addr, CertFile: os.Getenv("NAPIBOX_TLS_CERT"), KeyFile: os.Getenv("NAPIBOX_TLS_KEY"), HTTPAddr: os.Getenv("NAPIBOX_HTTP_ADDR"), PublicURL: os.Getenv("NAPIBOX_PUBLIC_URL")}
	if err := listeners.validate(); err != nil {
		log.Fatal(err)
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		log.Fatal(err)
	}
	proxies, err := parseTrustedProxies(os.Getenv("NAPIBOX_TRUSTED_PROXIES"))
	if err != nil {
		log.Fatal(err)
	}
	s := server{dir: dir, trustedProxies: proxies}
	s.cleanup()
	go func() {
		ticker := time.NewTicker(time.Minute)
		defer ticker.Stop()
		for range ticker.C {
			s.cleanup()
		}
	}()
	log.Printf("napibox listening on %s", addr)
	log.Fatal(listeners.serve(s.handler()))
}
