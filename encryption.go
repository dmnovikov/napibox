package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"html/template"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"
)

var secretMu sync.Mutex
var pinPage = template.Must(template.ParseFS(assets, "web/pin.html"))
var attemptsMu sync.Mutex

type pinWindow struct {
	count int
	until time.Time
}

var pinAttempts = map[string]pinWindow{}

func validPIN(pin string) bool {
	if len(pin) != 4 {
		return false
	}
	for _, c := range pin {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

// The server secret prevents guessing a four-digit PIN using only a stolen blob.
// It is deliberately kept out of file metadata and the upload audit log.
func (s server) masterKey(create bool) ([]byte, error) {
	secretMu.Lock()
	defer secretMu.Unlock()
	path := filepath.Join(s.dir, ".encryption-key")
	key, err := os.ReadFile(path)
	if err == nil {
		if len(key) != 32 {
			return nil, errors.New("invalid encryption key")
		}
		return key, nil
	}
	if !os.IsNotExist(err) || !create {
		return nil, err
	}
	key = make([]byte, 32)
	if _, err = rand.Read(key); err != nil {
		return nil, err
	}
	f, err := os.CreateTemp(s.dir, ".upload-key-")
	if err != nil {
		return nil, err
	}
	defer os.Remove(f.Name())
	if _, err = f.Write(key); err != nil {
		f.Close()
		return nil, err
	}
	if err = f.Sync(); err != nil {
		f.Close()
		return nil, err
	}
	if err = f.Close(); err != nil {
		return nil, err
	}
	if err = os.Link(f.Name(), path); err != nil {
		return nil, err
	}
	return key, nil
}

func (s server) messageCipher(id, pin string, create bool) (cipher.AEAD, error) {
	master, err := s.masterKey(create)
	if err != nil {
		return nil, err
	}
	mac := hmac.New(sha256.New, master)
	mac.Write([]byte("napibox-pin-v1\x00" + id + "\x00" + pin))
	block, err := aes.NewCipher(mac.Sum(nil))
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func (s server) encryptMessage(id, pin string, plain []byte) ([]byte, error) {
	aead, err := s.messageCipher(id, pin, true)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err = rand.Read(nonce); err != nil {
		return nil, err
	}
	return aead.Seal(nonce, nonce, plain, []byte(id)), nil
}

func allowPINAttempt(key string) bool {
	attemptsMu.Lock()
	defer attemptsMu.Unlock()
	now := time.Now()
	for k, v := range pinAttempts {
		if !now.Before(v.until) {
			delete(pinAttempts, k)
		}
	}
	v := pinAttempts[key]
	if v.count >= 5 {
		return false
	}
	if v.count == 0 {
		v.until = now.Add(time.Minute)
	}
	v.count++
	pinAttempts[key] = v
	return true
}

func showPIN(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	if err := pinPage.Execute(w, struct{ Error string }{message}); err != nil {
		log.Print(err)
	}
}

func (s server) protectedDownload(w http.ResponseWriter, r *http.Request, id string, info fileInfo) {
	if r.Method == http.MethodGet || r.Method == http.MethodHead {
		showPIN(w, 200, "")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1024)
	if err := r.ParseForm(); err != nil {
		showPIN(w, 400, "Некорректный запрос")
		return
	}
	pin := r.PostForm.Get("pin")
	if !validPIN(pin) {
		showPIN(w, 400, "Введите PIN из 4 цифр")
		return
	}
	if !allowPINAttempt(filepath.Join(s.dir, id)) {
		w.Header().Set("Retry-After", "60")
		showPIN(w, 429, "Слишком много попыток. Подождите минуту.")
		return
	}
	aead, err := s.messageCipher(id, pin, false)
	if err != nil {
		log.Printf("Decryption key unavailable: %v", err)
		showPIN(w, 500, "Не удалось открыть сообщение")
		return
	}
	f, err := os.Open(filepath.Join(s.dir, id+".bin"))
	if err != nil {
		http.NotFound(w, r)
		return
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maxSize+29))
	if err != nil || len(data) > maxSize+28 || len(data) < aead.NonceSize()+aead.Overhead() {
		showPIN(w, 500, "Не удалось прочитать сообщение")
		return
	}
	plain, err := aead.Open(nil, data[:aead.NonceSize()], data[aead.NonceSize():], []byte(id))
	if err != nil {
		showPIN(w, 401, "Неверный PIN-код или сообщение повреждено")
		return
	}
	attemptsMu.Lock()
	delete(pinAttempts, filepath.Join(s.dir, id))
	attemptsMu.Unlock()
	showMessage(w, info, plain)
}
