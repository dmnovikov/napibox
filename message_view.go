package main

import (
	"html/template"
	"log"
	"net/http"
	"regexp"
)

var messagePage = template.Must(template.ParseFS(assets, "web/message.html"))

// Older messages have no kind flag; recognize the exact generated UI filename.
var legacyMessageName = regexp.MustCompile(`^message-\d{4}-\d{2}-\d{2}T\d{2}-\d{2}-\d{2}-\d{3}Z\.txt$`)

func isMessage(info fileInfo) bool {
	return info.Message || info.Encrypted || legacyMessageName.MatchString(info.Name)
}

func showMessage(w http.ResponseWriter, info fileInfo, text []byte) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Referrer-Policy", "no-referrer")
	if err := messagePage.Execute(w, struct {
		Text, Expires string
		Encrypted     bool
	}{string(text), info.Expires.UTC().Format("02.01.2006 15:04 UTC"), info.Encrypted}); err != nil {
		log.Print(err)
	}
}
