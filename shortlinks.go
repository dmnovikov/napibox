package main

import (
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
)

var shortWords = makeShortWords()

func makeShortWords() []string {
	words := strings.Fields(`cat dog fox owl bee ant cow pig bat hen ram elk ape eel
        lion bear wolf deer duck frog fish bird goat hare swan seal crow dove crab lamb
        mouse horse tiger panda zebra otter camel koala snail shark whale rabbit monkey
        kitten puppy parrot pigeon goose turtle sheep donkey pony
        ball book pen cup hat bag box key car bus bike boat ship star moon sun sky sea
        tree leaf pine oak rose lily mint rain snow wind fire lake pond hill rock sand
        river stone cloud beach apple grape peach lemon mango melon honey bread cake
        milk rice soup salt sugar coffee cocoa berry olive pear plum corn cherry banana
        orange cookie butter cheese toast pizza pasta salad carrot onion potato tomato
        water juice candy cream nut bean egg
        red blue green pink gold grey white black yellow purple silver brown
        paper pencil brush shelf chair table spoon fork plate bowl glass bottle window
        door house room roof floor wall gate fence garden forest flower meadow island
        valley field grass path road bridge park farm nest cave coast ocean
        spring summer autumn winter morning evening sunset sunrise rainbow breeze storm
        frost mist light night day week month year music song piano drum bell dance
        smile dream magic lucky happy quiet calm sweet fresh sunny soft warm cool
        train truck plane wheel kite flag rope ring clock watch phone radio lamp candle
        planet rocket comet orbit space cloud piano beach`)
	result := make([]string, 0, len(words))
	seen := map[string]bool{}
	for _, word := range words {
		if len(word) < 3 || len(word) > 7 {
			panic("short link words must contain 3 to 7 letters")
		}
		if !seen[word] {
			result = append(result, word)
			seen[word] = true
		}
	}
	return result
}

func randomShortID() (string, error) {
	n, err := rand.Int(rand.Reader, big.NewInt(int64(len(shortWords))*1000))
	if err != nil {
		return "", err
	}
	index := n.Int64()
	return shortWords[index/1000] + fmt.Sprintf("%03d", index%1000), nil
}

func reserveShortID(dir string, next func() (string, error)) (string, string, error) {
	for attempt := 0; attempt < 128; attempt++ {
		id, err := next()
		if err != nil {
			return "", "", err
		}
		marker := filepath.Join(dir, id+".used")
		f, err := os.OpenFile(marker, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if os.IsExist(err) {
			continue
		}
		if err != nil {
			return "", "", err
		}
		if err = f.Close(); err != nil {
			os.Remove(marker)
			return "", "", err
		}
		occupied := false
		for _, suffix := range []string{".json", ".bin"} {
			_, err := os.Lstat(filepath.Join(dir, id+suffix))
			if err == nil {
				occupied = true
				break
			}
			if !os.IsNotExist(err) {
				os.Remove(marker)
				return "", "", err
			}
		}
		if occupied {
			continue
		}
		return id, marker, nil
	}
	return "", "", errors.New("unable to reserve an unused short link")
}
