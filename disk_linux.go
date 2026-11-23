package main

import (
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"sync"
	"syscall"
)

const minFreeSpace uint64 = 10 * 1024 * 1024 * 1024
const lowSpaceMessage = "Извините, место закончилось. Обратитесь к супергерою"

var errLowSpace = errors.New("disk free space below reserve")
var errSpaceCheck = errors.New("unable to check disk free space")
var diskWriteMu sync.Mutex

func availableSpace(dir string) (uint64, error) {
	var stat syscall.Statfs_t
	if err := syscall.Statfs(dir, &stat); err != nil {
		return 0, err
	}
	return stat.Bavail * uint64(stat.Bsize), nil
}

func (s server) checkSpace(next uint64) error {
	probe := s.spaceAvailable
	if probe == nil {
		probe = availableSpace
	}
	free, err := probe(s.dir)
	if err != nil {
		return fmt.Errorf("%w: %v", errSpaceCheck, err)
	}
	if free < minFreeSpace || free-minFreeSpace < next {
		return errLowSpace
	}
	return nil
}

func (s server) spaceError(w http.ResponseWriter, err error) {
	if errors.Is(err, errLowSpace) {
		http.Error(w, lowSpaceMessage, http.StatusInsufficientStorage)
		return
	}
	log.Print(err)
	http.Error(w, "Не удалось проверить свободное место. Попробуйте позже", http.StatusServiceUnavailable)
}

type spaceWriter struct {
	s    server
	file *os.File
}

func (w spaceWriter) Write(p []byte) (int, error) {
	// Serialize the check and write across concurrent uploads.
	diskWriteMu.Lock()
	defer diskWriteMu.Unlock()
	if err := w.s.checkSpace(uint64(len(p))); err != nil {
		return 0, err
	}
	return w.file.Write(p)
}
