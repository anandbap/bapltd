//go:build !windows

package cmd

import (
	"bap-edge/internal/state"
	"os"
	"path/filepath"
	"syscall"
)

func acquireRuntimeLock(kind string) (func(), error) {
	if err := os.MkdirAll(state.Dir(), 0700); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(filepath.Join(state.Dir(), kind+".lock"), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	if err = syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		if err == syscall.EWOULDBLOCK {
			return nil, errRuntimeRunning
		}
		return nil, err
	}
	return func() { f.Close() }, nil
}
