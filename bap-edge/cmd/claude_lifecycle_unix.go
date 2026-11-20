//go:build !windows

package cmd

import (
	"os"
	"path/filepath"
	"syscall"
)

func acquireClaudeLifecycleLock(workspace string) (func(), error) {
	path := filepath.Join(workspace, ".bap", "claude-lifecycle.lock")
	if err := claudeWorkspacePath(workspace, path); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		if err == syscall.EWOULDBLOCK {
			return nil, errRuntimeRunning
		}
		return nil, err
	}
	return func() { f.Close() }, nil
}
func replaceClaudeOwner(source, target string) error { return os.Rename(source, target) }
