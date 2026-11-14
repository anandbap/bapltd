package policystore

import (
	"bytes"
	"path/filepath"
	"sync"
	"testing"
)

func TestConcurrentCachePublishNeverExposesTruncatedFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "policy.cedar")
	content := bytes.Repeat([]byte("permit(principal, action, resource);\n"), 1000)
	if err := writeCacheFile(path, content); err != nil {
		t.Fatal(err)
	}
	var workers sync.WaitGroup
	errs := make(chan error, 8)
	for i := 0; i < 8; i++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for j := 0; j < 20; j++ {
				if err := writeCacheFile(path, content); err != nil {
					errs <- err
					return
				}
			}
		}()
	}
	for i := 0; i < 200; i++ {
		data, err := readCacheFile(path)
		if err != nil || !bytes.Equal(data, content) {
			t.Errorf("reader saw missing/truncated policy: bytes=%d err=%v", len(data), err)
			break
		}
	}
	workers.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
}
