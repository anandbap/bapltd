package sandbox

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestMain(m *testing.M) {
	// Run a real executable as a PATH shim on every platform, including Windows.
	if os.Getenv("BAP_TEST_GIT_IDENTITY_SHIM") == "1" {
		if os.Getenv("BAP_IN_BROKER") != "1" {
			os.Exit(91) // A real shim would start another broker here.
		}
		if len(os.Args) == 4 && os.Args[1] == "config" && os.Args[2] == "--get" {
			switch os.Args[3] {
			case "user.name":
				fmt.Println("Shim Developer")
			case "user.email":
				fmt.Println("shim@example.test")
			}
		}
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func TestGitIdentityLookupDoesNotReenterBrokerShim(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	binary, err := os.ReadFile(exe)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	name := "git"
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	if err := os.WriteFile(filepath.Join(dir, name), binary, 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("BAP_TEST_GIT_IDENTITY_SHIM", "1")
	t.Setenv("BAP_IN_BROKER", "")

	got := withGitIdentity(nil, "git commit -m fixture")
	for key, want := range map[string]string{
		"GIT_AUTHOR_NAME": "Shim Developer", "GIT_COMMITTER_NAME": "Shim Developer",
		"GIT_AUTHOR_EMAIL": "shim@example.test", "GIT_COMMITTER_EMAIL": "shim@example.test",
	} {
		if value := lookup(got, key); value != want {
			t.Errorf("%s = %q, want %q (identity lookup re-entered the broker shim)", key, value, want)
		}
	}
}
