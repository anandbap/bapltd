//go:build windows

package sandbox

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"
)

func TestCMDArgvHelper(t *testing.T) {
	if os.Getenv("BAP_CMD_ARGV_HELPER") != "1" {
		return
	}
	for i, arg := range os.Args {
		if arg == "--" {
			json.NewEncoder(os.Stdout).Encode(os.Args[i+1:])
			os.Exit(0)
		}
	}
	os.Exit(2)
}

func TestExplicitCMDPreservesQuotedNativeArguments(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(exe)
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	helper := filepath.Join(root, "argv helper with spaces.exe")
	if err := os.WriteFile(helper, data, 0700); err != nil {
		t.Fatal(err)
	}
	want := []string{"import sys; open(sys.argv[1], 'a').write('1\\n')", filepath.Join(root, "counter with spaces.txt")}
	args := []string{helper, "-test.run=TestCMDArgvHelper", "--"}
	args = append(args, want...)
	for i := range args {
		args[i] = syscall.EscapeArg(args[i])
	}
	cmd := BuildExecCmdWithShell(strings.Join(args, " "), "cmd")
	cleanup := ConfigureSandbox(cmd)
	defer cleanup()
	cmd.Env = append(os.Environ(), "BAP_CMD_ARGV_HELPER=1")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("CMD failed: %v\n%s", err, out)
	}
	var got []string
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatalf("invalid child argv: %v\n%s", err, out)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("native argv corrupted:\n got %q\nwant %q", got, want)
	}
}
