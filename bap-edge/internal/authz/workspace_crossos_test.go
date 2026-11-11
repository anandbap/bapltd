package authz

import (
	"runtime"
	"testing"
)

func TestCrossOSDrivePathBoundary(t *testing.T) {
	ws := t.TempDir()

	if !isWindowsDrivePath(`C:\`) || !isWindowsDrivePath(`d:/foo`) || isWindowsDrivePath(`/usr/bin`) {
		t.Fatalf("unexpected isWindowsDrivePath result")
	}

	if !IsPathOutsideWorkspace(ws, `C:\`) {
		t.Fatalf("expected IsPathOutsideWorkspace(%q, %q) to return true", ws, `C:\`)
	}
	if !IsPathOutsideWorkspaceCanonical(ws, `C:\`) {
		t.Fatalf("expected IsPathOutsideWorkspaceCanonical(%q, %q) to return true", ws, `C:\`)
	}

	if runtime.GOOS != "windows" {
		if got := ResolveCanonicalPath(`C:\Windows\System32`, ws); got != "C:/Windows/System32" {
			t.Fatalf("expected preserved drive path on non-Windows host, got %q", got)
		}
	}
}
