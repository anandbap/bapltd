//go:build windows

package main

import (
	"io"
	"os"
	"syscall"
)

func attachParentConsole() (io.Reader, io.Writer, func(), error) {
	kernel32 := syscall.NewLazyDLL("kernel32.dll")
	procAttachConsole := kernel32.NewProc("AttachConsole")
	procFreeConsole := kernel32.NewProc("FreeConsole")
	ret, _, _ := procAttachConsole.Call(uintptr(0xFFFFFFFF)) // ATTACH_PARENT_PROCESS
	attached := ret != 0

	conin, errIn := os.OpenFile("CONIN$", os.O_RDWR, 0)
	if errIn != nil {
		conin, errIn = os.Open("CONIN$")
	}
	conout, errOut := os.OpenFile("CONOUT$", os.O_RDWR, 0)
	if errOut != nil {
		conout, _ = os.OpenFile("CONOUT$", os.O_WRONLY, 0)
	}
	if errIn != nil {
		if attached {
			procFreeConsole.Call()
		}
		return nil, nil, nil, errIn
	}

	closer := func() {
		_ = conin.Close()
		if conout != nil {
			_ = conout.Close()
		}
		if attached {
			procFreeConsole.Call()
		}
	}
	var out io.Writer = conout
	if out == nil {
		out = os.Stderr
	}
	return conin, out, closer, nil
}
