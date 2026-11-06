//go:build !windows

package main

import (
	"io"
	"os"
)

func attachParentConsole() (io.Reader, io.Writer, func(), error) {
	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		return nil, nil, nil, err
	}
	closer := func() {
		_ = tty.Close()
	}
	return tty, tty, closer, nil
}
