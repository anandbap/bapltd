//go:build !windows

package appcontainer

import (
	"fmt"
	"os"
)

type Options struct {
	Name     string
	Argv     []string
	Dir      string
	Env      []string
	Writable []string
	Readable []string
	Stdin    *os.File
	Stdout   *os.File
	Stderr   *os.File
}

func SID(string) (string, error)  { return "", fmt.Errorf("AppContainer is Windows-only") }
func Run(Options) (int, error)    { return 2, fmt.Errorf("AppContainer is Windows-only") }
func Grant(_, _, _ string) error  { return fmt.Errorf("AppContainer is Windows-only") }
