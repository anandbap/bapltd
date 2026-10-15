package cmd

import (
	"flag"
	"fmt"

	"bap-edge/pkg/version"
)

// RunVersion prints the bapedge version manifest in human-readable or JSON format.
func RunVersion(args []string) error {
	fs := flag.NewFlagSet("version", flag.ContinueOnError)
	jsonFlag := fs.Bool("json", false, "Output version information in JSON format")
	fs.BoolVar(jsonFlag, "j", false, "Output version information in JSON format (shorthand)")

	if err := fs.Parse(args); err != nil {
		return err
	}

	info := version.Get("bapedge")
	if *jsonFlag {
		fmt.Println(info.JSON())
		return nil
	}

	fmt.Println(info.String())
	return nil
}
