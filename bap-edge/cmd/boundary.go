package cmd

import (
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"bap-edge/internal/capability"
	"bap-edge/internal/egress"
	"bap-edge/internal/learn"
	"bap-edge/internal/state"
)

// Boundary commands (ADR-001/002): `bap run`, `bap egress`, `bap learn`. They are human operator
// commands; the hook blocks agents from invoking them (humanOnlyBAPCommand), and the profile lives in the
// BAP state directory, outside any workspace the agent can write.

func profilePath(workspace string) string {
	sum := sha256.Sum256([]byte(strings.ToLower(filepath.Clean(workspace))))
	return filepath.Join(state.Dir(), "profiles", hex.EncodeToString(sum[:8])+".json")
}

func effectLog() *learn.Log { return learn.NewLog(filepath.Join(state.Dir(), "effects.jsonl")) }

func currentWorkspace() string {
	wd, err := os.Getwd()
	if err != nil {
		return "."
	}
	return wd
}

func loadProfile() (capability.Profile, string, error) {
	ws := currentWorkspace()
	path := profilePath(ws)
	p, err := capability.Load(path, ws)
	return p, path, err
}

// RunEgress implements `bap egress allow|list|serve`.
func RunEgress(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: bap egress <allow HOST | list | serve [--addr 127.0.0.1:3128]>")
	}
	p, path, err := loadProfile()
	if err != nil {
		return err
	}
	switch args[0] {
	case "list":
		fmt.Printf("workspace: %s\nprofile:   %s\n", p.Workspace, path)
		if len(p.EgressAllow) == 0 {
			fmt.Println("egress:    (none: the sandbox has no network)")
		}
		for _, h := range p.EgressAllow {
			fmt.Println("egress:    allow", h)
		}
		return nil
	case "allow":
		if len(args) < 2 {
			return fmt.Errorf("usage: bap egress allow HOST[:PORT] (or *.domain)")
		}
		next, err := p.AddEgress(args[1])
		if err != nil {
			return fmt.Errorf("refused: %w", err)
		}
		if err := next.Save(path); err != nil {
			return err
		}
		_ = effectLog().Append(learn.Event{Kind: "egress", Target: args[1], Verdict: "allow", Source: "bap-egress-allow", HumanApproved: true})
		fmt.Printf("Allowed egress to %s for %s\n", args[1], p.Workspace)
		return nil
	case "serve":
		fs := flag.NewFlagSet("egress serve", flag.ContinueOnError)
		addr := fs.String("addr", "127.0.0.1:3128", "listen address")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		return serveEgress(p, path, *addr)
	}
	return fmt.Errorf("unknown egress command %q", args[0])
}

func serveEgress(p capability.Profile, path, addr string) error {
	proxy := egress.New(p, effectLog(), "operator")
	fmt.Printf("BAP egress proxy on %s (allow: %v). Blocked destinations are recorded; review with `bap learn`.\n", addr, p.EgressAllow)
	return http.ListenAndServe(addr, proxy)
}

// RunLearn implements `bap learn [apply HOST]`.
func RunLearn(args []string) error {
	p, path, err := loadProfile()
	if err != nil {
		return err
	}
	events, err := effectLog().ReadAll()
	if err != nil {
		return err
	}
	props := learn.Mine(events, p)
	if len(args) >= 2 && args[0] == "apply" {
		for _, pr := range props {
			if strings.EqualFold(pr.Value, args[1]) {
				next, err := learn.Apply(pr, p)
				if err != nil {
					return fmt.Errorf("refused: %w", err)
				}
				if err := next.Save(path); err != nil {
					return err
				}
				fmt.Printf("Applied: allow egress to %s (would have unblocked %d past attempt(s)).\n", pr.Value, pr.Replay.WouldAllow)
				return nil
			}
		}
		return fmt.Errorf("no proposal for %q (run `bap learn` to list them)", args[1])
	}
	fmt.Printf("Observed %d effect event(s) for %s\n", len(events), p.Workspace)
	if len(props) == 0 {
		fmt.Println("No recommendations: nothing the agent was blocked on is both repeated and safe to suggest.")
		return nil
	}
	for _, pr := range props {
		fmt.Printf("\n- %s %s   [risk: %s]\n    %s\n    replay: would have allowed %d past attempt(s)\n    apply:  bap learn apply %s\n",
			pr.Kind, pr.Value, pr.Risk, pr.Reason, pr.Replay.WouldAllow, pr.Value)
	}
	return nil
}

// RunRun implements `bap run [--provider auto|bwrap|seatbelt|docker] [--print] -- cmd args...`.
func RunRun(args []string) error {
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	provider := fs.String("provider", "auto", "auto|bwrap|seatbelt|docker")
	printOnly := fs.Bool("print", false, "print the isolation spec instead of running")
	image := fs.String("image", "", "container image (docker provider)")
	network := fs.String("docker-network", "none", "docker network; use an --internal network shared with the egress proxy")
	if err := fs.Parse(args); err != nil {
		return err
	}
	argv := fs.Args()
	if len(argv) == 0 {
		return fmt.Errorf("usage: bap run [--provider P] [--print] -- command args...")
	}
	p, _, err := loadProfile()
	if err != nil {
		return err
	}
	if *image != "" {
		p.Image = *image
	}
	prov := *provider
	if prov == "auto" { // native, unprivileged, no Docker: AppContainer / bubblewrap / Seatbelt
		switch runtime.GOOS {
		case "linux":
			prov = "bwrap"
		case "darwin":
			prov = "seatbelt"
		default:
			prov = "appcontainer"
		}
	}
	if prov == "appcontainer" {
		return runAppContainer(p, argv)
	}
	var bin string
	var full []string
	switch prov {
	case "bwrap":
		bin = "bwrap"
		sock := filepath.Join(os.TempDir(), fmt.Sprintf("bap-egress-%d.sock", os.Getpid()))
		p.ProxyAddr = "unix:" + sock
		p.ShimPath, _ = os.Executable()
		if !*printOnly {
			if _, lerr := exec.LookPath(bin); lerr != nil {
				return fmt.Errorf("provider %q needs %q installed. Nothing was run: BAP will not fall back to an unsandboxed process", prov, bin)
			}
			stop, serr := egress.ServeUnix(egress.New(p, effectLog(), "run"), sock)
			if serr != nil {
				return serr
			}
			defer stop()
		}
		full, err = capability.BwrapArgs(p, argv)
	case "docker":
		bin = "docker"
		full, err = capability.DockerArgs(p, *network, argv)
	case "seatbelt":
		bin = "sandbox-exec"
		sock := filepath.Join(os.TempDir(), fmt.Sprintf("bap-egress-%d.sock", os.Getpid()))
		p.ProxyAddr = "unix:" + sock
		self, _ := os.Executable()
		if !*printOnly {
			if _, lerr := exec.LookPath(bin); lerr != nil {
				return fmt.Errorf("provider %q needs %q installed. Nothing was run: BAP will not fall back to an unsandboxed process", prov, bin)
			}
			stop, serr := egress.ServeUnix(egress.New(p, effectLog(), "run"), sock)
			if serr != nil {
				return serr
			}
			defer stop()
		}
		var prof string
		prof, err = capability.SeatbeltProfile(p)
		full = append([]string{"-p", prof, self, "__shim", "--socket", sock, "--"}, argv...)
	default:
		return fmt.Errorf("unknown provider %q", prov)
	}
	if err != nil {
		return err
	}
	if *printOnly {
		fmt.Println(bin, strings.Join(full, " "))
		return nil
	}
	if _, lerr := exec.LookPath(bin); lerr != nil {
		return fmt.Errorf("provider %q needs %q installed. Nothing was run: BAP will not fall back to an unsandboxed process", prov, bin)
	}
	cmd := exec.Command(bin, full...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	return cmd.Run()
}
