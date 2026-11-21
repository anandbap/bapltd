package bapsh

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"bap-edge/internal/authz"
	"mvdan.cc/sh/v3/expand"
	"mvdan.cc/sh/v3/interp"
	"mvdan.cc/sh/v3/syntax"
)

// Options configure the BAP-aware restricted shell execution.
type Options struct {
	SessionID     string
	ClientType    string
	WorkspaceRoot string
	Stdin         io.Reader
	Stdout        io.Writer
	Stderr        io.Writer
	Env           []string
	Timeout       time.Duration
}

// Parse parses a shell script string into a syntax.File AST.
func Parse(script string) (*syntax.File, error) {
	p := syntax.NewParser()
	f, err := p.Parse(strings.NewReader(script), "")
	if err != nil {
		return nil, fmt.Errorf("bapsh parse error: %w", err)
	}
	return f, nil
}

// ExtractCallCommands walks the AST and returns all top-level and subshell command invocations.
func ExtractCallCommands(f *syntax.File) [][]string {
	var calls [][]string
	syntax.Walk(f, func(node syntax.Node) bool {
		if call, ok := node.(*syntax.CallExpr); ok && len(call.Args) > 0 {
			var cmdArgs []string
			for _, word := range call.Args {
				var sb strings.Builder
				for _, part := range word.Parts {
					if lit, ok := part.(*syntax.Lit); ok {
						sb.WriteString(lit.Value)
					} else if sval, ok := part.(*syntax.SglQuoted); ok {
						sb.WriteString(sval.Value)
					} else if dval, ok := part.(*syntax.DblQuoted); ok {
						for _, p := range dval.Parts {
							if dlit, ok := p.(*syntax.Lit); ok {
								sb.WriteString(dlit.Value)
							}
						}
					}
				}
				cmdArgs = append(cmdArgs, sb.String())
			}
			if len(cmdArgs) > 0 && cmdArgs[0] != "" {
				calls = append(calls, cmdArgs)
			}
		}
		return true
	})
	return calls
}

// Run executes a shell script string within a BAP-governed restricted AST interpreter.
func Run(ctx context.Context, script string, opts Options) error {
	f, err := Parse(script)
	if err != nil {
		return err
	}

	ws := opts.WorkspaceRoot
	if ws == "" {
		ws = authz.GetWorkspaceRoot()
	}

	sess := opts.SessionID
	if sess == "" {
		sess = "sess-bapsh-interactive"
	}

	client := opts.ClientType
	if client == "" {
		client = "agent"
	}

	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = 5 * time.Minute
	}

	subCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// Intercept every command execution in the AST before dispatch
	execHandler := func(hCtx context.Context, args []string) error {
		if len(args) == 0 {
			return nil
		}
		cmdName := args[0]
		fullLine := strings.Join(args, " ")

		// 1. Guard BAP authority paths & credential secrets
		for _, arg := range args {
			if authz.IsBAPAuthorityPath(arg) {
				return fmt.Errorf("BAP ZERO-TRUST SECURITY VIOLATION: Access to BAP authority/state path %q is strictly forbidden", arg)
			}
			lower := strings.ToLower(filepath.ToSlash(arg))
			if strings.Contains(lower, ".env") || strings.Contains(lower, ".aws/credentials") || strings.Contains(lower, ".ssh/id_") {
				return fmt.Errorf("BAP POLICY DENIAL: Access to credential file %q is permanently denied", arg)
			}
		}

		// 2. Resolve ZSP checks for this specific command invocation
		cmdArgs := ""
		if len(args) > 1 {
			cmdArgs = strings.Join(args[1:], " ")
		}

		// Read-only inspection within workspace is exempted
		if authz.IsLocalReadOnlyCommand(fullLine, cmdName, cmdArgs, ws) {
			return interp.DefaultExecHandler(timeout)(hCtx, args)
		}

		// Evaluate policy and ZSP grant status
		zspDir := authz.ResolveZSPDir()
		zspChecks := authz.ResolveZSPCommandChecks(fullLine, cmdName, cmdArgs, "", "", ws)
		_, _, _, zspErr := authz.AuthorizeSessionCommandBatch(
			zspDir,
			sess,
			client,
			fullLine,
			ws,
			zspChecks,
			true,
			[]string{fmt.Sprintf("broker:%d", os.Getpid())},
			"bapsh",
		)
		if zspErr != nil {
			var reqActions, reqResources []string
			for _, c := range zspChecks {
				reqActions = append(reqActions, c.Action)
				res := c.CanonicalResource
				if res == "" || !c.EscapesWorkspace {
					res = "workspace://current"
				}
				reqResources = append(reqResources, res)
			}

			var policy *authz.PermissionPolicy
			if _, _, _, secret, sErr := authz.EnsureSessionPrincipal(zspDir, sess, client); sErr == nil {
				policy, _ = authz.LoadPermissionPolicy(zspDir, secret)
			}
			if policy == nil {
				policy, _ = authz.DefaultPermissionPolicy()
			}

			if policy != nil {
				decision := policy.Evaluate(reqActions, reqResources)
				if len(decision.Denied) > 0 {
					return fmt.Errorf("BAP POLICY DENIAL: Action(s) %s permanently denied by enterprise policy", authz.FormatPairs(decision.Denied))
				}
				if len(decision.NeedsApproval) > 0 || errors.Is(zspErr, authz.ErrHighRiskApprovalRequired) {
					p, rErr := authz.RaisePendingApproval(zspDir, authz.PendingApproval{
						SessionID:           sess,
						RequestingSessionID: sess,
						ClientType:          client,
						Mission:             "TASK_EXECUTION",
						Goal:                fullLine,
						Actions:             reqActions,
						Resources:           reqResources,
						MaxUses:             1,
						TTLSeconds:          300,
						Reason:              fmt.Sprintf("high-risk execution in bapsh requires human approval: %s", authz.FormatPairs(decision.NeedsApproval)),
					})
					if rErr == nil && p != nil {
						return fmt.Errorf("HUMAN APPROVAL REQUIRED: Action(s) require verified human approval.\nPending Request ID: %s\nDEVELOPER ACTION: Run 'bapedge zsp approve %s' in your terminal.\nAGENT: Stop and ask the developer to approve request %s. Do NOT run bapedge zsp authorize; retry once approved", p.ID, p.ID, p.ID)
					}
					return errors.New("HUMAN APPROVAL REQUIRED: High-risk action requires interactive human approval")
				}
			}
			return fmt.Errorf("ZeroStandingPrivilegeViolation: %w", zspErr)
		}

		// Verified in-boundary action: execute via standard runner
		return interp.DefaultExecHandler(timeout)(hCtx, args)
	}

	var runnerOpts []interp.RunnerOption
	runnerOpts = append(runnerOpts, interp.ExecHandler(execHandler))
	runnerOpts = append(runnerOpts, interp.Dir(ws))
	runnerOpts = append(runnerOpts, interp.StdIO(opts.Stdin, opts.Stdout, opts.Stderr))

	envList := opts.Env
	if len(envList) == 0 {
		envList = os.Environ()
	}
	runnerOpts = append(runnerOpts, interp.Env(expand.ListEnviron(envList...)))

	runner, err := interp.New(runnerOpts...)
	if err != nil {
		return fmt.Errorf("bapsh init error: %w", err)
	}

	return runner.Run(subCtx, f)
}
