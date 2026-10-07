package authz

import (
	"path/filepath"
	"strings"
)

// DecomposedAction holds canonical Cedar action and resource deduced from raw CLI tool calls.
type DecomposedAction struct {
	CanonicalAction   string
	CanonicalResource string
	ActionType        string // "read", "write", "admin", "delete", "exec"
	TargetEntity      string
}

// Decompose deterministically parses executable, command, and arguments into canonical action and resource.
func Decompose(executable, fullCommand, args string) DecomposedAction {
	exec := strings.ToLower(filepath.Base(strings.TrimSuffix(executable, ".exe")))
	tokens := tokenize(fullCommand)
	if len(tokens) == 0 {
		tokens = []string{exec}
	}

	switch exec {
	case "git":
		return decomposeGit(tokens)
	case "kubectl":
		return decomposeKubectl(tokens)
	case "helm":
		return decomposeHelm(tokens)
	case "psql", "mysql", "sqlite3", "mongosh", "redis-cli":
		return decomposeDatabase(exec, tokens)
	case "aws":
		return decomposeAWS(tokens)
	case "az":
		return decomposeAzure(tokens)
	case "gcloud":
		return decomposeGCP(tokens)
	case "docker", "podman":
		return decomposeContainer(exec, tokens)
	case "pytest":
		target := "tests"
		if len(tokens) > 1 {
			for _, t := range tokens[1:] {
				if !strings.HasPrefix(t, "-") {
					target = t
					break
				}
			}
		}
		return DecomposedAction{
			CanonicalAction:   "dev:test:exec",
			CanonicalResource: "fs://" + target,
			ActionType:        "exec",
			TargetEntity:      target,
		}
	case "npm", "yarn", "pnpm", "pip", "pip3":
		return decomposePackageManager(exec, tokens)
	case "python", "python3", "py":
		target := "interactive"
		if len(tokens) > 1 {
			for _, t := range tokens[1:] {
				if !strings.HasPrefix(t, "-") {
					target = t
					break
				}
			}
		}
		return DecomposedAction{
			CanonicalAction:   "dev:python:exec",
			CanonicalResource: "file://" + target,
			ActionType:        "exec",
			TargetEntity:      target,
		}
	case "go", "cargo", "mvn", "gradle":
		sub := "build"
		if len(tokens) > 1 {
			sub = tokens[1]
		}
		return DecomposedAction{
			CanonicalAction:   "dev:" + exec + ":" + sub,
			CanonicalResource: "repo:local",
			ActionType:        "exec",
			TargetEntity:      sub,
		}
	case "cat", "type", "head", "tail", "grep", "findstr", "more":
		target := extractFirstFileTarget(tokens)
		return DecomposedAction{
			CanonicalAction:   "fs:file:read",
			CanonicalResource: "file://" + target,
			ActionType:        "read",
			TargetEntity:      target,
		}
	case "ls", "dir", "find":
		target := extractFirstFileTarget(tokens)
		if target == "." || target == "" {
			target = "local"
		}
		return DecomposedAction{
			CanonicalAction:   "fs:dir:read",
			CanonicalResource: "dir://" + target,
			ActionType:        "read",
			TargetEntity:      target,
		}
	case "rm", "del", "unlink", "rmdir":
		target := extractFirstFileTarget(tokens)
		return DecomposedAction{
			CanonicalAction:   "fs:file:delete",
			CanonicalResource: "file://" + target,
			ActionType:        "delete",
			TargetEntity:      target,
		}
	case "cp", "mv", "copy", "move", "mkdir", "touch":
		target := extractFirstFileTarget(tokens)
		return DecomposedAction{
			CanonicalAction:   "fs:file:write",
			CanonicalResource: "file://" + target,
			ActionType:        "write",
			TargetEntity:      target,
		}
	case "curl", "wget", "http":
		return decomposeHTTP(exec, tokens)
	default:
		return DecomposedAction{
			CanonicalAction:   "cli:" + exec + ":exec",
			CanonicalResource: "system://local",
			ActionType:        "exec",
			TargetEntity:      exec,
		}
	}
}

func decomposeGit(tokens []string) DecomposedAction {
	sub := "inspect"
	if len(tokens) > 1 {
		sub = strings.ToLower(tokens[1])
	}

	switch sub {
	case "status", "log", "diff", "show", "branch", "rev-parse", "describe", "tag":
		return DecomposedAction{
			CanonicalAction:   "git:inspect:read",
			CanonicalResource: "repo:local",
			ActionType:        "read",
			TargetEntity:      sub,
		}
	case "fetch", "pull":
		remote := "origin"
		if len(tokens) > 2 && !strings.HasPrefix(tokens[2], "-") {
			remote = tokens[2]
		}
		return DecomposedAction{
			CanonicalAction:   "git:pull:read",
			CanonicalResource: "git://" + remote,
			ActionType:        "read",
			TargetEntity:      remote,
		}
	case "clone":
		repo := "unknown"
		if len(tokens) > 2 && !strings.HasPrefix(tokens[2], "-") {
			repo = tokens[2]
		}
		return DecomposedAction{
			CanonicalAction:   "git:clone:read",
			CanonicalResource: repo,
			ActionType:        "read",
			TargetEntity:      repo,
		}
	case "commit", "add", "stash":
		return DecomposedAction{
			CanonicalAction:   "git:commit:write",
			CanonicalResource: "repo:local",
			ActionType:        "write",
			TargetEntity:      sub,
		}
	case "push":
		remote := "origin"
		branch := "main"
		nonFlags := []string{}
		for _, t := range tokens[2:] {
			if !strings.HasPrefix(t, "-") {
				nonFlags = append(nonFlags, t)
			}
		}
		if len(nonFlags) > 0 {
			remote = nonFlags[0]
		}
		if len(nonFlags) > 1 {
			branch = nonFlags[1]
		}
		return DecomposedAction{
			CanonicalAction:   "git:push:write",
			CanonicalResource: "git://" + remote + "/" + branch,
			ActionType:        "write",
			TargetEntity:      remote + "/" + branch,
		}
	case "checkout", "switch", "merge", "rebase":
		target := "HEAD"
		if len(tokens) > 2 && !strings.HasPrefix(tokens[2], "-") {
			target = tokens[2]
		}
		return DecomposedAction{
			CanonicalAction:   "git:branch:write",
			CanonicalResource: "git://local/" + target,
			ActionType:        "write",
			TargetEntity:      target,
		}
	case "reset", "clean", "rm":
		return DecomposedAction{
			CanonicalAction:   "git:clean:delete",
			CanonicalResource: "repo:local",
			ActionType:        "delete",
			TargetEntity:      sub,
		}
	default:
		return DecomposedAction{
			CanonicalAction:   "git:" + sub + ":exec",
			CanonicalResource: "repo:local",
			ActionType:        "exec",
			TargetEntity:      sub,
		}
	}
}

func decomposeKubectl(tokens []string) DecomposedAction {
	verb := "get"
	target := "all"
	ns := "default"

	for i := 1; i < len(tokens); i++ {
		t := tokens[i]
		if t == "-n" && i+1 < len(tokens) {
			ns = tokens[i+1]
			i++
		} else if strings.HasPrefix(t, "--namespace=") {
			ns = strings.TrimPrefix(t, "--namespace=")
		} else if !strings.HasPrefix(t, "-") {
			if verb == "get" && i == 1 {
				verb = strings.ToLower(t)
			} else if target == "all" {
				target = strings.ToLower(t)
			}
		}
	}

	actionType := "read"
	switch verb {
	case "get", "describe", "logs", "top":
		actionType = "read"
	case "apply", "create", "patch", "edit", "scale", "rollout":
		actionType = "write"
	case "delete":
		actionType = "delete"
	case "exec", "port-forward", "attach", "cp", "proxy":
		actionType = "admin"
	}

	return DecomposedAction{
		CanonicalAction:   "k8s:" + target + ":" + actionType,
		CanonicalResource: "k8s://" + ns + "/" + target,
		ActionType:        actionType,
		TargetEntity:      target,
	}
}

func decomposeHelm(tokens []string) DecomposedAction {
	verb := "list"
	release := "all"
	ns := "default"

	for i := 1; i < len(tokens); i++ {
		t := tokens[i]
		if t == "-n" && i+1 < len(tokens) {
			ns = tokens[i+1]
			i++
		} else if strings.HasPrefix(t, "--namespace=") {
			ns = strings.TrimPrefix(t, "--namespace=")
		} else if !strings.HasPrefix(t, "-") {
			if verb == "list" && i == 1 {
				verb = strings.ToLower(t)
			} else if release == "all" {
				release = strings.ToLower(t)
			}
		}
	}

	actionType := "read"
	switch verb {
	case "list", "status", "get", "show":
		actionType = "read"
	case "install", "upgrade":
		actionType = "write"
	case "uninstall", "delete":
		actionType = "delete"
	}

	return DecomposedAction{
		CanonicalAction:   "helm:releases:" + actionType,
		CanonicalResource: "helm://" + ns + "/" + release,
		ActionType:        actionType,
		TargetEntity:      release,
	}
}

func decomposeDatabase(engine string, tokens []string) DecomposedAction {
	db := "default"
	query := ""
	for i := 1; i < len(tokens); i++ {
		t := tokens[i]
		if (t == "-d" || t == "--dbname" || t == "-u") && i+1 < len(tokens) {
			db = tokens[i+1]
			i++
		} else if (t == "-c" || t == "-e" || t == "--eval") && i+1 < len(tokens) {
			query = strings.ToUpper(tokens[i+1])
			i++
		}
	}

	action := "db:query:read"
	actionType := "read"
	if strings.Contains(query, "DROP") || strings.Contains(query, "TRUNCATE") || strings.Contains(query, "FLUSHALL") {
		action = "db:query:drop"
		actionType = "delete"
	} else if strings.Contains(query, "DELETE") {
		action = "db:query:delete"
		actionType = "delete"
	} else if strings.Contains(query, "INSERT") || strings.Contains(query, "UPDATE") || strings.Contains(query, "ALTER") || strings.Contains(query, "CREATE") || strings.Contains(query, "SET") {
		action = "db:query:write"
		actionType = "write"
	}

	return DecomposedAction{
		CanonicalAction:   action,
		CanonicalResource: "db://" + db,
		ActionType:        actionType,
		TargetEntity:      db,
	}
}

func decomposeAWS(tokens []string) DecomposedAction {
	service := "general"
	if len(tokens) > 1 {
		service = strings.ToLower(tokens[1])
	}

	actionType := "read"
	target := "aws://" + service

	switch service {
	case "s3":
		sub := "ls"
		if len(tokens) > 2 {
			sub = strings.ToLower(tokens[2])
		}
		bucket := "all"
		for _, t := range tokens[3:] {
			if strings.HasPrefix(t, "s3://") {
				bucket = strings.TrimPrefix(t, "s3://")
				bucket = strings.Split(bucket, "/")[0]
				break
			}
		}
		if sub == "cp" || sub == "sync" || sub == "mv" {
			actionType = "write"
		} else if sub == "rm" || sub == "rb" {
			actionType = "delete"
		}
		return DecomposedAction{
			CanonicalAction:   "aws:s3:" + actionType,
			CanonicalResource: "s3://" + bucket,
			ActionType:        actionType,
			TargetEntity:      bucket,
		}
	case "secretsmanager":
		return DecomposedAction{
			CanonicalAction:   "aws:secretsmanager:read",
			CanonicalResource: "aws://secretsmanager",
			ActionType:        "read",
			TargetEntity:      "secretsmanager",
		}
	case "iam":
		return DecomposedAction{
			CanonicalAction:   "aws:iam:admin",
			CanonicalResource: "aws://iam",
			ActionType:        "admin",
			TargetEntity:      "iam",
		}
	default:
		return DecomposedAction{
			CanonicalAction:   "aws:" + service + ":" + actionType,
			CanonicalResource: target,
			ActionType:        actionType,
			TargetEntity:      service,
		}
	}
}

func decomposeAzure(tokens []string) DecomposedAction {
	sub := "cli"
	if len(tokens) > 1 {
		sub = strings.ToLower(tokens[1])
	}
	return DecomposedAction{
		CanonicalAction:   "azure:" + sub + ":exec",
		CanonicalResource: "azure://" + sub,
		ActionType:        "exec",
		TargetEntity:      sub,
	}
}

func decomposeGCP(tokens []string) DecomposedAction {
	sub := "cli"
	if len(tokens) > 1 {
		sub = strings.ToLower(tokens[1])
	}
	return DecomposedAction{
		CanonicalAction:   "gcp:" + sub + ":exec",
		CanonicalResource: "gcp://" + sub,
		ActionType:        "exec",
		TargetEntity:      sub,
	}
}

func decomposeContainer(engine string, tokens []string) DecomposedAction {
	verb := "ps"
	target := "daemon"
	if len(tokens) > 1 {
		verb = strings.ToLower(tokens[1])
	}
	for i := 2; i < len(tokens); i++ {
		t := tokens[i]
		if !strings.HasPrefix(t, "-") {
			target = t
			break
		}
	}

	actionType := "read"
	switch verb {
	case "ps", "images", "inspect", "logs":
		actionType = "read"
	case "run", "start", "build", "commit":
		actionType = "write"
	case "stop", "rm", "rmi", "kill":
		actionType = "delete"
	case "exec":
		actionType = "admin"
	}

	return DecomposedAction{
		CanonicalAction:   "container:" + verb + ":" + actionType,
		CanonicalResource: engine + "://" + target,
		ActionType:        actionType,
		TargetEntity:      target,
	}
}

func decomposePackageManager(pm string, tokens []string) DecomposedAction {
	sub := "install"
	if len(tokens) > 1 {
		sub = strings.ToLower(tokens[1])
	}
	actionType := "exec"
	if sub == "install" || sub == "add" || sub == "update" {
		actionType = "write"
	} else if sub == "test" || sub == "run" || sub == "audit" {
		actionType = "read"
	}
	return DecomposedAction{
		CanonicalAction:   "dev:package:" + sub,
		CanonicalResource: pm + "://packages",
		ActionType:        actionType,
		TargetEntity:      pm,
	}
}

func decomposeHTTP(client string, tokens []string) DecomposedAction {
	method := "GET"
	target := "http://localhost"
	for i := 1; i < len(tokens); i++ {
		t := tokens[i]
		if (t == "-X" || t == "--request") && i+1 < len(tokens) {
			method = strings.ToUpper(tokens[i+1])
			i++
		} else if strings.HasPrefix(t, "http://") || strings.HasPrefix(t, "https://") {
			target = t
		}
	}

	actionType := "read"
	if method == "POST" || method == "PUT" || method == "PATCH" {
		actionType = "write"
	} else if method == "DELETE" {
		actionType = "delete"
	}

	return DecomposedAction{
		CanonicalAction:   "http:" + strings.ToLower(method),
		CanonicalResource: target,
		ActionType:        actionType,
		TargetEntity:      target,
	}
}

func extractFirstFileTarget(tokens []string) string {
	for i := 1; i < len(tokens); i++ {
		t := tokens[i]
		if !strings.HasPrefix(t, "-") {
			return t
		}
	}
	return "local"
}

func tokenize(cmd string) []string {
	parts := strings.Fields(cmd)
	clean := []string{}
	for _, p := range parts {
		p = strings.Trim(p, "\"'")
		if p != "" {
			clean = append(clean, p)
		}
	}
	return clean
}

