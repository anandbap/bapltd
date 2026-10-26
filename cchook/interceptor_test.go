package main

import (
	"encoding/base64"
	"strings"
	"testing"
)

func TestUnwrapBrokerCommandRequiresExactSessionBoundWrapper(t *testing.T) {
	payload := base64.StdEncoding.EncodeToString([]byte("echo governed"))
	command := `bapedge exec --source claude-code --session-id sess-1 --cmd-b64 ` + payload
	decoded, wrapped, err := unwrapBrokerCommand(command, "sess-1")
	if err != nil || !wrapped || decoded != "echo governed" {
		t.Fatalf("decoded=%q wrapped=%v err=%v", decoded, wrapped, err)
	}
}

func TestUnwrapBrokerCommandRejectsAgentLookalikes(t *testing.T) {
	payload := base64.StdEncoding.EncodeToString([]byte("cat .env"))
	for _, command := range []string{
		`bapedge exec --source claude-code --session-id another-session --cmd-b64 ` + payload,
		`bapedge exec --source claude-code --session-id sess-1 --cmd-b64 ` + payload + ` && echo bypass`,
		`bapedge --cmd-b64 ` + payload,
	} {
		if _, wrapped, err := unwrapBrokerCommand(command, "sess-1"); !wrapped || err == nil {
			t.Fatalf("expected wrapped lookalike to be rejected: %q (wrapped=%v err=%v)", command, wrapped, err)
		}
	}
}

func TestUnwrapBrokerCommandDoesNotTrustArbitraryCmdB64Argument(t *testing.T) {
	command := `python tool.py --cmd-b64 attacker-controlled`
	decoded, wrapped, err := unwrapBrokerCommand(command, "sess-1")
	if err != nil || wrapped || decoded != command {
		t.Fatalf("decoded=%q wrapped=%v err=%v", decoded, wrapped, err)
	}
}

func TestSafeSubagentAndInspectionTools(t *testing.T) {
	safeTools := []string{
		"search_code_subagent",
		"search_code",
		"find_by_name",
		"grep_search",
		"file_search",
		"list_dir",
		"Glob",
		"Grep",
		"LS",
		"Agent",
		"Task",
		"subagent",
		"bap_status",
		"bap_explain_policy",
	}

	for _, tool := range safeTools {
		if !isSafeSubagentOrInspectionTool(strings.ToLower(tool)) {
			t.Errorf("expected tool %q to be classified as safe subagent or inspection tool", tool)
		}
	}
}

func TestShellToolsClassification(t *testing.T) {
	shellTools := []string{"Bash", "sh", "terminal", "command", "execute", "run_command", "shell", ""}
	for _, tool := range shellTools {
		if !isShellTool(strings.ToLower(tool)) {
			t.Errorf("expected tool %q to be classified as shell tool", tool)
		}
	}

	nonShellTools := []string{"search_code_subagent", "Glob", "Grep", "Read", "View", "Agent"}
	for _, tool := range nonShellTools {
		if isShellTool(strings.ToLower(tool)) {
			t.Errorf("expected tool %q NOT to be classified as shell tool", tool)
		}
	}
}

func TestIsTamperingCommand_HeredocsAndSafeCommands(t *testing.T) {
	userCmd := `cd /c/Users/User/pyprj/bapltd && cat > "$TEMP/addstop.py" <<'EOF'
import re,sys
for f in sys.argv[1:]:
    s=open(f,encoding='utf-8').read(); o=s
    if f.endswith('.py') and 'bap_install' in f:
        s=s.replace('''    claude_settings["hooks"]["SessionEnd"] = [''','''    claude_settings["hooks"]["Stop"] = [
        {"hooks": [interceptor_hook]}
    ]
    claude_settings["hooks"]["SessionEnd"] = [''',1)
    elif f.endswith('cli_bap.ps1'):
        s=re.sub(r"(\n(\s*)SessionEnd(\s*)= @\( \[ordered\]@\{ hooks = @\( \[ordered\]@\{ type = 'command'; command = 'interceptor.exe'; args = @\(\) \} \) \} \))",
                 lambda m:"\n"+m.group(2)+"Stop"+m.group(3)[:-1]+"    = @( [ordered]@{ hooks = @( [ordered]@{ type = 'command'; command = 'interceptor.exe'; args = @() } ) } )"+m.group(1),s,1)
    open(f,'w',encoding='utf-8',newline='').write(s)
EOF
python "$TEMP/addstop.py" scripts/bap_install.py
git diff --stat | tail -15`

	isTamper, reason := isTamperingCommand(userCmd)
	if isTamper {
		t.Fatalf("expected user command with heredoc containing interceptor.exe not to be flagged as tampering, got reason: %s", reason)
	}

	safeCommands := []string{
		`echo "hello" > notes.txt`,
		`echo "interceptor.exe is here" > notes.txt`,
		`python script.py interceptor.exe`,
		`git diff policy.cedar`,
		`cat policy.cedar`,
		`grep "interceptor.exe" package.json`,
		`sed -i 's/interceptor.exe/myhook.exe/g' scripts/install.py`,
		`cp interceptor.exe /tmp/backup.exe`,
	}
	for _, cmd := range safeCommands {
		if isT, r := isTamperingCommand(cmd); isT {
			t.Errorf("expected safe command %q not to be flagged as tampering, got: %s", cmd, r)
		}
	}
}

func TestIsTamperingCommand_RealTampering(t *testing.T) {
	tamperCommands := []string{
		`echo "malicious" > interceptor.exe`,
		`cat evil.exe > .claude/hooks/interceptor.exe`,
		`echo "permit" >> policy.cedar`,
		`rm interceptor.exe`,
		`rm -rf .claude/hooks`,
		`del /f bapedge.exe`,
		`mv interceptor.exe interceptor.old`,
		`sed -i 's/deny/permit/g' policy.cedar`,
		"cat <<'EOF' > interceptor.exe\nevil binary content\nEOF",
	}
	for _, cmd := range tamperCommands {
		if isT, _ := isTamperingCommand(cmd); !isT {
			t.Errorf("expected tampering command %q to be flagged, but was allowed", cmd)
		}
	}
}
