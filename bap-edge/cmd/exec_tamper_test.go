package cmd

import (
	"testing"
)

func TestIsTamperingAttempt_HeredocsAndSafeCommands(t *testing.T) {
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

	isTamper, reason := isTamperingAttempt(userCmd)
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
		if isT, r := isTamperingAttempt(cmd); isT {
			t.Errorf("expected safe command %q not to be flagged as tampering, got: %s", cmd, r)
		}
	}
}

func TestIsTamperingAttempt_RealTampering(t *testing.T) {
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
		if isT, _ := isTamperingAttempt(cmd); !isT {
			t.Errorf("expected tampering command %q to be flagged, but was allowed", cmd)
		}
	}
}
