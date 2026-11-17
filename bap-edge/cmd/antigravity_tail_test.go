package cmd

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"bap-edge/internal/state"
)

func userLine(text string) string {
	return `{"type":"USER_INPUT","content":"<USER_REQUEST>` + text + `</USER_REQUEST>"}` + "\n"
}

func appendFile(t *testing.T, p, s string) {
	t.Helper()
	f, err := os.OpenFile(p, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := f.WriteString(s); err != nil {
		t.Fatal(err)
	}
}

func TestParsePromptLine_IgnoresNonUserTurns(t *testing.T) {
	if got := parsePromptLine(`{"type":"ASSISTANT","content":"I saw <USER_REQUEST>old thing</USER_REQUEST>"}`); got != "" {
		t.Fatalf("assistant line quoting a request must not be a prompt, got %q", got)
	}
	if got := parsePromptLine(`{"type":"TOOL_OUTPUT","content":"x"}`); got != "" {
		t.Fatalf("tool output must not be a prompt, got %q", got)
	}
	if got := parsePromptLine(userLine("fix it")); got != "fix it" {
		t.Fatalf("user turn not parsed, got %q", got)
	}
}

func TestTailReadsOnlyAppendedPromptsAndSkipsHistory(t *testing.T) {
	t.Setenv("BAP_STATE_DIR", t.TempDir())
	state.ResetForTesting()

	root := t.TempDir()
	conv := filepath.Join(root, "conv-old")
	if err := os.MkdirAll(conv, 0700); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(conv, "transcript.jsonl")
	appendFile(t, p, userLine("ancient prompt one")+userLine("ancient prompt two"))
	old := time.Now().Add(-time.Hour)
	if err := os.Chtimes(p, old, old); err != nil {
		t.Fatal(err)
	}

	offsets := map[string]int64{}
	var reported []string
	baselineTranscripts([]string{root}, offsets, time.Now(), func(s string) { reported = append(reported, s) })
	if len(reported) != 0 {
		t.Fatalf("history must not be replayed at startup, got %v", reported)
	}

	prompts, _, next, ok := readNewTranscriptPrompts(p, offsets)
	if !ok || len(prompts) != 0 {
		t.Fatalf("expected nothing new after baseline, got %v ok=%v", prompts, ok)
	}
	offsets[p] = next

	// A repeated prompt text is still a new turn; a half-written line waits for its newline.
	appendFile(t, p, userLine("continue")+userLine("continue"))
	appendFile(t, p, `{"type":"USER_INPUT","content":"<USER_REQUEST>partial`)
	prompts, spans, next, _ := readNewTranscriptPrompts(p, offsets)
	if len(prompts) != 2 || prompts[0] != "continue" || prompts[1] != "continue" {
		t.Fatalf("expected two distinct 'continue' turns, got %v", prompts)
	}
	if promptClaimKey(p, spans[0]) == promptClaimKey(p, spans[1]) {
		t.Fatal("identical prompts at different positions must have different claim keys")
	}
	offsets[p] = next
	appendFile(t, p, `</USER_REQUEST>"}`+"\n")
	prompts, _, _, _ = readNewTranscriptPrompts(p, offsets)
	if len(prompts) != 1 || prompts[0] != "partial" {
		t.Fatalf("completed line should be picked up once, got %v", prompts)
	}
}

func TestBaselineReportsOnlyLastPromptOfJustTouchedConversation(t *testing.T) {
	t.Setenv("BAP_STATE_DIR", t.TempDir())
	state.ResetForTesting()

	root := t.TempDir()
	conv := filepath.Join(root, "conv-live")
	if err := os.MkdirAll(conv, 0700); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(conv, "transcript.jsonl")
	appendFile(t, p, userLine("earlier turn")+userLine("the prompt that started this session"))

	offsets := map[string]int64{}
	var reported []string
	baselineTranscripts([]string{root}, offsets, time.Now(), func(s string) { reported = append(reported, s) })
	if len(reported) != 1 || reported[0] != "the prompt that started this session" {
		t.Fatalf("expected only the triggering prompt, got %v", reported)
	}
}
