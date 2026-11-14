package session

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"time"

	"bap-controlplane/internal/audit"
)

// CanonicalPromptEvents projects context supplied through any transport into
// logical prompts, retaining original actions and immutable ledger records.
func CanonicalPromptEvents(events []audit.Event) []audit.Event {
	var prompts, other []audit.Event
	aliases := map[string]string{}
	ambiguous := map[string]bool{}
	for _, ev := range events {
		if ev.UserPrompt == "" && (ev.Executable != "user_prompt" || ev.PromptHash == "") {
			other = append(other, ev)
			continue
		}
		if ev.Executable != "user_prompt" {
			other = append(other, ev)
			ev.EventID += "-prompt-context"
		}
		ev.Executable, ev.FullCommand = "user_prompt", "USER_PROMPT_SUBMITTED"
		ev.PromptCaptured = ev.UserPrompt != ""
		if ev.PromptHash == "" {
			sum := sha256.Sum256([]byte(CleanUserPrompt(ev.UserPrompt)))
			ev.PromptHash = hex.EncodeToString(sum[:])
		}
		if ev.PrimaryIntent == "" {
			ev.PrimaryIntent = ClassifyIntent(ev.UserPrompt).Primary
		}
		key := ev.SessionID + "\x00" + ev.PromptHash
		if ev.TurnID != "" {
			if old := aliases[key]; old != "" && old != ev.TurnID {
				ambiguous[key] = true
			}
			aliases[key] = ev.TurnID
		}
		prompts = append(prompts, ev)
	}
	for i := range prompts {
		key := prompts[i].SessionID + "\x00" + prompts[i].PromptHash
		if prompts[i].TurnID == "" && !ambiguous[key] {
			prompts[i].TurnID = aliases[key]
		}
	}
	combined := append(other, Arbitrate(prompts)...)
	sort.SliceStable(combined, func(i, j int) bool {
		a, _ := time.Parse(time.RFC3339Nano, combined[i].Timestamp)
		b, _ := time.Parse(time.RFC3339Nano, combined[j].Timestamp)
		return a.Before(b)
	})
	return combined
}
