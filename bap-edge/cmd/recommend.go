package cmd

import (
	"bufio"
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"bap-edge/internal/audit"
	"bap-edge/internal/authz"
	"bap-edge/internal/httptransport"
)

// RunRecommend lets a developer inspect a call BAP blocked and recommend its effect class to the
// control plane as benign. Only an enrolled machine (valid workstation credential) can submit; an
// administrator reviews it on the control plane, and an approval comes back through the signed
// policy sync. Nothing here changes local enforcement.
//
//	bap recommend                 list recent blocked calls, grouped by effect, then inspect one
//	bap recommend --pick 2        inspect and recommend entry 2 non-interactively
//	bap recommend --status        show what you have recommended and what the administrator decided
func RunRecommend(args []string) error {
	fs := flag.NewFlagSet("recommend", flag.ContinueOnError)
	pick := fs.Int("pick", 0, "number of the blocked call to inspect and recommend (see the list)")
	justify := fs.String("justify", "", "why this is benign (shown to the administrator)")
	yes := fs.Bool("yes", false, "submit without the confirmation prompt")
	status := fs.Bool("status", false, "show the status of your recommendations")
	limit := fs.Int("limit", 15, "how many blocked effects to list")
	logPath := fs.String("audit-log", "", "audit log to read (defaults to this machine's BAP audit log)")
	if err := fs.Parse(args); err != nil {
		return err
	}

	creds, err := loadEnrolledCredentials()
	if err != nil {
		return err
	}
	if *status {
		return printRecommendationStatus(creds)
	}

	path := *logPath
	if path == "" {
		path = audit.DefaultLogPath()
	}
	groups, err := collectBlockedEffects(path, 4<<20)
	if err != nil {
		return fmt.Errorf("could not read the audit log %s: %w", path, err)
	}
	if len(groups) == 0 {
		fmt.Println("No blocked calls found in the audit log. Nothing to recommend.")
		return nil
	}
	if len(groups) > *limit {
		groups = groups[:*limit]
	}
	printBlockedEffects(groups)

	idx := *pick
	if idx == 0 {
		if !stdinIsInteractive() {
			fmt.Println("\nRe-run with --pick N to inspect and recommend one of these.")
			return nil
		}
		fmt.Print("\nInspect which entry? (number, or q to quit): ")
		line, _ := bufio.NewReader(os.Stdin).ReadString('\n')
		line = strings.TrimSpace(line)
		if line == "" || strings.EqualFold(line, "q") {
			return nil
		}
		idx, err = strconv.Atoi(line)
		if err != nil {
			return fmt.Errorf("not a number: %q", line)
		}
	}
	if idx < 1 || idx > len(groups) {
		return fmt.Errorf("pick a number between 1 and %d", len(groups))
	}
	g := groups[idx-1]
	printBlockedDetail(g)

	if !authz.ApprovableEffect(g.Action) {
		fmt.Printf("\n%q can never be approved from a recommendation (network, deletion, publishing, databases, arbitrary interpreters and credentials always need a task grant).\n", g.Action)
		fmt.Println("Use `bapedge zsp authorize ...` for this call instead.")
		return nil
	}
	if g.Escaped {
		fmt.Println("\nThis call touched a path outside the workspace. Recommendations only cover work inside the workspace.")
		return nil
	}

	why := strings.TrimSpace(*justify)
	if why == "" && stdinIsInteractive() {
		fmt.Print("\nWhy is this benign? (one line, shown to the administrator): ")
		why, _ = bufio.NewReader(os.Stdin).ReadString('\n')
		why = strings.TrimSpace(why)
	}
	if !*yes {
		if !stdinIsInteractive() {
			return fmt.Errorf("refusing to submit without --yes in a non-interactive session")
		}
		fmt.Printf("\nSend a recommendation for %q to %s ? [y/N]: ", g.Action, creds.ServerURL)
		ans, _ := bufio.NewReader(os.Stdin).ReadString('\n')
		if !strings.HasPrefix(strings.ToLower(strings.TrimSpace(ans)), "y") {
			fmt.Println("Cancelled.")
			return nil
		}
	}
	return submitRecommendation(creds, g, why)
}

type blockedEffect struct {
	Action      string
	Resource    string
	Executable  string
	CommandHint string
	Reason      string
	Count       int
	First, Last time.Time
	Sessions    map[string]bool
	Escaped     bool
}

func collectBlockedEffects(path string, maxBytes int64) ([]*blockedEffect, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	if st, err := f.Stat(); err == nil && st.Size() > maxBytes {
		_, _ = f.Seek(st.Size()-maxBytes, io.SeekStart)
	}
	byAction := map[string]*blockedEffect{}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 8<<20)
	for sc.Scan() {
		var e audit.AuditEntry
		if json.Unmarshal(sc.Bytes(), &e) != nil || e.CanonicalAction == "" {
			continue
		}
		dec := strings.ToLower(e.Decision)
		if !strings.Contains(dec, "deny") && !strings.Contains(dec, "block") {
			continue
		}
		// Only grant-requirement denials are friction candidates; Cedar invariant denials (secrets,
		// exfiltration, tamper protection) are deliberate and are not recommendable.
		if !strings.Contains(e.Reason, "ZeroStandingPrivilege") {
			continue
		}
		action := strings.ToLower(e.CanonicalAction)
		g := byAction[action]
		if g == nil {
			g = &blockedEffect{Action: action, Sessions: map[string]bool{}, First: e.Timestamp}
			byAction[action] = g
		}
		g.Count++
		g.Last = e.Timestamp
		g.Resource, g.Executable, g.Reason = e.CanonicalResource, e.Executable, e.Reason
		g.CommandHint = redactCommand(e.FullCommand)
		g.Sessions[e.SessionID] = true
		if strings.HasPrefix(e.CanonicalResource, "outside-workspace://") {
			g.Escaped = true
		}
	}
	out := make([]*blockedEffect, 0, len(byAction))
	for _, g := range byAction {
		out = append(out, g)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Last.After(out[j].Last) })
	return out, sc.Err()
}

var secretLike = regexp.MustCompile(`(?i)((?:token|secret|passw(?:or)?d|api[_-]?key|authorization|bearer)\s*[=: ]\s*)\S+`)
var longBlob = regexp.MustCompile(`[A-Za-z0-9+/=_\-]{40,}`)

// redactCommand keeps only what an administrator needs to judge the call: no credentials, no long
// opaque blobs, and a short length.
func redactCommand(cmd string) string {
	cmd = strings.Join(strings.Fields(cmd), " ")
	cmd = secretLike.ReplaceAllString(cmd, "${1}[redacted]")
	cmd = longBlob.ReplaceAllString(cmd, "[redacted]")
	if len(cmd) > 200 {
		cmd = cmd[:200] + "..."
	}
	return cmd
}

func printBlockedEffects(groups []*blockedEffect) {
	fmt.Printf("\nRecent blocked calls (grouped by effect, newest first):\n\n")
	fmt.Printf("  %-3s %-26s %6s  %-9s %s\n", "#", "EFFECT", "COUNT", "MAY ASK", "EXAMPLE")
	for i, g := range groups {
		may := "yes"
		if !authz.ApprovableEffect(g.Action) || g.Escaped {
			may = "no"
		}
		ex := g.CommandHint
		if len(ex) > 48 {
			ex = ex[:48] + "..."
		}
		fmt.Printf("  %-3d %-26s %6d  %-9s %s\n", i+1, g.Action, g.Count, may, ex)
	}
}

func printBlockedDetail(g *blockedEffect) {
	fmt.Printf("\n--- Inspecting: %s ---\n", g.Action)
	fmt.Printf("  Effect:      %s\n", g.Action)
	fmt.Printf("  Resource:    %s\n", g.Resource)
	fmt.Printf("  Executable:  %s\n", g.Executable)
	fmt.Printf("  Example:     %s\n", g.CommandHint)
	fmt.Printf("  Seen:        %d time(s) in %d session(s), %s to %s\n", g.Count, len(g.Sessions),
		g.First.Local().Format("Jan 2 15:04"), g.Last.Local().Format("Jan 2 15:04"))
	reason := g.Reason
	if len(reason) > 220 {
		reason = reason[:220] + "..."
	}
	fmt.Printf("  Blocked as:  %s\n", reason)
	fmt.Println("  Scope:       approval would cover this effect inside your workspace only, on this machine only.")
}

type recommendationReply struct {
	ID           string `json:"id"`
	Status       string `json:"status"`
	Action       string `json:"action"`
	Occurrences  int    `json:"occurrences"`
	DecisionNote string `json:"decision_note"`
	DecidedAt    string `json:"decided_at"`
	Error        string `json:"error"`
}

func loadEnrolledCredentials() (*StoredCredentials, error) {
	data, err := os.ReadFile(DefaultCredentialsPath())
	if err != nil {
		return nil, fmt.Errorf("this machine is not registered with a control plane; run `bap login` (or `bap register <code>`) first")
	}
	var c StoredCredentials
	if json.Unmarshal(data, &c) != nil || c.SessionToken == "" || c.ServerURL == "" {
		return nil, fmt.Errorf("stored credentials are unusable; run `bap login` again")
	}
	return &c, nil
}

func submitRecommendation(c *StoredCredentials, g *blockedEffect, why string) error {
	body, _ := json.Marshal(map[string]string{
		"action": g.Action, "executable": g.Executable, "command_hint": g.CommandHint,
		"deny_reason": g.Reason, "justification": why,
	})
	status, raw, err := controlPlaneCall(c, "POST", "/api/v1/policy/recommendations", body)
	if err != nil {
		return err
	}
	var r recommendationReply
	_ = json.Unmarshal(raw, &r)
	switch status {
	case 202:
		fmt.Printf("\nRecommendation %s sent (%s, seen %d time(s)). An administrator must review it.\n", r.ID, r.Action, r.Occurrences)
		fmt.Println("Check the outcome with: bap recommend --status")
		return nil
	case 401:
		return fmt.Errorf("the control plane rejected this machine's credential; run `bap login` to re-enroll")
	case 409:
		return fmt.Errorf("this machine has not synced policy yet; run `bapedge sync` and try again")
	default:
		msg := r.Error
		if msg == "" {
			msg = strings.TrimSpace(string(raw))
		}
		return fmt.Errorf("control plane refused the recommendation (%d): %s", status, msg)
	}
}

func printRecommendationStatus(c *StoredCredentials) error {
	status, raw, err := controlPlaneCall(c, "GET", "/api/v1/policy/recommendations", nil)
	if err != nil {
		return err
	}
	if status == 401 {
		return fmt.Errorf("the control plane rejected this machine's credential; run `bap login` to re-enroll")
	}
	if status != 200 {
		return fmt.Errorf("control plane returned %d: %s", status, strings.TrimSpace(string(raw)))
	}
	var resp struct {
		Recommendations []recommendationReply `json:"recommendations"`
	}
	if err := json.Unmarshal(raw, &resp); err != nil {
		return err
	}
	if len(resp.Recommendations) == 0 {
		fmt.Println("You have not recommended anything yet.")
		return nil
	}
	fmt.Printf("%-16s %-26s %-9s %s\n", "ID", "EFFECT", "STATUS", "ADMIN NOTE")
	for _, r := range resp.Recommendations {
		fmt.Printf("%-16s %-26s %-9s %s\n", r.ID, r.Action, r.Status, r.DecisionNote)
	}
	return nil
}

func controlPlaneCall(c *StoredCredentials, method, path string, body []byte) (int, []byte, error) {
	req, err := http.NewRequest(method, strings.TrimRight(c.ServerURL, "/")+path, bytes.NewReader(body))
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.SessionToken)
	resp, err := httptransport.New(15 * time.Second).Do(req)
	if err != nil {
		return 0, nil, fmt.Errorf("control plane unreachable at %s: %w", c.ServerURL, err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return resp.StatusCode, raw, nil
}

func stdinIsInteractive() bool {
	st, err := os.Stdin.Stat()
	return err == nil && st.Mode()&os.ModeCharDevice != 0
}
