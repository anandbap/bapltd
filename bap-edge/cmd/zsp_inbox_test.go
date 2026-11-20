package cmd

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"bap-edge/internal/authz"
)

func TestZSPInboxAgentCommandAliasesAreBlocked(t *testing.T) {
	for _, command := range []string{"bap zsp", "bapedge zsp inbox --watch", "'C:\\Program Files\\BAP\\bapedge.exe' zsp inbox", "ltd-agent zsp approve req-a", "bapmcp zsp approve req-a", "python -m bap.cli zsp inbox", "bap zsp autoapprove enable", "bap dev on"} {
		if _, blocked := humanOnlyBAPCommand(command); !blocked {
			t.Errorf("agent approval entry point not blocked: %s", command)
		}
	}
	for _, command := range []string{"bap zsp approvals", "bap zsp authorize --actions fs:file:write", "bap zsp status", "bap zsp autoapprove status"} {
		if _, blocked := humanOnlyBAPCommand(command); blocked {
			t.Errorf("agent request/inspection was blocked: %s", command)
		}
	}
}

func TestZSPInboxRejectsBrokerAndNonTerminal(t *testing.T) {
	e2eEnv(t) // Pipe stdin; never ask a real human or mint a live approval.
	for _, broker := range []string{"1", ""} {
		t.Setenv("BAP_IN_BROKER", broker)
		if err := runZSPInbox(nil); !errors.Is(err, authz.ErrHighRiskApprovalRequired) {
			t.Fatalf("broker=%q: %v", broker, err)
		}
	}
}

func TestZSPInboxReviewsIndividuallyAndEscapesRequestText(t *testing.T) {
	var output bytes.Buffer
	requests := []authz.PendingApproval{
		{ID: "third", Status: "pending", ExpiresAt: time.Now().Add(time.Hour)},
		{ID: "second", Status: "pending", ExpiresAt: time.Now().Add(time.Hour)},
		{ID: "first", Status: "pending", ExpiresAt: time.Now().Add(time.Hour), Goal: "\x1b[2Jfake approval\n", Actions: []string{"dev:python:exec"}},
	}
	var decisions []string
	err := reviewZSPInbox(context.Background(), false, bufio.NewReader(strings.NewReader("a\nd\ns\n")), &output,
		func() ([]authz.PendingApproval, error) { return requests, nil },
		func(approve bool, p authz.PendingApproval, _ *bufio.Reader) error {
			decisions = append(decisions, p.ID)
			if approve != (p.ID == "first") {
				t.Error("decision mapped to wrong request")
			}
			return nil
		})
	if err != nil || strings.Join(decisions, ",") != "first,second" {
		t.Fatal(decisions, err)
	}
	if strings.Contains(output.String(), "\x1b") || !strings.Contains(output.String(), `\x1b`) {
		t.Fatal("request text can control the terminal")
	}
}

func TestZSPInboxEOFQuitAndInvalidChoicesDoNotDecide(t *testing.T) {
	for _, input := range []string{"a", "q\n", "approve-all\n", "\n"} {
		t.Run(input, func(t *testing.T) {
			called := false
			p := authz.PendingApproval{ID: "pending", Status: "pending", ExpiresAt: time.Now().Add(time.Hour)}
			err := reviewZSPInbox(context.Background(), false, bufio.NewReader(strings.NewReader(input)), &bytes.Buffer{},
				func() ([]authz.PendingApproval, error) { return []authz.PendingApproval{p}, nil },
				func(bool, authz.PendingApproval, *bufio.Reader) error { called = true; return nil })
			if err != nil || called {
				t.Fatal("unexpected decision", called, err)
			}
		})
	}
}

func TestZSPInboxChallengeFailureStopsReview(t *testing.T) {
	p := authz.PendingApproval{ID: "pending", Status: "pending", ExpiresAt: time.Now().Add(time.Hour)}
	err := reviewZSPInbox(context.Background(), true, bufio.NewReader(strings.NewReader("a\n")), &bytes.Buffer{},
		func() ([]authz.PendingApproval, error) { return []authz.PendingApproval{p}, nil },
		func(bool, authz.PendingApproval, *bufio.Reader) error { return authz.ErrHighRiskApprovalRequired })
	if !errors.Is(err, authz.ErrHighRiskApprovalRequired) {
		t.Fatal(err)
	}
}

func TestZSPInboxWatchFindsNewRequestsWithoutDecidingAutomatically(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	p := authz.PendingApproval{ID: "new-request", Status: "pending", ExpiresAt: time.Now().Add(time.Hour)}
	calls := 0
	err := reviewZSPInbox(ctx, true, bufio.NewReader(strings.NewReader("q\n")), &bytes.Buffer{},
		func() ([]authz.PendingApproval, error) {
			calls++
			if calls == 1 {
				return nil, nil
			}
			return []authz.PendingApproval{p}, nil
		},
		func(bool, authz.PendingApproval, *bufio.Reader) error { t.Fatal("auto decision"); return nil })
	if err != nil || calls != 2 {
		t.Fatal(calls, err)
	}
}
