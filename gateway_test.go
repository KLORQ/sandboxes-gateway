package gateway

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/KLORQ/sandboxes-gateway/policy"
)

func TestRenderConfig(t *testing.T) {
	cfg := renderConfig(policy.Policy{
		Revision:  2,
		SandboxID: "dev",
		AuditPath: "/tmp/dev.audit.jsonl",
		Allow: []policy.Rule{
			{Protocol: "tcp", CIDR: "10.0.0.0/8", Port: 443},
		},
		Deny: []policy.Rule{
			{Protocol: "udp", CIDR: "10.1.0.0/16", Port: 53},
		},
		Ports: []policy.Port{{Host: 8080, Guest: 3000}},
	}, "1.1.1.1:53")
	for _, want := range []string{
		"egressPolicy:",
		`revision: "2"`,
		`sandboxID: "dev"`,
		`auditLog: "/tmp/dev.audit.jsonl"`,
		"    allow:",
		`cidr: "10.0.0.0/8"`,
		"    deny:",
		`protocol: "udp"`,
		`"127.0.0.1:8080": "192.168.127.3:3000"`,
		`dnsUpstream: "1.1.1.1:53"`,
	} {
		if !strings.Contains(cfg, want) {
			t.Fatalf("missing %q in config:\n%s", want, cfg)
		}
	}
}

func TestStartDoesNotRemoveExistingSocketPath(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "dev.sock")
	if err := os.WriteFile(path, []byte("owned elsewhere"), 0o600); err != nil {
		t.Fatal(err)
	}
	m, err := New(Config{GVProxy: "/bin/true", RunDir: dir})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.Start(context.Background(), policy.Policy{SandboxID: "dev"}); err == nil {
		t.Fatal("start accepted an existing socket path")
	}
	data, err := os.ReadFile(path)
	if err != nil || string(data) != "owned elsewhere" {
		t.Fatalf("existing file changed: %q, %v", data, err)
	}
}

func TestGatewayFilesRejectLinksWithoutChangingTargets(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	if err := os.WriteFile(target, []byte("unchanged"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		link func(string, string) error
	}{
		{"symlink", os.Symlink},
		{"hardlink", os.Link},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(dir, tc.name)
			if err := tc.link(target, path); err != nil {
				t.Fatal(err)
			}
			if err := writeConfig(path, policy.Policy{SandboxID: "dev"}, ""); err == nil {
				t.Fatal("linked config accepted")
			}
			data, err := os.ReadFile(target)
			if err != nil || string(data) != "unchanged" {
				t.Fatalf("target changed: %q, %v", data, err)
			}
		})
	}
	path := filepath.Join(dir, "valid.yaml")
	if err := writeConfig(path, policy.Policy{SandboxID: "dev"}, ""); err != nil {
		t.Fatalf("private regular config rejected: %v", err)
	}
}

func TestMACDeterministic(t *testing.T) {
	first := MAC("dev")
	second := MAC("dev")
	if first != second {
		t.Fatal("MAC must be deterministic")
	}
	if MAC("dev") == MAC("prod") {
		t.Fatal("different sandboxes need different MACs")
	}
}

func TestValidatePolicyFailsClosedForUnsupportedRules(t *testing.T) {
	tests := []struct {
		name string
		rule policy.Rule
	}{
		{name: "domain", rule: policy.Rule{Protocol: "tcp", Domain: "registry.example", Port: 443}},
		{name: "missing cidr", rule: policy.Rule{Protocol: "tcp", Port: 443}},
		{name: "invalid cidr", rule: policy.Rule{Protocol: "tcp", CIDR: "registry.example", Port: 443}},
		{name: "invalid protocol", rule: policy.Rule{Protocol: "icmp", CIDR: "192.0.2.1/32"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := validatePolicy(policy.Policy{Allow: []policy.Rule{tt.rule}}); err == nil {
				t.Fatal("unsupported policy must be rejected")
			}
		})
	}
}

func TestNewValidation(t *testing.T) {
	if _, err := New(Config{}); err == nil {
		t.Fatal("expected validation error")
	}
	if _, err := New(Config{GVProxy: "/bin/true", RunDir: "/tmp/x"}); err != nil {
		t.Fatal(err)
	}
}

func TestStopUnknownIsSafe(t *testing.T) {
	m, err := New(Config{GVProxy: "/bin/true", RunDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	if err := m.Stop(context.Background(), "missing"); err != nil {
		t.Fatal(err)
	}
}

func TestCloseRejectsNewStarts(t *testing.T) {
	m, err := New(Config{GVProxy: "/bin/true", RunDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	if err := m.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Start(context.Background(), policy.Policy{SandboxID: "dev"}); err == nil {
		t.Fatal("closed manager accepted a new gateway")
	}
}

func TestCloseReportsStartupInProgress(t *testing.T) {
	m, err := New(Config{GVProxy: "/bin/true", RunDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	if err := m.reserveStart("dev"); err != nil {
		t.Fatal(err)
	}
	if err := m.Close(context.Background()); err == nil {
		t.Fatal("close reported success during gateway startup")
	}
}

func TestReloadWaitsForStartupBeforeFailingClosed(t *testing.T) {
	m, err := New(Config{GVProxy: "/bin/true", RunDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	if err := m.reserveStart("dev"); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- m.Reload(context.Background(), policy.Policy{SandboxID: "dev"}) }()
	select {
	case <-done:
		t.Fatal("reload returned before startup completed")
	case <-time.After(50 * time.Millisecond):
	}
	m.mu.Lock()
	finished := m.starting["dev"]
	delete(m.starting, "dev")
	close(finished)
	m.mu.Unlock()
	if err := <-done; err == nil {
		t.Fatal("reload reported success without a running gateway")
	}
}

func TestStartRejectsUnsafeSandboxID(t *testing.T) {
	m, err := New(Config{GVProxy: "/bin/true", RunDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"", ".", "..", "../outside", "a/b", `a\b`, "a\x00b", strings.Repeat("a", 64)} {
		t.Run(id, func(t *testing.T) {
			if _, err := m.Start(context.Background(), policy.Policy{SandboxID: id}); err == nil {
				t.Fatal("unsafe sandbox ID accepted")
			}
		})
	}
	for _, id := range []string{"dev", "DEV_1", "a.b-c"} {
		if !validSandboxID(id) {
			t.Fatalf("valid sandbox ID %q rejected", id)
		}
	}
}
