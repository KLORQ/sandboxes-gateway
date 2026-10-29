package gateway

import (
	"context"
	"strings"
	"testing"

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
