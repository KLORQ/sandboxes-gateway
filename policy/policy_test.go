package policy

import "testing"

func TestDefaultDeny(t *testing.T) {
	for _, action := range []Action{"", Allow, Deny} {
		got := Evaluate(Rule{ID: "fixture", Action: action})
		if got.Allow {
			t.Fatalf("unconfigured engine allowed action %q", action)
		}
	}
}

func TestCheckDenyWinsAndDomainRulesDoNotAuthorizeIP(t *testing.T) {
	allow := []Rule{
		{ID: "domain", Protocol: "tcp", Domain: "*.example.com", Port: 443},
		{ID: "cidr", Protocol: "tcp", CIDR: "10.0.0.0/8", Port: 443},
	}
	deny := []Rule{{ID: "deny", Protocol: "tcp", Domain: "secret.example.com", Port: 443}}
	if got := Check(allow, deny, Request{Protocol: "tcp", Domain: "api.example.com", Port: 443}); !got.Allow || got.RuleID != "domain" {
		t.Fatalf("allow=%+v", got)
	}
	if got := Check(allow, deny, Request{Protocol: "tcp", Domain: "secret.example.com", Port: 443}); got.Allow || got.RuleID != "deny" {
		t.Fatalf("deny=%+v", got)
	}
	if got := Check(allow, deny, Request{Protocol: "tcp", Address: "10.1.2.3", Port: 443}); !got.Allow || got.RuleID != "cidr" {
		t.Fatalf("cidr=%+v", got)
	}
	if got := Check(allow, deny, Request{Protocol: "tcp", Address: "203.0.113.4", Port: 443}); got.Allow {
		t.Fatalf("domain rule authorized IP: %+v", got)
	}
	if got := Check(allow, deny, Request{Protocol: "tcp", Address: "10.1.2.3", Port: 80}); got.Allow {
		t.Fatalf("port mismatch: %+v", got)
	}
}
