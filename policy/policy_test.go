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
