package policy

import "testing"

func TestDefaultDeny(t *testing.T) {
	got := Evaluate(Rule{ID: "empty"})
	if got.Allow {
		t.Fatal("empty policy must deny")
	}
}
