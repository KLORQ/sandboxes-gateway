// Package policy defines the default-deny network policy model.
package policy

// Action is an allow or deny decision.
type Action string

const (
	Allow Action = "allow"
	Deny  Action = "deny"
)

// Rule is a single policy rule.
type Rule struct {
	ID       string
	Action   Action
	Protocol string
	Domain   string
	Port     uint16
}

// Decision is the result of policy evaluation.
type Decision struct {
	Allow    bool
	RuleID   string
	Revision string
	Reason   string
}

// Evaluate fails closed until a policy engine is configured.
func Evaluate(rule Rule) Decision {
	if rule.Action != Allow {
		return Decision{Allow: false, RuleID: rule.ID, Reason: "default deny"}
	}
	return Decision{Allow: true, RuleID: rule.ID, Reason: "allow rule"}
}
