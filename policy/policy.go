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
	CIDR     string
	Port     uint16
}

// Port maps a host loopback port to a guest port.
type Port struct {
	Host  uint16
	Guest uint16
	Proto string
}

// Policy is the effective sandbox policy.
type Policy struct {
	Revision  int
	SandboxID string
	AuditPath string
	Allow     []Rule
	Deny      []Rule
	Ports     []Port
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
	return Decision{Allow: false, RuleID: rule.ID, Reason: "policy engine unavailable"}
}
