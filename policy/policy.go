// Package policy defines the default-deny network policy model.
package policy

import (
	"net"
	"regexp"
	"strings"
)

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

// Port maps a host loopback address/port to a guest port.
type Port struct {
	Host   uint16
	Guest  uint16
	Proto  string
	HostIP string
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

// Request is a single network authorization request. Domain is used for a
// hostname target; Address is used for an IP target. HTTP fields are reserved
// for the HTTP policy phase.
type Request struct {
	Protocol string
	Address  string
	Domain   string
	Port     uint16
}

// Evaluate fails closed until a policy engine is configured.
func Evaluate(rule Rule) Decision {
	return Decision{Allow: false, RuleID: rule.ID, Reason: "policy engine unavailable"}
}

// Check evaluates compiled-in-command rules with deny precedence across both
// scopes. Domain rules are matched against Request.Domain; they never authorize
// an IP literal without a DNS binding.
func Check(allow, deny []Rule, req Request) Decision {
	protocol := strings.ToLower(strings.TrimSpace(req.Protocol))
	if protocol == "" {
		protocol = "tcp"
	}
	for i := range deny {
		if ruleMatches(deny[i], protocol, req) {
			return Decision{Allow: false, RuleID: deny[i].ID, Reason: "deny rule " + target(deny[i])}
		}
	}
	for i := range allow {
		if ruleMatches(allow[i], protocol, req) {
			return Decision{Allow: true, RuleID: allow[i].ID, Reason: "allow rule " + target(allow[i])}
		}
	}
	return Decision{Allow: false, Reason: "default deny"}
}

func target(rule Rule) string {
	if rule.Domain != "" {
		return rule.Domain
	}
	return rule.CIDR
}

func ruleMatches(rule Rule, protocol string, req Request) bool {
	ruleProtocol := strings.ToLower(strings.TrimSpace(rule.Protocol))
	if ruleProtocol == "" {
		ruleProtocol = "tcp"
	}
	if ruleProtocol != protocol {
		return false
	}
	if rule.Port != 0 && rule.Port != req.Port {
		return false
	}
	if rule.Domain != "" {
		return req.Domain != "" && domainMatches(rule.Domain, req.Domain)
	}
	if req.Address == "" || rule.CIDR == "" {
		return false
	}
	ip := net.ParseIP(req.Address)
	_, network, err := net.ParseCIDR(rule.CIDR)
	return err == nil && ip != nil && network.Contains(ip)
}

func domainMatches(pattern, name string) bool {
	pattern = strings.ToLower(strings.TrimSuffix(pattern, "."))
	name = strings.ToLower(strings.TrimSuffix(name, "."))
	switch {
	case strings.HasPrefix(pattern, "**."):
		suffix := strings.TrimPrefix(pattern, "**.")
		return name != suffix && strings.HasSuffix(name, "."+suffix)
	case strings.HasPrefix(pattern, "*."):
		suffix := strings.TrimPrefix(pattern, "*.")
		label, rest, found := strings.Cut(name, ".")
		return found && label != "" && rest == suffix
	}
	patternLabels := strings.Split(pattern, ".")
	nameLabels := strings.Split(name, ".")
	if len(patternLabels) != len(nameLabels) {
		return false
	}
	for i := range patternLabels {
		glob := strings.ReplaceAll(patternLabels[i], "[!", "[^")
		ok, err := regexp.MatchString("^"+glob+"$", nameLabels[i])
		if err != nil || !ok {
			return false
		}
	}
	return true
}
