// Package registryauth validates OCI registry bearer challenges before a
// host-side credential broker is allowed to contact an authentication realm.
package registryauth

import (
	"fmt"
	"net/url"
	"strings"
)

const httpsScheme = "https"

// Realm is an explicitly trusted HTTPS authentication endpoint. Path matching
// is exact so trusting one token endpoint does not trust the whole host.
type Realm struct {
	Host string
	Path string
}

// Challenge is the parsed Bearer challenge. Parameters never contain a secret.
type Challenge struct {
	Realm   *url.URL
	Service string
	Scope   string
}

// ParseBearerChallenge parses one WWW-Authenticate Bearer challenge and
// accepts its realm only when it matches a configured HTTPS host and path.
func ParseBearerChallenge(header string, trusted []Realm) (Challenge, error) {
	scheme, params, err := parseChallenge(header)
	if err != nil {
		return Challenge{}, err
	}
	if !strings.EqualFold(scheme, "Bearer") {
		return Challenge{}, fmt.Errorf("unsupported registry challenge scheme %q", scheme)
	}
	realmRaw := params["realm"]
	if realmRaw == "" {
		return Challenge{}, fmt.Errorf("registry bearer challenge has no realm")
	}
	realm, err := url.Parse(realmRaw)
	if err != nil || realm.Scheme != httpsScheme || realm.Host == "" || realm.User != nil || realm.RawQuery != "" || realm.ForceQuery || realm.Fragment != "" || strings.Contains(realmRaw, "#") {
		return Challenge{}, fmt.Errorf("registry bearer realm must be an HTTPS URL without userinfo, query, or fragment")
	}
	if !trustedRealm(realm, trusted) {
		return Challenge{}, fmt.Errorf("registry bearer realm is not trusted")
	}
	return Challenge{Realm: realm, Service: params["service"], Scope: params["scope"]}, nil
}

func trustedRealm(candidate *url.URL, trusted []Realm) bool {
	for _, realm := range trusted {
		if !strings.EqualFold(candidate.Host, realm.Host) {
			continue
		}
		if candidate.EscapedPath() == realm.Path {
			return true
		}
	}
	return false
}

func parseChallenge(header string) (string, map[string]string, error) {
	header = strings.TrimSpace(header)
	scheme, rest, ok := strings.Cut(header, " ")
	if !ok || scheme == "" || rest == "" {
		return "", nil, fmt.Errorf("malformed registry authentication challenge")
	}
	params := make(map[string]string)
	for _, field := range splitParameters(rest) {
		key, value, ok := strings.Cut(strings.TrimSpace(field), "=")
		if !ok || key == "" || value == "" {
			return "", nil, fmt.Errorf("malformed registry challenge parameter")
		}
		key = strings.ToLower(strings.TrimSpace(key))
		value = strings.TrimSpace(value)
		if len(value) < 2 || value[0] != '"' || value[len(value)-1] != '"' {
			return "", nil, fmt.Errorf("registry challenge parameters must be quoted")
		}
		if _, exists := params[key]; exists {
			return "", nil, fmt.Errorf("duplicate registry challenge parameter %q", key)
		}
		unquoted, err := unquote(value[1 : len(value)-1])
		if err != nil {
			return "", nil, err
		}
		params[key] = unquoted
	}
	return scheme, params, nil
}

func splitParameters(value string) []string {
	var fields []string
	start := 0
	quoted, escaped := false, false
	for i, r := range value {
		if escaped {
			escaped = false
			continue
		}
		if quoted && r == '\\' {
			escaped = true
			continue
		}
		if r == '"' {
			quoted = !quoted
		} else if r == ',' && !quoted {
			fields = append(fields, value[start:i])
			start = i + 1
		}
	}
	fields = append(fields, value[start:])
	return fields
}

func unquote(value string) (string, error) {
	var result strings.Builder
	for i := 0; i < len(value); i++ {
		if value[i] == '"' || value[i] < 0x20 || value[i] == 0x7f {
			return "", fmt.Errorf("invalid character in registry challenge")
		}
		if value[i] == '\\' {
			i++
			if i >= len(value) || value[i] < 0x20 || value[i] == 0x7f {
				return "", fmt.Errorf("malformed escape in registry challenge")
			}
		}
		result.WriteByte(value[i])
	}
	return result.String(), nil
}
