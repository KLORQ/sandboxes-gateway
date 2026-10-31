package registryauth

import (
	"errors"
	"net/http"
	"net/url"
	"strings"
)

// PullScope derives the least-privileged token scope for a supported registry
// pull request. The expected authority must come from host configuration, not
// from the request. This does not authenticate the caller or enforce network
// policy; those checks are required before using the result.
func PullScope(method string, requestURL *url.URL, expectedAuthority string) (string, error) {
	if method != http.MethodGet && method != http.MethodHead {
		return "", errors.New("unsupported registry pull method")
	}
	if !validPullURL(requestURL, expectedAuthority) {
		return "", errors.New("invalid registry pull URL")
	}
	parts := strings.Split(requestURL.Path, "/")
	if len(parts) < 5 || parts[0] != "" || parts[1] != "v2" {
		return "", errors.New("unsupported registry pull path")
	}
	kind := parts[len(parts)-2]
	if (kind != "manifests" && kind != "blobs") || !validReference(parts[len(parts)-1]) {
		return "", errors.New("unsupported registry pull resource")
	}
	repository := parts[2 : len(parts)-2]
	if len(strings.Join(repository, "/")) > 255 {
		return "", errors.New("registry repository is too long")
	}
	for _, component := range repository {
		if !validRepositoryComponent(component) {
			return "", errors.New("invalid registry repository")
		}
	}
	return "repository:" + strings.Join(repository, "/") + ":pull", nil
}

// ManifestPushScope derives a push-only repository scope for a manifest PUT.
// It does not authorize a caller, route requests, or support blob uploads.
func ManifestPushScope(method string, requestURL *url.URL, expectedAuthority string) (string, error) {
	if method != http.MethodPut {
		return "", errors.New("unsupported registry manifest push method")
	}
	scope, err := PullScope(http.MethodGet, requestURL, expectedAuthority)
	if err != nil {
		return "", err
	}
	parts := strings.Split(requestURL.Path, "/")
	if parts[len(parts)-2] != "manifests" {
		return "", errors.New("unsupported registry manifest push resource")
	}
	return strings.TrimSuffix(scope, ":pull") + ":push", nil
}

func validPullURL(u *url.URL, authority string) bool {
	return u != nil && u.Scheme == httpsScheme && authority != "" &&
		strings.EqualFold(u.Host, authority) && u.User == nil && u.Opaque == "" &&
		u.RawQuery == "" && !u.ForceQuery && u.Fragment == "" &&
		u.RawFragment == "" && u.RawPath == "" && !strings.Contains(u.Path, "%")
}

func validRepositoryComponent(s string) bool {
	if s == "" || len(s) > 255 || !isLowerAlphaNumeric(s[0]) || !isLowerAlphaNumeric(s[len(s)-1]) {
		return false
	}
	for i := 0; i < len(s); i++ {
		if !isLowerAlphaNumeric(s[i]) && s[i] != '.' && s[i] != '_' && s[i] != '-' {
			return false
		}
	}
	return true
}

func isLowerAlphaNumeric(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= '0' && c <= '9'
}

func validReference(s string) bool {
	if s == "" || len(s) > 255 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !isLowerAlphaNumeric(c) && (c < 'A' || c > 'Z') && c != '.' && c != '_' && c != '-' && c != ':' {
			return false
		}
	}
	return true
}
