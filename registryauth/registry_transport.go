package registryauth

import (
	"crypto/x509"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
)

// RegistryTransport is a host-only transport for read-only registry requests.
// It does not authenticate a sandbox or authorize access on its own.
type RegistryTransport struct {
	authority string
	transport *http.Transport
}

// NewRegistryTransport confines requests to one trusted HTTPS authority and
// the explicitly configured IP prefixes. It does not use proxy environment.
func NewRegistryTransport(authority string, prefixes []netip.Prefix, roots *x509.CertPool) (*RegistryTransport, error) {
	endpoint, err := url.Parse("https://" + authority)
	if err != nil || endpoint.Host != authority || endpoint.Hostname() == "" || endpoint.User != nil ||
		endpoint.Path != "" || endpoint.RawQuery != "" || endpoint.ForceQuery || endpoint.Fragment != "" {
		return nil, errors.New("invalid registry transport authority")
	}
	transport, err := restrictedTransport(prefixes, roots, net.DefaultResolver.LookupNetIP)
	if err != nil {
		return nil, err
	}
	return &RegistryTransport{authority: authority, transport: transport}, nil
}

// RoundTrip accepts only the registry ping and supported read-only pull paths.
// Redirect handling must be disabled by the client using this transport.
func (t *RegistryTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if t == nil || t.transport == nil || req == nil || req.URL == nil || req.URL.Opaque != "" ||
		req.Host != "" && !strings.EqualFold(req.Host, t.authority) {
		return nil, errors.New("invalid registry request")
	}
	if req.URL.Path == "/v2/" && (req.Method == http.MethodGet || req.Method == http.MethodHead) && validPullURL(req.URL, t.authority) {
		return t.transport.RoundTrip(req)
	}
	if _, err := PullScope(req.Method, req.URL, t.authority); err != nil {
		return nil, err
	}
	return t.transport.RoundTrip(req)
}
