package registryauth

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"
)

// TokenTransport restricts token requests to one configured HTTPS endpoint and
// connects only to resolved addresses within explicitly allowed prefixes. It
// verifies TLS using the endpoint hostname and never uses an HTTP proxy.
// This transport does not authenticate sandbox identity or enforce guest egress.
type TokenTransport struct {
	realm     Realm
	transport *http.Transport
}

// NewTokenTransport constructs a fail-closed transport for a trusted endpoint.
// A nil root pool uses system roots. Prefixes must be supplied by trusted host
// configuration, not obtained from a registry challenge or guest request.
func NewTokenTransport(realm Realm, prefixes []netip.Prefix, roots *x509.CertPool) (*TokenTransport, error) {
	return newTokenTransport(realm, prefixes, roots, net.DefaultResolver.LookupNetIP)
}

type lookupIP func(context.Context, string, string) ([]netip.Addr, error)

func newTokenTransport(realm Realm, prefixes []netip.Prefix, roots *x509.CertPool, lookup lookupIP) (*TokenTransport, error) {
	endpoint, err := url.Parse("https://" + realm.Host + realm.Path)
	if err != nil || endpoint.Host != realm.Host || endpoint.Path != realm.Path || endpoint.RawPath != "" ||
		endpoint.User != nil || endpoint.RawQuery != "" || endpoint.ForceQuery || endpoint.Fragment != "" ||
		endpoint.Hostname() == "" || !strings.HasPrefix(realm.Path, "/") || len(prefixes) == 0 {
		return nil, errors.New("invalid token transport configuration")
	}
	transport, err := restrictedTransport(prefixes, roots, lookup)
	if err != nil {
		return nil, err
	}
	return &TokenTransport{realm: realm, transport: transport}, nil
}

func restrictedTransport(prefixes []netip.Prefix, roots *x509.CertPool, lookup lookupIP) (*http.Transport, error) {
	if len(prefixes) == 0 || lookup == nil {
		return nil, errors.New("token address policy is required")
	}
	allowed := make([]netip.Prefix, len(prefixes))
	for i, prefix := range prefixes {
		if !prefix.IsValid() {
			return nil, errors.New("invalid token address prefix")
		}
		allowed[i] = prefix.Masked()
	}
	if roots != nil {
		roots = roots.Clone()
	}
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	transport := &http.Transport{
		Proxy:             nil,
		DisableKeepAlives: true,
		TLSClientConfig:   &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots},
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			return dialAllowed(ctx, dialer, network, address, allowed, lookup)
		},
	}
	return transport, nil
}

func (t *TokenTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if t == nil || t.transport == nil || req == nil || req.URL == nil || req.Method != http.MethodGet || req.URL.Scheme != httpsScheme ||
		!strings.EqualFold(req.URL.Host, t.realm.Host) || req.URL.EscapedPath() != t.realm.Path ||
		req.URL.User != nil || req.URL.Opaque != "" || req.URL.Fragment != "" || req.Host != "" && !strings.EqualFold(req.Host, t.realm.Host) {
		return nil, errors.New("token request does not match configured endpoint")
	}
	return t.transport.RoundTrip(req)
}

func dialAllowed(ctx context.Context, dialer *net.Dialer, network, address string, allowed []netip.Prefix, lookup lookupIP) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil || network != "tcp" {
		return nil, errors.New("invalid token endpoint address")
	}
	addresses, err := lookup(ctx, "ip", host)
	if err != nil {
		return nil, errors.New("token endpoint DNS lookup failed")
	}
	for _, address := range addresses {
		address = address.Unmap()
		for _, prefix := range allowed {
			if prefix.Contains(address) {
				conn, dialErr := dialer.DialContext(ctx, "tcp", net.JoinHostPort(address.String(), port))
				if dialErr == nil {
					return conn, nil
				}
			}
		}
	}
	return nil, errors.New("no allowed token endpoint address reachable")
}
