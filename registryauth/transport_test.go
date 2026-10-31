package registryauth

import (
	"context"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"testing"
)

func TestTokenTransportRestrictsDestinationAndVerifiesTLS(t *testing.T) {
	requests := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests++
		_, _ = fmt.Fprint(w, `{"token":"fixture-token"}`)
	}))
	defer server.Close()
	endpoint, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	realm := Realm{Host: endpoint.Host, Path: "/token"}
	allowed := []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")}
	transport, err := NewTokenTransport(realm, allowed, roots)
	if err != nil {
		t.Fatal(err)
	}
	header := fmt.Sprintf(`Bearer realm="%s/token",service="registry.example",scope="repository:demo:pull"`, server.URL)
	exchange := func(rt http.RoundTripper) error {
		_, err := Exchange(context.Background(), rt, header, []Realm{realm}, "registry.example", "repository:demo:pull", "fixture-user", "fixture-password")
		return err
	}
	if err := exchange(transport); err != nil || requests != 1 {
		t.Fatalf("allowed TLS exchange failed: %v", err)
	}
	blocked, err := NewTokenTransport(realm, []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")}, roots)
	if err != nil {
		t.Fatal(err)
	}
	if err := exchange(blocked); err == nil || requests != 1 {
		t.Fatal("disallowed address reached token endpoint")
	}
	untrusted, err := NewTokenTransport(realm, allowed, x509.NewCertPool())
	if err != nil {
		t.Fatal(err)
	}
	if err := exchange(untrusted); err == nil || requests != 1 {
		t.Fatal("untrusted TLS certificate was accepted")
	}
	request, err := http.NewRequestWithContext(context.Background(), http.MethodGet, server.URL+"/other", http.NoBody)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := transport.RoundTrip(request); err == nil || requests != 1 {
		t.Fatal("wrong token path accepted")
	}
	request.URL.Path = "/token"
	request.Host = "wrong.example"
	if _, err := transport.RoundTrip(request); err == nil || requests != 1 {
		t.Fatal("wrong HTTP host accepted")
	}
	_, port, err := net.SplitHostPort(endpoint.Host)
	if err != nil {
		t.Fatal(err)
	}
	const wrongHostname = "wrong.example"
	if err := server.Certificate().VerifyHostname(wrongHostname); err == nil {
		t.Fatal("test certificate unexpectedly matches wrong hostname")
	}
	wrongHostRealm := Realm{Host: net.JoinHostPort(wrongHostname, port), Path: "/token"}
	lookup := func(context.Context, string, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
	}
	wrongHost, err := newTokenTransport(wrongHostRealm, allowed, roots, lookup)
	if err != nil {
		t.Fatal(err)
	}
	wrongHeader := fmt.Sprintf(`Bearer realm="https://%s/token",service="registry.example",scope="repository:demo:pull"`, wrongHostRealm.Host)
	if _, err := Exchange(context.Background(), wrongHost, wrongHeader, []Realm{wrongHostRealm}, "registry.example", "repository:demo:pull", "fixture-user", "fixture-password"); err == nil || requests != 1 {
		t.Fatal("TLS hostname mismatch accepted")
	}
}

func TestTokenTransportRequiresValidConfiguration(t *testing.T) {
	allowed := []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")}
	for _, tc := range []struct {
		realm Realm
		cidrs []netip.Prefix
	}{
		{Realm{Host: "example.test", Path: "/token"}, nil},
		{Realm{Host: "example.test", Path: "/token?other"}, allowed},
		{Realm{Host: "user@example.test", Path: "/token"}, allowed},
		{Realm{Host: "example.test", Path: "token"}, allowed},
		{Realm{Host: "example.test", Path: "/token"}, []netip.Prefix{{}}},
	} {
		if _, err := NewTokenTransport(tc.realm, tc.cidrs, nil); err == nil {
			t.Fatalf("invalid configuration accepted: %+v", tc.realm)
		}
	}
}

func TestTokenTransportRechecksDNSForEachConnection(t *testing.T) {
	requests := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests++
		_, _ = fmt.Fprint(w, `{"token":"fixture-token"}`)
	}))
	defer server.Close()
	endpoint, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	lookups := 0
	lookup := func(context.Context, string, string) ([]netip.Addr, error) {
		lookups++
		if lookups == 1 {
			return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
		}
		return []netip.Addr{netip.MustParseAddr("192.0.2.1")}, nil
	}
	realm := Realm{Host: endpoint.Host, Path: "/token"}
	transport, err := newTokenTransport(realm, []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")}, roots, lookup)
	if err != nil {
		t.Fatal(err)
	}
	header := fmt.Sprintf(`Bearer realm="%s/token",service="registry.example",scope="repository:demo:pull"`, server.URL)
	call := func() error {
		_, err := Exchange(context.Background(), transport, header, []Realm{realm}, "registry.example", "repository:demo:pull", "fixture-user", "fixture-password")
		return err
	}
	if err := call(); err != nil || requests != 1 {
		t.Fatalf("initial allowed address failed: %v", err)
	}
	if err := call(); err == nil || requests != 1 || lookups != 2 {
		t.Fatalf("changed DNS address was not blocked: requests=%d lookups=%d err=%v", requests, lookups, err)
	}
}
