package registryauth

import (
	"context"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"testing"
)

func TestRegistryTransportReadOnlyAndBoundToAuthority(t *testing.T) {
	requests := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests++
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	endpoint, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	transport, err := NewRegistryTransport(endpoint.Host, []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")}, roots)
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"/v2/", "/v2/team/app/manifests/latest", "/v2/team/app/blobs/sha256:abc"} {
		req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, server.URL+path, http.NoBody)
		if err != nil {
			t.Fatal(err)
		}
		resp, err := transport.RoundTrip(req)
		if err != nil {
			t.Fatalf("allowed path %s: %v", path, err)
		}
		_ = resp.Body.Close()
	}
	for _, tc := range []struct{ method, url string }{
		{http.MethodPut, server.URL + "/v2/team/app/manifests/latest"},
		{http.MethodGet, server.URL + "/v2/team/app/blobs/uploads/id"},
		{http.MethodGet, server.URL + "/v2/team/app/manifests/latest?x=1"},
		{http.MethodGet, "https://wrong.example/v2/team/app/manifests/latest"},
	} {
		req, err := http.NewRequestWithContext(context.Background(), tc.method, tc.url, http.NoBody)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := transport.RoundTrip(req); err == nil {
			t.Fatalf("unauthorized request accepted: %s %s", tc.method, tc.url)
		}
	}
	if requests != 3 {
		t.Fatalf("unexpected number of upstream requests: %d", requests)
	}
}
