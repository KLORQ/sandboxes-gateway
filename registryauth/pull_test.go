package registryauth

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
)

func TestPullScope(t *testing.T) {
	tests := []struct {
		name, method, rawURL, authority, want string
	}{
		{"manifest", http.MethodGet, "https://registry.example/v2/team/app/manifests/latest", "registry.example", "repository:team/app:pull"},
		{"blob head", http.MethodHead, "https://registry.example:443/v2/app/blobs/sha256:abc", "registry.example:443", "repository:app:pull"},
		{"write", http.MethodPut, "https://registry.example/v2/app/manifests/latest", "registry.example", ""},
		{"other host", http.MethodGet, "https://evil.example/v2/app/manifests/latest", "registry.example", ""},
		{"plain http", http.MethodGet, "http://registry.example/v2/app/manifests/latest", "registry.example", ""},
		{"userinfo", http.MethodGet, "https://user@registry.example/v2/app/manifests/latest", "registry.example", ""},
		{"query", http.MethodGet, "https://registry.example/v2/app/manifests/latest?scope=push", "registry.example", ""},
		{"empty query", http.MethodGet, "https://registry.example/v2/app/manifests/latest?", "registry.example", ""},
		{"encoded slash", http.MethodGet, "https://registry.example/v2/app%2Fother/manifests/latest", "registry.example", ""},
		{"traversal", http.MethodGet, "https://registry.example/v2/app/../manifests/latest", "registry.example", ""},
		{"uppercase repository", http.MethodGet, "https://registry.example/v2/App/manifests/latest", "registry.example", ""},
		{"upload", http.MethodGet, "https://registry.example/v2/app/blobs/uploads/id", "registry.example", ""},
		{"catalog", http.MethodGet, "https://registry.example/v2/_catalog", "registry.example", ""},
		{"empty authority", http.MethodGet, "https://registry.example/v2/app/manifests/latest", "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u, err := url.Parse(tt.rawURL)
			if err != nil {
				t.Fatal(err)
			}
			got, err := PullScope(tt.method, u, tt.authority)
			if tt.want == "" {
				if err == nil {
					t.Fatalf("unexpected scope %q", got)
				}
				return
			}
			if err != nil || got != tt.want {
				t.Fatalf("scope = %q, error = %v; want %q", got, err, tt.want)
			}
		})
	}
}

func FuzzPullScope(f *testing.F) {
	for _, seed := range []string{
		"https://registry.example/v2/library/alpine/manifests/latest",
		"https://registry.example/v2/demo/blobs/sha256:123",
		"https://registry.example/v2/demo%2Fother/manifests/latest",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		u, err := url.Parse(raw)
		if err != nil {
			return
		}
		scope, err := PullScope(http.MethodGet, u, "registry.example")
		if err == nil && (!strings.HasPrefix(scope, "repository:") || !strings.HasSuffix(scope, ":pull") || strings.Count(scope, ":") != 2) {
			t.Fatalf("invalid granted scope %q", scope)
		}
	})
}

func TestPullScopeRejectsAmbiguousURLRepresentation(t *testing.T) {
	base := url.URL{Scheme: "https", Host: "registry.example", Path: "/v2/demo/manifests/latest"}
	if _, err := PullScope(http.MethodGet, &base, "registry.example"); err != nil {
		t.Fatalf("valid URL rejected: %v", err)
	}
	for _, mutate := range []func(*url.URL){
		func(u *url.URL) { u.Opaque = "//evil.example/v2/demo/manifests/latest" },
		func(u *url.URL) { u.RawFragment = "untrusted" },
	} {
		u := base
		mutate(&u)
		if scope, err := PullScope(http.MethodGet, &u, "registry.example"); err == nil {
			t.Fatalf("ambiguous URL accepted with scope %q", scope)
		}
	}
}

func TestManifestPushScope(t *testing.T) {
	for _, tc := range []struct {
		method, path, want string
	}{
		{http.MethodPut, "/v2/team/app/manifests/latest", "repository:team/app:push"},
		{http.MethodPut, "/v2/team/app/blobs/sha256:abc", ""},
		{http.MethodPut, "/v2/team/app/blobs/uploads/id", ""},
		{http.MethodDelete, "/v2/team/app/manifests/latest", ""},
		{http.MethodPut, "/v2/team/../manifests/latest", ""},
	} {
		u := &url.URL{Scheme: "https", Host: "registry.example", Path: tc.path}
		got, err := ManifestPushScope(tc.method, u, "registry.example")
		if tc.want == "" && err == nil {
			t.Fatalf("%s %s unexpectedly authorized as %q", tc.method, tc.path, got)
		}
		if tc.want != "" && (err != nil || got != tc.want) {
			t.Fatalf("%s %s: got %q, %v", tc.method, tc.path, got, err)
		}
	}
}

func FuzzManifestPushScope(f *testing.F) {
	f.Add("https://registry.example/v2/team/app/manifests/latest")
	f.Add("https://registry.example/v2/team/app/blobs/uploads/id")
	f.Fuzz(func(t *testing.T, raw string) {
		u, err := url.Parse(raw)
		if err != nil {
			return
		}
		scope, err := ManifestPushScope(http.MethodPut, u, "registry.example")
		if err == nil && (!strings.HasPrefix(scope, "repository:") || !strings.HasSuffix(scope, ":push") || strings.Count(scope, ":") != 2) {
			t.Fatalf("invalid push scope %q", scope)
		}
	})
}
