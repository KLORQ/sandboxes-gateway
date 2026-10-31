package registryauth

import (
	"strings"
	"testing"
)

func TestParseBearerChallenge(t *testing.T) {
	challenge, err := ParseBearerChallenge(`Bearer realm="https://auth.example/token",service="registry.example",scope="repository:team/app:pull,push"`, []Realm{{Host: "auth.example", Path: "/token"}})
	if err != nil {
		t.Fatal(err)
	}
	if challenge.Service != "registry.example" || challenge.Scope != "repository:team/app:pull,push" {
		t.Fatalf("parsed challenge = %#v", challenge)
	}
}

func FuzzParseBearerChallenge(f *testing.F) {
	f.Add(`Bearer realm="https://auth.example/token",service="registry.example",scope="repository:demo:pull"`)
	f.Add(`Bearer realm="https://evil.example/token"`)
	f.Add(`Bearer realm="https://auth.example/token",realm="https://evil.example/token"`)
	f.Fuzz(func(t *testing.T, header string) {
		result, err := ParseBearerChallenge(header, []Realm{{Host: "auth.example", Path: "/token"}})
		if err != nil {
			return
		}
		if result.Realm == nil || result.Realm.Scheme != "https" || !strings.EqualFold(result.Realm.Host, "auth.example") || result.Realm.EscapedPath() != "/token" || result.Realm.User != nil || result.Realm.RawQuery != "" || result.Realm.ForceQuery || result.Realm.Fragment != "" {
			t.Fatalf("unexpected trusted realm: %#v", result.Realm)
		}
	})
}

func TestParseBearerChallengeRejectsUntrustedOrUnsafeRealm(t *testing.T) {
	trusted := []Realm{{Host: "auth.example", Path: "/token"}}
	tests := []struct {
		name   string
		header string
	}{
		{name: "wrong host", header: `Bearer realm="https://evil.example/token"`},
		{name: "wrong path", header: `Bearer realm="https://auth.example/other"`},
		{name: "http", header: `Bearer realm="http://auth.example/token"`},
		{name: "userinfo", header: `Bearer realm="https://user:pass@auth.example/token"`},
		{name: "query", header: `Bearer realm="https://auth.example/token?next=evil"`},
		{name: "fragment", header: `Bearer realm="https://auth.example/token#part"`},
		{name: "empty query", header: `Bearer realm="https://auth.example/token?"`},
		{name: "empty fragment", header: `Bearer realm="https://auth.example/token#"`},
		{name: "unescaped quote", header: `Bearer realm="https://auth.example/token",service="a"b"`},
		{name: "control character", header: "Bearer realm=\"https://auth.example/token\",service=\"a\nb\""},
		{name: "wrong scheme", header: `Basic realm="https://auth.example/token"`},
		{name: "duplicate realm", header: `Bearer realm="https://auth.example/token",realm="https://auth.example/token"`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := ParseBearerChallenge(tt.header, trusted); err == nil {
				t.Fatal("unsafe or untrusted challenge must be rejected")
			}
		})
	}
}
