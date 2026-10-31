package registryauth

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

func TestExchangeTrustedRealmAndRejectsRedirect(t *testing.T) {
	requests := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		if r.URL.Path == "/redirect" {
			http.Redirect(w, r, "/token", http.StatusFound)
			return
		}
		user, password, ok := r.BasicAuth()
		if !ok || user != "synthetic" || password != "synthetic-secret" || r.URL.Query().Get("scope") != "repository:demo:pull" {
			t.Error("unexpected token request")
		}
		_, _ = fmt.Fprint(w, `{"token":"synthetic-token"}`)
	}))
	defer server.Close()
	endpoint, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	header := fmt.Sprintf(`Bearer realm="%s/token",service="registry.example",scope="repository:demo:pull"`, server.URL)
	trusted := []Realm{{Host: endpoint.Host, Path: "/token"}}
	token, err := Exchange(context.Background(), server.Client().Transport, header, trusted, "registry.example", "repository:demo:pull", "synthetic", "synthetic-secret")
	if err != nil || token != "synthetic-token" {
		t.Fatalf("exchange: token=%q err=%v", token, err)
	}
	if _, err := Exchange(context.Background(), server.Client().Transport, header, trusted, "registry.example", "repository:other:pull", "synthetic", "synthetic-secret"); err == nil || requests != 1 {
		t.Fatal("unapproved scope reached token endpoint")
	}
	redirect := fmt.Sprintf(`Bearer realm="%s/redirect",service="registry.example",scope="repository:demo:pull"`, server.URL)
	if _, err := Exchange(context.Background(), server.Client().Transport, redirect, []Realm{{Host: endpoint.Host, Path: "/redirect"}}, "registry.example", "repository:demo:pull", "synthetic", "synthetic-secret"); err == nil || requests != 2 {
		t.Fatal("redirect was followed or accepted")
	}
}
