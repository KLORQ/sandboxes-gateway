package registryauth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"
)

// Exchange obtains a bearer token from an explicitly trusted realm. The caller
// must derive service and scope from its own authorized request, not the guest.
// transport must verify TLS and must not forward requests through an untrusted proxy.
func Exchange(ctx context.Context, transport http.RoundTripper, header string, trusted []Realm, service, scope, username, password string) (string, error) {
	challenge, err := ParseBearerChallenge(header, trusted)
	if err != nil {
		return "", err
	}
	if service == "" || scope == "" || challenge.Service != service || challenge.Scope != scope || username == "" || password == "" {
		return "", errors.New("registry challenge does not match authorized request")
	}
	if transport == nil {
		return "", errors.New("registry token transport is required")
	}
	endpoint := *challenge.Realm
	query := endpoint.Query()
	query.Set("service", service)
	query.Set("scope", scope)
	endpoint.RawQuery = query.Encode()
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), http.NoBody)
	if err != nil {
		return "", errors.New("invalid registry token request")
	}
	req.SetBasicAuth(username, password)
	client := http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := client.Do(req)
	if err != nil {
		return "", errors.New("registry token request failed")
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("registry token request returned HTTP %d", resp.StatusCode)
	}
	return readToken(resp.Body)
}

func readToken(reader io.Reader) (string, error) {
	const maxResponse = 64 << 10
	body, err := io.ReadAll(io.LimitReader(reader, maxResponse+1))
	if err != nil || len(body) > maxResponse {
		return "", errors.New("invalid registry token response")
	}
	defer clear(body)
	var result struct {
		Token       string `json:"token"`
		AccessToken string `json:"access_token"`
	}
	if json.Unmarshal(body, &result) != nil || (result.Token == "" && result.AccessToken == "") || (result.Token != "" && result.AccessToken != "" && result.Token != result.AccessToken) {
		return "", errors.New("invalid registry token response")
	}
	if result.Token != "" {
		return result.Token, nil
	}
	return result.AccessToken, nil
}
