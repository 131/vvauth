package vvauth

import (
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
)

type pingTransport func(*http.Request) (*http.Response, error)

func (f pingTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestPingRuntimeSnapshot(t *testing.T) {
	for _, scenario := range []string{"valid", "missing", "expired child", "network", "invalid response"} {
		t.Run(scenario, func(t *testing.T) {
			env := map[string]string{"VAULT_ADDR": "https://synthetic.invalid", "VAULT_TOKEN": "synthetic-parent", "VAULT_ROUTER_TOKEN": "synthetic-child"}
			v, err := NewFromRC([]byte(`{"delegate":["router"],"env":{"map":{"VAULT_ROUTER_TOKEN":"$${delegate.router}","SECRET":"$${secrets.secret}"}}}`), env)
			if err != nil {
				t.Fatal(err)
			}
			// Both snapshots are independent: Ping must not use changed ambient credentials.
			env["VAULT_TOKEN"] = "synthetic-replacement"
			t.Setenv("VAULT_TOKEN", "synthetic-ambient")
			if scenario == "missing" {
				delete(v.Environ, "VAULT_ROUTER_TOKEN")
			}
			calls := 0
			v.HTTPClient = &http.Client{Transport: pingTransport(func(r *http.Request) (*http.Response, error) {
				calls++
				if r.Method != "GET" || r.URL.Path != "/v1/auth/token/lookup-self" {
					t.Error("unexpected request")
				}
				token := r.Header.Get("X-Vault-Token")
				if token != "synthetic-parent" && token != "synthetic-child" {
					t.Error("wrong runtime token")
				}
				if scenario == "network" {
					return nil, errors.New("synthetic-parent synthetic-child")
				}
				status, body := 200, `{"data":{"ttl":3600}}`
				if scenario == "expired child" && token == "synthetic-child" {
					status, body = 403, "synthetic-parent synthetic-child"
				}
				if scenario == "invalid response" {
					body = "synthetic-parent synthetic-child"
				}
				return &http.Response{StatusCode: status, Body: io.NopCloser(strings.NewReader(body)), Header: http.Header{}}, nil
			})}
			err = v.Ping()
			if scenario == "valid" {
				if err != nil {
					t.Fatal(err)
				}
				if calls != 2 {
					t.Fatalf("lookups: %d", calls)
				}
			} else {
				if err == nil {
					t.Fatal("expected failure")
				}
				if strings.Contains(err.Error(), "synthetic-parent") || strings.Contains(err.Error(), "synthetic-child") {
					t.Fatal("credential leaked")
				}
			}
			if v.VAULT_TOKEN() != "synthetic-parent" {
				t.Fatal("parent changed")
			}
		})
	}
}
