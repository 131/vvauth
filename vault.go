package vvauth

import (
	"encoding/json"
	"fmt"
	"regexp"
	"slices"
	"sort"
	"strings"

	vauthlogin "github.com/131/vauth-login"
)

// vaultRead returns the data of a kv2 secret.
func (v *Vauth) vaultRead(mount, secretPath string, optional bool) (map[string]any, error) {
	secretPath = strings.Trim(secretPath, "/")
	status, response, err := v.Request("GET", mount+"/data/"+secretPath, v.VAULT_TOKEN(), nil, 0)
	if err != nil {
		return nil, err
	}
	if optional && status == 404 {
		return map[string]any{}, nil
	}
	if status != 200 {
		return nil, &vauthlogin.HTTPError{Status: status, Body: string(response)}
	}
	var parsed struct {
		Data struct {
			Data map[string]any `json:"data"`
		} `json:"data"`
	}
	if err := json.Unmarshal(response, &parsed); err != nil {
		return nil, fmt.Errorf("Invalid secret response for '%s/%s': %w", mount, secretPath, err)
	}
	return parsed.Data.Data, nil
}

// vaultWrite replaces the data of a kv2 secret.
func (v *Vauth) vaultWrite(mount, secretPath string, data map[string]any) error {
	secretPath = strings.Trim(secretPath, "/")
	status, response, err := v.Request("POST", mount+"/data/"+secretPath, v.VAULT_TOKEN(), map[string]any{"data": data}, 0)
	if err != nil {
		return err
	}
	if status != 200 {
		return &vauthlogin.HTTPError{Status: status, Body: string(response)}
	}
	return nil
}

var pingDelegate = regexp.MustCompile(`(?i)^\$\$(?:\{delegate\.([A-Za-z0-9_.-]+)\}|delegate\.([A-Za-z0-9_.-]+))$`)

// Ping validates inherited credentials without login, environment resolution or cache access.
// Environ is the runtime snapshot supplied to the constructor, not Connect's token.
func (v *Vauth) Ping() error {
	if v.VAULT_ADDR() == "" {
		return fmt.Errorf("Vault ping requires VAULT_ADDR")
	}
	keys := []string{"VAULT_TOKEN"}
	rcEnv, _ := v.RC()["env"].(map[string]any)
	mapping, _ := rcEnv["map"].(map[string]any)
	var names []string
	for key := range mapping {
		names = append(names, key)
	}
	sort.Strings(names)
	for _, key := range names {
		value, ok := mapping[key].(string)
		if !ok {
			continue
		}
		macro := pingDelegate.FindStringSubmatch(value)
		if macro == nil {
			continue
		}
		role := macro[1]
		if role == "" {
			role = macro[2]
		}
		if !slices.Contains(v.Config.Delegate, role) {
			return fmt.Errorf("Unknown Vault delegation in env.map")
		}
		if !slices.Contains(keys, key) {
			keys = append(keys, key)
		}
	}
	for _, key := range keys {
		token := v.Environ[key]
		if token == "" {
			return fmt.Errorf("Vault ping requires inherited %s", key)
		}
		status, body, err := v.Request("GET", "auth/token/lookup-self", token, nil, 0)
		// Do not expose transport errors or response bodies containing credentials.
		if err != nil {
			return fmt.Errorf("Vault ping failed for %s: request failed", key)
		}
		if status != 200 {
			return fmt.Errorf("Vault ping failed for %s: HTTP %d", key, status)
		}
		var response struct {
			Data *struct {
				TTL *float64 `json:"ttl"`
			} `json:"data"`
		}
		if json.Unmarshal(body, &response) != nil || response.Data == nil || response.Data.TTL == nil || *response.Data.TTL < 0 {
			return fmt.Errorf("Vault ping failed for %s: invalid lookup response", key)
		}
	}
	return nil
}
