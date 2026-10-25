package vvauth

import (
	"encoding/json"
	"fmt"
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
