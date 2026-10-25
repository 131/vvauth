package vvauth

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strconv"

	nyksobject "github.com/131/nyks/v6/object"
	nyksstring "github.com/131/nyks/v6/string"
	"gopkg.in/yaml.v3"
)

// Config contains only environment/profile settings; authentication is
// parsed and owned by vauth-login.
type Config struct {
	AgentCrypt *AgentCrypt `json:"ssh-agent-crypt" yaml:"ssh-agent-crypt"`
	Env        *EnvConfig  `json:"env" yaml:"env"`
}

// AgentCrypt points to a local ssh-agent-crypt armored JSON file whose keys
// feed $${secrets.X}.
type AgentCrypt struct {
	Path     string `json:"path" yaml:"path"`
	Identity string `json:"identity" yaml:"identity"`
}

// EnvConfig describes the environment to resolve.
type EnvConfig struct {
	Map    OrderedMap `json:"map" yaml:"map"`
	Paths  []string   `json:"paths" yaml:"paths"`
	Path   string     `json:"path" yaml:"path"`
	Git    bool       `json:"git" yaml:"git"`
	GitLab bool       `json:"gitlab" yaml:"gitlab"`
}

// OrderedMap keeps the decoded JSON order of a string mapping.
type OrderedMap struct {
	Keys   []string
	Values map[string]string
}

// Set adds or replaces key.
func (m *OrderedMap) Set(key, value string) {
	if m.Values == nil {
		m.Values = map[string]string{}
	}
	if _, exists := m.Values[key]; !exists {
		m.Keys = append(m.Keys, key)
	}
	m.Values[key] = value
}

// Get returns the value for key.
func (m *OrderedMap) Get(key string) (string, bool) {
	value, ok := m.Values[key]
	return value, ok
}

// Len returns the number of entries.
func (m *OrderedMap) Len() int { return len(m.Keys) }

// UnmarshalJSON decodes scalar values while retaining their JSON key order.
func (m *OrderedMap) UnmarshalJSON(body []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(body))
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	if token != json.Delim('{') {
		return fmt.Errorf("expected a mapping")
	}
	for decoder.More() {
		token, err := decoder.Token()
		if err != nil {
			return err
		}
		key := token.(string)
		var value any
		if err := decoder.Decode(&value); err != nil {
			return err
		}
		text, err := envValue(value)
		if err != nil {
			return fmt.Errorf("Invalid environment value '%s' in env.map: %w", key, err)
		}
		m.Set(key, text)
	}
	_, err = decoder.Token()
	return err
}

// MarshalJSON renders the entries in order.
func (m OrderedMap) MarshalJSON() ([]byte, error) {
	var out bytes.Buffer
	out.WriteByte('{')
	for i, key := range m.Keys {
		if i > 0 {
			out.WriteByte(',')
		}
		out.Write(jsonString(key))
		out.WriteByte(':')
		out.Write(jsonString(m.Values[key]))
	}
	out.WriteByte('}')
	return out.Bytes(), nil
}

func stringify(value any) (string, bool) {
	switch v := value.(type) {
	case nil:
		return "", false
	case string:
		return v, true
	case bool:
		return strconv.FormatBool(v), true
	case float64:
		return strconv.FormatFloat(v, 'f', -1, 64), true
	case json.Number:
		return v.String(), true
	}
	body, err := json.Marshal(value)
	if err != nil {
		return "", false
	}
	return string(body), true
}

// envValue accepts only JSON scalars, rendering numbers like JavaScript String.
func envValue(value any) (string, error) {
	switch value := value.(type) {
	case nil:
		return "", nil
	case string:
		return value, nil
	case bool:
		return strconv.FormatBool(value), nil
	case int, int8, int16, int32, int64, uint, uint8, uint16, uint32, uint64, float32, float64, json.Number:
		body, err := json.Marshal(value)
		var number float64
		if err == nil {
			err = json.Unmarshal(body, &number)
		}
		if err == nil {
			if number == 0 {
				return "0", nil
			}
			body, err = json.Marshal(number)
			if err == nil {
				return string(body), nil
			}
		}
	}
	return "", fmt.Errorf("expected a scalar")
}

// jsonString encodes like JSON.stringify (no HTML escaping).
func jsonString(value string) []byte {
	var out bytes.Buffer
	encoder := json.NewEncoder(&out)
	encoder.SetEscapeHTML(false)
	encoder.Encode(value)
	return bytes.TrimRight(out.Bytes(), "\n")
}

// ParseConfig expands environment/profile sections from a standalone YAML body.
func ParseConfig(body []byte, file string, environ map[string]string) (*Config, error) {
	var rc map[string]any
	if err := yaml.Unmarshal(body, &rc); err != nil {
		return nil, fmt.Errorf("Could not parse %s: %w", file, err)
	}
	return compileConfig(rc, file, environ)
}

// configFromRC consumes the independent JSON snapshot without a YAML roundtrip.
func configFromRC(rc map[string]any, environ map[string]string) (*Config, error) {
	return compileConfig(rc, "RC", environ)
}

func compileConfig(rc map[string]any, file string, environ map[string]string) (*Config, error) {
	selected := map[string]any{}
	for _, key := range []string{"env", "ssh-agent-crypt"} {
		if value, ok := rc[key]; ok {
			selected[key] = value
		}
	}
	// Clone the selected sections before Walk, preserving the raw RC snapshot.
	body, err := json.Marshal(selected)
	if err != nil {
		return nil, fmt.Errorf("Could not parse %s: %w", file, err)
	}
	var document map[string]any
	if err := json.Unmarshal(body, &document); err != nil {
		return nil, fmt.Errorf("Could not parse %s: %w", file, err)
	}
	nyksobject.Walk(document, func(value string) any {
		return nyksstring.ReplaceEnv(value, map[string]any{"env": environ})
	})
	body, err = json.Marshal(document)
	if err != nil {
		return nil, fmt.Errorf("Could not parse %s: %w", file, err)
	}
	var config Config
	if err := json.Unmarshal(body, &config); err != nil {
		return nil, fmt.Errorf("Could not parse %s: %w", file, err)
	}
	return &config, nil
}
