package vvauth

import (
	"bytes"
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// Config contains only environment/profile settings; authentication is
// parsed and owned by vauth-login.
type Config struct {
	AgentCrypt *AgentCrypt `yaml:"ssh-agent-crypt"`
	Env        *EnvConfig  `yaml:"env"`
}

// AgentCrypt points to a local ssh-agent-crypt armored JSON file whose keys
// feed $${secrets.X}.
type AgentCrypt struct {
	Path     string `yaml:"path"`
	Identity string `yaml:"identity"`
}

// EnvConfig describes the environment to resolve.
type EnvConfig struct {
	Map    OrderedMap `yaml:"map"`
	Paths  []string   `yaml:"paths"`
	Path   string     `yaml:"path"`
	Git    bool       `yaml:"git"`
	GitLab bool       `yaml:"gitlab"`
}

// OrderedMap keeps the YAML document order of a string mapping.
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

// UnmarshalYAML decodes a mapping, scalars as strings.
func (m *OrderedMap) UnmarshalYAML(node *yaml.Node) error {
	if node.Kind != yaml.MappingNode {
		return fmt.Errorf("line %d: expected a mapping", node.Line)
	}
	for i := 0; i+1 < len(node.Content); i += 2 {
		var key string
		var value any
		if err := node.Content[i].Decode(&key); err != nil {
			return err
		}
		if err := node.Content[i+1].Decode(&value); err != nil {
			return err
		}
		text, err := envValue(value)
		if err != nil {
			return fmt.Errorf("Invalid environment value '%s' in env.map: %w", key, err)
		}
		m.Set(key, text)
	}
	return nil
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

// Lookup resolves dotted paths ($${env.X}) in nested string maps.
type Lookup map[string]any

func (dict Lookup) get(path string) (any, bool) {
	var current any = map[string]any(dict)
	for _, part := range strings.Split(path, ".") {
		switch node := current.(type) {
		case map[string]any:
			value, ok := node[part]
			if !ok {
				return nil, false
			}
			current = value
		case map[string]string:
			value, ok := node[part]
			if !ok {
				return nil, false
			}
			current = value
		case Lookup:
			value, ok := node[part]
			if !ok {
				return nil, false
			}
			current = value
		default:
			return nil, false
		}
	}
	return current, true
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

var macroPattern = regexp.MustCompile(`(?i)\$\$([a-z0-9._-]+)|\$\$\{([^}]+)\}`)

// ReplaceEnv expands $$key and $${key} macros against dict (nyks
// string/replaceEnv semantics): unknown keys stay, expansions recurse.
func ReplaceEnv(str string, dict Lookup) string {
	return replaceEnv(str, func(key string) (string, bool) {
		value, ok := dict.get(key)
		if !ok {
			return "", false
		}
		return stringify(value)
	})
}

func replaceEnv(str string, lookup func(string) (string, bool)) string {
	for depth := 0; depth < 16; depth++ {
		touched := false
		str = macroPattern.ReplaceAllStringFunc(str, func(macro string) string {
			match := macroPattern.FindStringSubmatch(macro)
			key := match[1]
			if key == "" {
				key = match[2]
			}
			value, ok := lookup(key)
			if !ok {
				return macro
			}
			touched = true
			return value
		})
		if !touched {
			break
		}
	}
	return str
}

// walk expands every scalar string of a YAML tree in place.
func walk(node *yaml.Node, process func(string) string) {
	if node.Kind == yaml.ScalarNode {
		if node.Tag == "!!str" || node.Tag == "" {
			node.Value = process(node.Value)
		}
		return
	}
	for _, child := range node.Content {
		walk(child, process)
	}
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
	var document yaml.Node
	if err := yaml.Unmarshal(body, &document); err != nil {
		return nil, fmt.Errorf("Could not parse %s: %w", file, err)
	}
	return compileConfig(&document, file, environ)
}

// configFromRC consumes the independent JSON snapshot without reopening its file.
func configFromRC(rc map[string]any, environ map[string]string) (*Config, error) {
	var document yaml.Node
	if err := document.Encode(rc); err != nil {
		return nil, fmt.Errorf("Could not read RC: %w", err)
	}
	return compileConfig(&document, "RC", environ)
}

func compileConfig(document *yaml.Node, file string, environ map[string]string) (*Config, error) {
	root := document
	if root.Kind == yaml.DocumentNode {
		if len(root.Content) == 0 {
			return &Config{}, nil
		}
		root = root.Content[0]
	}
	if root.Kind != yaml.MappingNode {
		return nil, fmt.Errorf("Could not parse %s: expected a mapping", file)
	}
	var content []*yaml.Node
	for i := 0; i+1 < len(root.Content); i += 2 {
		switch root.Content[i].Value {
		case "env", "ssh-agent-crypt":
			content = append(content, root.Content[i], root.Content[i+1])
		}
	}
	root.Content = content
	walk(document, func(value string) string { return ReplaceEnv(value, Lookup{"env": environ}) })
	var config Config
	if err := document.Decode(&config); err != nil {
		return nil, fmt.Errorf("Could not parse %s: %w", file, err)
	}
	return &config, nil
}
