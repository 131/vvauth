package vvauth

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	sshagentcrypt "github.com/131/ssh-agent-crypt"
	vauthlogin "github.com/131/vauth-login"
)

var delegateRole = regexp.MustCompile(`^[A-Za-z0-9_.-]+$`)
var delegateMacro = regexp.MustCompile(`(?i)\$\$\{([^}]+)\}|\$\$([a-z0-9._-]+)`)

type delegateCache struct {
	Token     string  `json:"token"`
	ExpiresAt float64 `json:"expires_at"`
}

func (c delegateCache) valid(parent string, now float64) bool {
	return c.Token != "" && c.Token != parent && !math.IsNaN(c.ExpiresAt) && !math.IsInf(c.ExpiresAt, 0) && c.ExpiresAt > now
}

func (v *Vauth) delegateNow() float64 {
	now := time.Now()
	if v.Now != nil {
		now = v.Now()
	}
	return float64(now.UnixMilli())
}

// delegateKey hashes a shared JSON tuple: no parent credential in filenames.
func delegateKey(address, parent, role string) string {
	var body bytes.Buffer
	encoder := json.NewEncoder(&body)
	encoder.SetEscapeHTML(false)
	encoder.Encode([]string{strings.Trim(address, "/"), parent, role})
	hash := sha256.Sum256(bytes.TrimSuffix(body.Bytes(), []byte("\n")))
	return hex.EncodeToString(hash[:])
}

func (v *Vauth) delegateFile(key string) string {
	return filepath.Join(v.HomeDir, ".vauth", "delegates", key+".creds")
}

// Delegate emits or reuses a role-scoped child. renew forces child issuance,
// not another parent login. The server role owns the ACL.
func (v *Vauth) Delegate(role string, renew bool) (string, error) {
	if !delegateRole.MatchString(role) || role == "." || role == ".." {
		return "", errors.New("Invalid Vault delegation role")
	}
	if _, err := v.Connect(false); err != nil {
		return "", err
	}
	parent := v.VAULT_TOKEN()
	if parent == "" || v.VAULT_ADDR() == "" {
		return "", errors.New("Vault delegation requires a parent token and address")
	}
	key := delegateKey(v.VAULT_ADDR(), parent, role)
	if v.delegates == nil {
		v.delegates = map[string]delegateCache{}
	}
	cache := v.delegates[key]
	if !renew && !cache.valid(parent, v.delegateNow()) && v.TokenCache {
		if armor, err := os.ReadFile(v.delegateFile(key)); err == nil {
			if body, err := sshagentcrypt.Decrypt(armor, "", &sshagentcrypt.Options{AgentSocket: v.Agent}); err == nil {
				// Invalid cache content is a miss, never a human-token fallback.
				if json.Unmarshal(body, &cache) != nil {
					cache = delegateCache{}
				}
			}
		}
	}
	if !renew && cache.valid(parent, v.delegateNow()) {
		v.delegates[key] = cache
		return cache.Token, nil
	}
	lookupStarted := v.delegateNow()
	info, err := v.LookupSelf(parent)
	if err != nil {
		var httpErr *vauthlogin.HTTPError
		if !errors.As(err, &httpErr) || (httpErr.Status != 400 && httpErr.Status != 403) {
			return "", err
		}
		if _, err := v.Connect(true); err != nil {
			return "", err
		}
		parent = v.VAULT_TOKEN()
		if parent == "" {
			return "", errors.New("Vault delegation requires a parent token")
		}
		key = delegateKey(v.VAULT_ADDR(), parent, role)
		lookupStarted = v.delegateNow()
		info, err = v.LookupSelf(parent)
		if err != nil {
			return "", err
		}
	}
	// Anchor server TTLs at request start; response time is not extra life.
	createStarted := v.delegateNow()
	ttl := info.TTL - (createStarted-lookupStarted)/1000
	if ttl <= 0 || math.IsNaN(ttl) || math.IsInf(ttl, 0) {
		return "", errors.New("Invalid Vault parent delegation TTL")
	}
	_, body, err := v.Request("POST", "auth/token/create/"+role, parent, map[string]any{
		"ttl": strconv.FormatFloat(ttl, 'f', -1, 64) + "s", "renewable": false, "no_default_policy": true, "type": "service",
	}, 200)
	if err != nil {
		return "", err
	}
	var response struct {
		Auth *struct {
			Token string  `json:"client_token"`
			TTL   float64 `json:"lease_duration"`
		} `json:"auth"`
	}
	if err := json.Unmarshal(body, &response); err != nil {
		return "", err
	}
	if response.Auth == nil || response.Auth.Token == "" || response.Auth.Token == parent || response.Auth.TTL <= 0 || response.Auth.TTL > ttl {
		return "", errors.New("Invalid Vault delegation response")
	}
	cache = delegateCache{Token: response.Auth.Token, ExpiresAt: createStarted + response.Auth.TTL*1000}
	if !cache.valid(parent, v.delegateNow()) {
		return "", errors.New("Invalid Vault delegation TTL")
	}
	v.delegates[key] = cache
	if v.TokenCache {
		v.saveDelegate(key, cache)
	}
	if !cache.valid(parent, v.delegateNow()) {
		return "", errors.New("Expired Vault delegation response")
	}
	return cache.Token, nil
}

func (v *Vauth) saveDelegate(key string, cache delegateCache) {
	// Persistence is best effort; memory reuse remains available without disk.
	err := v.writeDelegate(key, cache)
	if err != nil {
		fmt.Fprintln(v.stderr(), "Could not encrypt/write delegation cache; token not persisted")
	}
}

func (v *Vauth) writeDelegate(key string, cache delegateCache) error {
	body, err := json.Marshal(cache)
	if err != nil {
		return err
	}
	identity := v.Environ["SSH_AGENT_CRYPT_KEY"]
	if identity == "" {
		identity = v.Environ["VAUTH_USER_IDENTITY"]
	}
	if identity == "" {
		identity = v.Environ["VAUTH_USER_MAIL"]
	}
	armor, err := sshagentcrypt.Encrypt(body, identity, &sshagentcrypt.Options{AgentSocket: v.Agent})
	if err != nil {
		return err
	}
	file := v.delegateFile(key)
	if err := os.MkdirAll(filepath.Dir(file), 0700); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(filepath.Dir(file), ".delegate-*.next")
	if err != nil {
		return err
	}
	defer os.Remove(temporary.Name())
	_, err = temporary.WriteString(armor)
	closeErr := temporary.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	return os.Rename(temporary.Name(), file)
}

func replaceDelegates(value string, delegates map[string]string) (string, error) {
	var err error
	expanded := delegateMacro.ReplaceAllStringFunc(value, func(macro string) string {
		parts := delegateMacro.FindStringSubmatch(macro)
		key := parts[1]
		if key == "" {
			key = parts[2]
		}
		if strings.ToLower(key) != "delegate" && !strings.HasPrefix(strings.ToLower(key), "delegate.") {
			return macro
		}
		role := ""
		if len(key) > len("delegate.") {
			role = key[len("delegate."):]
		}
		token, ok := delegates[role]
		if !ok {
			err = fmt.Errorf("Unknown Vault delegation '%s'", role)
		}
		return token
	})
	return expanded, err
}
