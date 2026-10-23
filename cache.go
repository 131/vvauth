package vvauth

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	sshagentcrypt "github.com/131/ssh-agent-crypt"
)

// tokenCache is the clear content of ~/.vauth/tokens/<key>.creds.
type tokenCache struct {
	Token         string `json:"token"`
	LeaseDuration int64  `json:"lease_duration"`
	Renewable     bool   `json:"renewable"`
	ExpiresAt     *int64 `json:"expires_at"` // unix milliseconds, null when unlimited
}

// TokenCacheKey isolates cached tokens by Vault address and authentication
// configuration. It matches the Node implementation byte for byte.
func (v *Vauth) TokenCacheKey() string {
	key := `{"vault_addr":` + string(jsonString(strings.Trim(v.VaultAddr, "/")))
	if auth := v.RC.AuthKey(); auth != "" {
		key += "," + auth
	}
	digest := sha256.Sum256([]byte(key + "}"))
	return hex.EncodeToString(digest[:])
}

// TokenCacheFile is the armored cache file for this configuration.
func (v *Vauth) TokenCacheFile() string {
	return filepath.Join(v.CacheDir, v.TokenCacheKey()+".creds")
}

func (v *Vauth) agentOptions() *sshagentcrypt.Options {
	return &sshagentcrypt.Options{AgentSocket: v.Agent}
}

func (v *Vauth) readTokenCache() *tokenCache {
	if !v.TokenCache {
		return nil
	}
	armor, err := os.ReadFile(v.TokenCacheFile())
	if err != nil {
		return nil
	}
	body, err := sshagentcrypt.Decrypt(armor, "", v.agentOptions())
	if err != nil {
		return nil
	}
	var cache tokenCache
	if json.Unmarshal(body, &cache) != nil || cache.Token == "" {
		return nil
	}
	return &cache
}

func (v *Vauth) saveTokenCache(token *token) {
	if !v.TokenCache {
		return
	}
	file := v.TokenCacheFile()
	temporary := file + ".next"
	defer os.Remove(temporary)
	cache := tokenCache{Token: token.Value, LeaseDuration: token.LeaseDuration, Renewable: token.Renewable}
	if token.TTL != 0 {
		expires := v.now().UnixMilli() + int64(token.TTL*1000)
		cache.ExpiresAt = &expires
	}
	err := v.writeTokenCache(file, temporary, &cache)
	if err != nil {
		// Cache failures must not prevent authentication or expose credentials.
		fmt.Fprintln(v.stderr(), "Could not encrypt/write token cache; token not persisted")
	}
}

func (v *Vauth) writeTokenCache(file, temporary string, cache *tokenCache) error {
	body, err := json.Marshal(cache)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(file), 0o700); err != nil {
		return err
	}
	identity := v.Environ["VAUTH_USER_IDENTITY"]
	if identity == "" {
		identity = v.Environ["VAUTH_USER_MAIL"]
	}
	armor, err := sshagentcrypt.Encrypt(body, identity, v.agentOptions())
	if err != nil {
		return err
	}
	if err := os.WriteFile(temporary, []byte(armor), 0o600); err != nil {
		return err
	}
	return os.Rename(temporary, file)
}
