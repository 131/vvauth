// Package vvauth logs into HashiCorp Vault (ssh-agent challenge or jwt),
// caches the token with ssh-agent-crypt and resolves the environment
// declared by .vauthrc. It is the Go counterpart of the vvauth npm package.
package vvauth

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	sshagentcrypt "github.com/131/ssh-agent-crypt"
)

// FunctionName is the shell function installed by Install.
const FunctionName = "venv"

// FunctionDecl is the bash declaration of FunctionName.
const FunctionDecl = `function ` + FunctionName + `() { source <(/usr/bin/env vauth env --source "$@"); }`

// Vauth is a configured client. New builds one from the process environment;
// fields may be set directly for programmatic use.
type Vauth struct {
	RC         RC
	VaultAddr  string
	VaultToken string
	// Agent is the ssh-agent address; empty disables ssh authentication.
	Agent string
	// TokenCache enables the on-disk token cache in CacheDir.
	TokenCache bool
	CacheDir   string
	HomeDir    string
	// Environ is the process environment snapshot used for macros.
	Environ map[string]string
	// Stdout/Stderr/Stdin default to the process streams.
	Stdout     io.Writer
	Stderr     io.Writer
	Stdin      io.Reader
	HTTPClient *http.Client
	// Now overrides the clock (tests).
	Now func() time.Time

	connected bool
}

// token is an established token with its remaining validity.
type token struct {
	Value         string
	TTL           float64 // seconds; 0 means unlimited
	LeaseDuration int64
	Renewable     bool
}

// Environ converts os.Environ() into a map.
func Environ() map[string]string {
	environ := map[string]string{}
	for _, entry := range os.Environ() {
		if key, value, ok := strings.Cut(entry, "="); ok {
			environ[key] = value
		}
	}
	return environ
}

// New loads the configuration from the environment and the first .vauthrc
// found (VAUTHRC, ./.vauthrc, ~/.vauthrc).
func New() (*Vauth, error) {
	environ := Environ()
	home, _ := os.UserHomeDir()
	cwd, _ := os.Getwd()
	v := &Vauth{
		Agent:      sshagentcrypt.DefaultAgentAddress(),
		TokenCache: true,
		HomeDir:    home,
		CacheDir:   filepath.Join(home, ".vauth", "tokens"),
		Environ:    environ,
	}
	if file := LocateRC(environ, cwd, home); file != "" {
		body, err := os.ReadFile(file)
		if err != nil {
			return nil, err
		}
		rc, err := ParseRC(body, file, environ)
		if err != nil {
			return nil, err
		}
		v.RC = *rc
	}
	if v.RC.TokenCache != nil && !*v.RC.TokenCache {
		v.TokenCache = false
	}
	if v.Agent == "" {
		v.TokenCache = false
	}
	v.VaultAddr = v.RC.VaultAddr
	if v.VaultAddr == "" {
		v.VaultAddr = environ["VAULT_ADDR"]
	}
	v.VaultToken = environ["VAULT_TOKEN"]
	if v.VaultAddr == "" {
		fmt.Fprintln(v.stderr(), "Not bound to any vault")
	}
	return v, nil
}

func (v *Vauth) stdout() io.Writer {
	if v.Stdout != nil {
		return v.Stdout
	}
	return os.Stdout
}

func (v *Vauth) stderr() io.Writer {
	if v.Stderr != nil {
		return v.Stderr
	}
	return os.Stderr
}

func (v *Vauth) stdin() io.Reader {
	if v.Stdin != nil {
		return v.Stdin
	}
	return os.Stdin
}

func (v *Vauth) now() time.Time {
	if v.Now != nil {
		return v.Now()
	}
	return time.Now()
}

func (v *Vauth) debug(format string, args ...any) {
	if strings.Contains(v.Environ["DEBUG"], "vvauth") {
		fmt.Fprintf(v.stderr(), "vvauth "+format+"\n", args...)
	}
}

func (v *Vauth) tokenStatus(operation string, token *token) {
	validity := "valid indefinitely"
	if token.TTL != 0 {
		validity = HumanDiff(token.TTL, 2)
	}
	fmt.Fprintf(v.stderr(), "Vauth token: %s · %s · %s\n", operation, v.VaultAddr, validity)
}

// Connect establishes VaultToken: the environment token, then the cached one
// (renewed in the last third of its lease), then a new login. With renew, a
// new login is forced. Without an authentication method, no token is used.
func (v *Vauth) Connect(renew bool) (string, error) {
	if v.RC.SSHAuth == nil && v.RC.JWTAuth == nil {
		v.VaultToken = ""
		return "", nil
	}
	if v.connected && !renew {
		return v.VaultToken, nil
	}
	v.connected = false

	cached := v.readTokenCache()
	current := v.VaultToken
	if current == "" && cached != nil {
		current = cached.Token
	}
	hadToken := current != ""
	operation := "reused"
	now := v.now().UnixMilli()
	if renew || (cached != nil && current == cached.Token && cached.ExpiresAt != nil && *cached.ExpiresAt <= now) {
		current = ""
	}

	var established *token
	if current != "" {
		established = &token{Value: current}
		if cached != nil && cached.Token == current {
			established.LeaseDuration, established.Renewable = cached.LeaseDuration, cached.Renewable
			if cached.ExpiresAt != nil {
				established.TTL = float64(*cached.ExpiresAt-now) / 1000
			}
		} else {
			info, lease, err := v.lookupToken(current)
			if err := reauthenticable(err); err != nil {
				return "", err
			}
			if err != nil {
				established = nil
			} else {
				established.TTL, established.Renewable, established.LeaseDuration = info.TTL, info.Renewable, lease
			}
		}
		if established != nil && established.TTL > 0 && established.TTL <= float64(established.LeaseDuration)/3 {
			if established.Renewable {
				renewed, err := v.renewToken(current)
				if err := reauthenticable(err); err != nil {
					return "", err
				}
				if err != nil {
					established = nil
				} else {
					established = fromAuth(renewed)
					operation = "renewed"
				}
			} else {
				established = nil
			}
		}
	}

	if established == nil {
		var granted *auth
		var err error
		if v.RC.SSHAuth != nil && v.Agent != "" {
			granted, err = v.loginVaultSSH(v.RC.SSHAuth)
		} else if v.RC.JWTAuth != nil && v.RC.JWTAuth.JWT != "" {
			path := v.RC.JWTAuth.Path
			if path == "" {
				path = "jwt"
			}
			granted, err = v.loginVault(path, map[string]string{"jwt": v.RC.JWTAuth.JWT, "role": v.RC.JWTAuth.Role})
		}
		if err != nil {
			return "", err
		}
		if granted == nil {
			if renew || hadToken {
				return "", errors.New("Could not login to vault: no authentication method available")
			}
		} else {
			established = fromAuth(granted)
		}
		operation = "generated"
	}

	v.VaultToken = ""
	if established != nil {
		if operation != "reused" || cached == nil || cached.Token != established.Value {
			v.saveTokenCache(established)
		}
		v.tokenStatus(operation, established)
		v.VaultToken = established.Value
	}
	v.connected = true
	return v.VaultToken, nil
}

// reauthenticable returns err unless it is an invalid token (400/403), in
// which case a new login is appropriate.
func reauthenticable(err error) error {
	var failure *HTTPError
	if err == nil || (errors.As(err, &failure) && (failure.Status == 400 || failure.Status == 403)) {
		return nil
	}
	return err
}

func fromAuth(granted *auth) *token {
	return &token{Value: granted.ClientToken, TTL: float64(granted.LeaseDuration), LeaseDuration: granted.LeaseDuration, Renewable: granted.Renewable}
}

// Profile is the Vault identity of the token: entity metadata and the
// private .vauth_database of VAUTH_USER_LOGIN.
type Profile struct {
	EntityID string
	Metadata map[string]any
	Database map[string]any
}

// Merged returns the metadata over the database.
func (p *Profile) Merged() map[string]any {
	merged := map[string]any{}
	for k, val := range p.Database {
		merged[k] = val
	}
	for k, val := range p.Metadata {
		merged[k] = val
	}
	return merged
}

// GetProfile connects and reads the identity profile. Without token, the
// profile is empty.
func (v *Vauth) GetProfile(renew bool) (*Profile, error) {
	if _, err := v.Connect(renew); err != nil {
		return nil, err
	}
	profile := &Profile{Metadata: map[string]any{}, Database: map[string]any{}}
	if v.VaultToken == "" {
		return profile, nil
	}
	info, _, err := v.lookupToken(v.VaultToken)
	if err != nil {
		return nil, err
	}
	metadata, err := v.lookupIdentity(v.VaultToken, info.EntityID)
	if err != nil {
		return nil, err
	}
	profile.EntityID = info.EntityID
	if metadata != nil {
		profile.Metadata = metadata
	}
	if login, _ := stringify(metadata["VAUTH_USER_LOGIN"]); login != "" {
		database, err := v.vaultRead("private/"+login, ".vauth_database", true)
		if err != nil {
			return nil, err
		}
		if database != nil {
			profile.Database = database
		}
	}
	return profile, nil
}

// Set stores an upper-cased key in the user's .vauth_database.
func (v *Vauth) Set(key, value string) error {
	return v.update(strings.ToUpper(key), value, true)
}

// Unset removes a key from the user's .vauth_database.
func (v *Vauth) Unset(key string) error {
	return v.update(strings.ToUpper(key), "", false)
}

func (v *Vauth) update(key, value string, set bool) error {
	profile, err := v.GetProfile(false)
	if err != nil {
		return err
	}
	login, _ := stringify(profile.Metadata["VAUTH_USER_LOGIN"])
	if login == "" {
		return errors.New("Could not resolve VAUTH_USER_LOGIN from vault identity")
	}
	if set {
		profile.Database[key] = value
	} else {
		delete(profile.Database, key)
	}
	return v.vaultWrite("private/"+login, ".vauth_database", profile.Database)
}

// Show returns the merged profile.
func (v *Vauth) Show() (map[string]any, error) {
	profile, err := v.GetProfile(false)
	if err != nil {
		return nil, err
	}
	return profile.Merged(), nil
}

// Env resolves the environment declared by .vauthrc: VAULT_TOKEN and
// VAULT_ADDR, then env.map with $${env|profile|secrets.X} expanded.
func (v *Vauth) Env(renew bool) (*OrderedMap, error) {
	profile, err := v.GetProfile(renew)
	if err != nil {
		return nil, err
	}
	env := &OrderedMap{}
	if v.VaultToken != "" {
		env.Set("VAULT_TOKEN", v.VaultToken)
	}
	if v.VaultAddr != "" {
		env.Set("VAULT_ADDR", v.VaultAddr)
	}

	config := v.RC.Env
	if config == nil {
		config = &EnvConfig{}
	}
	secrets := map[string]any{}
	if v.RC.AgentCrypt != nil {
		armor, err := os.ReadFile(v.RC.AgentCrypt.Path)
		if err != nil {
			return nil, err
		}
		body, err := sshagentcrypt.Decrypt(armor, v.RC.AgentCrypt.Identity, v.agentOptions())
		if err != nil {
			return nil, err
		}
		if err := json.Unmarshal(body, &secrets); err != nil {
			return nil, fmt.Errorf("Invalid ssh-agent-crypt payload %s: %w", v.RC.AgentCrypt.Path, err)
		}
	}

	mapping := OrderedMap{}
	for _, key := range config.Map.Keys {
		mapping.Set(key, config.Map.Values[key])
	}
	merged := profile.Merged()
	if config.Git {
		mapping.Set("GIT_COMMITTER_NAME", "$${profile.VAUTH_USER_NAME}")
		mapping.Set("GIT_COMMITTER_EMAIL", "$${profile.VAUTH_USER_MAIL}")
		mapping.Set("GIT_AUTHOR_EMAIL", "$${profile.VAUTH_USER_MAIL}")
		mapping.Set("GIT_AUTHOR_NAME", "$${profile.VAUTH_USER_NAME}")
		mapping.Set("GIT_USER_LOGIN", "$${profile.VAUTH_USER_LOGIN}")
	}
	mount := config.Path
	if mount == "" {
		mount = "secrets"
	}
	for _, secretPath := range config.Paths {
		fmt.Fprintln(v.stderr(), "reaching paths", secretPath)
		data, err := v.vaultRead(mount, secretPath, false)
		if err != nil {
			return nil, err
		}
		for k, val := range data {
			secrets[k] = val
		}
	}
	dict := Lookup{"env": v.Environ, "profile": merged, "secrets": secrets}
	for _, key := range mapping.Keys {
		if !envName.MatchString(key) {
			return nil, fmt.Errorf("Invalid environment variable name '%s' in env.map", key)
		}
		env.Set(key, ReplaceEnv(mapping.Values[key], dict))
	}
	return env, nil
}

// envName is the only shape of key that reaches `export KEY=...` unescaped;
// .vauthrc may come from an untrusted working directory.
var envName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// Login connects, and with source publishes VAULT_TOKEN as shell exports.
func (v *Vauth) Login(source, renew bool) error {
	if _, err := v.Connect(renew); err != nil {
		return err
	}
	if source {
		env := &OrderedMap{}
		env.Set("VAULT_TOKEN", v.VaultToken)
		v.PublishEnv(env)
	}
	return nil
}

// PublishEnv writes `export K='v'` lines to stdout, each followed by an echo
// of the redacted assignment to stderr for the sourcing shell.
func (v *Vauth) PublishEnv(env *OrderedMap) {
	var lines []string
	for _, key := range env.Keys {
		lines = append(lines, fmt.Sprintf("export %s=%s", key, ShellEscape(env.Values[key])))
		lines = append(lines, fmt.Sprintf(`echo export %s="[redacted]" >&2`, key))
	}
	fmt.Fprint(v.stdout(), strings.Join(lines, "\n")+"\n")
}

// ShellEscape single-quotes a value for bash.
func ShellEscape(value string) string {
	return "'" + strings.ReplaceAll(value, "'", `'"'"'`) + "'"
}

// Dotenv writes `K=v` lines to stdout and redacted exports to stderr.
func (v *Vauth) Dotenv() error {
	env, err := v.Env(false)
	if err != nil {
		return err
	}
	for _, key := range env.Keys {
		fmt.Fprintf(v.stdout(), "%s=%s\n", key, env.Values[key])
		fmt.Fprintf(v.stderr(), "export %s=[redacted]\n", key)
	}
	return nil
}

// Run executes a command with the resolved environment merged over the
// process environment and returns its exit code.
func (v *Vauth) Run(command string, args ...string) (int, error) {
	env, err := v.Env(false)
	if err != nil {
		return 1, err
	}
	cmd := exec.Command(command, args...)
	cmd.Env = os.Environ()
	for _, key := range env.Keys {
		cmd.Env = append(cmd.Env, key+"="+env.Values[key])
	}
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	err = cmd.Run()
	var exit *exec.ExitError
	if errors.As(err, &exit) {
		return exit.ExitCode(), nil
	}
	if err != nil {
		return 1, fmt.Errorf("run failure : %w", err)
	}
	return 0, nil
}

// FunctionExists reports whether a bash login shell already defines alias.
func FunctionExists(alias string) bool {
	return exec.Command("bash", "-lc", "declare -F "+alias).Run() == nil
}

var yes = regexp.MustCompile(`(?i)^y(es)?$`)

// Install appends FunctionDecl to ~/.bashrc, asking before overriding an
// existing definition.
func (v *Vauth) Install() error {
	bashrcPath := filepath.Join(v.HomeDir, ".bashrc")
	body, _ := os.ReadFile(bashrcPath)
	bashrc := strings.TrimSpace(string(body))
	if FunctionExists(FunctionName) {
		fmt.Fprint(v.stdout(), "Function already defined, override current definition?  [y/N] ")
		answer, _ := bufio.NewReader(v.stdin()).ReadString('\n')
		if !yes.MatchString(strings.TrimSpace(answer)) {
			return nil
		}
	}
	fmt.Fprintf(v.stderr(), "Installing function %s in %s\n", FunctionName, bashrcPath)
	if err := os.WriteFile(bashrcPath, []byte(bashrc+"\n"+FunctionDecl+"\n"), 0o644); err != nil {
		return err
	}
	fmt.Fprintf(v.stderr(), "Installation ok, please \nsource %s\n", bashrcPath)
	return nil
}
