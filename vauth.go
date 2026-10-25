// Package vvauth resolves the environment and profile declared by .vauthrc.
// Authentication, token caching and HTTP transport belong to vauth-login.
package vvauth

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"

	nyksstring "github.com/131/nyks/v6/string"
	sshagentcrypt "github.com/131/ssh-agent-crypt"
	vauthlogin "github.com/131/vauth-login"
	"github.com/Masterminds/semver/v3"
)

// PackageName is the npm name a project uses to pin vauth:
// `"dependencies": {"vvauth": "^2.5.0"}` in its package.json.
const PackageName = "vvauth"

// Version is the running version (ldflags -X or debug.ReadBuildInfo), checked
// by New against the current directory's package.json; empty or non-semver
// values ("(devel)") skip the check.
var Version string

// FunctionName is the shell function installed by Install.
const FunctionName = "venv"

// FunctionDecl is the bash declaration of FunctionName.
const FunctionDecl = `function ` + FunctionName + `() { source <(/usr/bin/env vauth env --source "$@"); }`

// Vauth is a configured client. New builds one from the process environment;
// fields may be set directly for programmatic use.
type Vauth struct {
	*vauthlogin.Vauth
	Config Config
	Stdout io.Writer
	Stdin  io.Reader
}

// CheckProjectVersion fails when manifest (a package.json) declares a
// dependency on PackageName that version does not satisfy. A missing manifest,
// dependency or unparseable version is not an error.
func CheckProjectVersion(manifest, version string) error {
	body, err := os.ReadFile(manifest)
	if err != nil {
		return nil
	}
	var pkg struct {
		Dependencies map[string]string `json:"dependencies"`
	}
	if json.Unmarshal(body, &pkg) != nil {
		return nil
	}
	required, ok := pkg.Dependencies[PackageName]
	if !ok || required == "" {
		return nil
	}
	current, err := semver.NewVersion(version)
	if err != nil {
		return nil
	}
	constraint, err := semver.NewConstraint(required)
	if err != nil {
		return fmt.Errorf("Invalid %s version requirement '%s' in %s", PackageName, required, manifest)
	}
	if !constraint.Check(current) {
		return fmt.Errorf("Unsupported %s version %s (project requires %s)", PackageName, version, required)
	}
	return nil
}

// New loads authentication through vauth-login, then the environment/profile
// configuration from the same selected .vauthrc.
func New() (*Vauth, error) {
	cwd, err := os.Getwd()
	if err != nil {
		return nil, err
	}
	if err := CheckProjectVersion(filepath.Join(cwd, "package.json"), Version); err != nil {
		return nil, err
	}
	login, err := vauthlogin.New()
	if err != nil {
		return nil, err
	}
	v := &Vauth{Vauth: login}
	config, err := configFromRC(login.RC(), login.Environ)
	if err != nil {
		return nil, err
	}
	v.Config = *config
	if v.Config.Env != nil && v.Config.Env.GitLab {
		var missing []string
		for _, key := range []string{"CI_PROJECT_PATH", "CI_PROJECT_NAME", "CI_PROJECT_NAMESPACE", "CI_PROJECT_PATH_SLUG"} {
			if v.Environ[key] == "" {
				missing = append(missing, key)
			}
		}
		if len(missing) != 0 {
			return nil, fmt.Errorf("Missing %s. Run venv --gitlab first.", strings.Join(missing, ", "))
		}
	}
	if v.VAULT_ADDR() == "" {
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
	if v.VAULT_TOKEN() == "" || v.VAULT_ADDR() == "" {
		return profile, nil
	}
	info, err := v.LookupSelf(v.VAULT_TOKEN())
	if err != nil {
		return nil, err
	}
	_, response, err := v.Request("GET", "identity/entity/id/"+info.EntityID, v.VAULT_TOKEN(), nil, 200)
	if err != nil {
		return nil, err
	}
	var identity struct {
		Data struct {
			Metadata map[string]any `json:"metadata"`
		} `json:"data"`
	}
	if err := json.Unmarshal(response, &identity); err != nil {
		return nil, fmt.Errorf("Invalid identity response: %w", err)
	}
	profile.EntityID = info.EntityID
	if identity.Data.Metadata != nil {
		profile.Metadata = identity.Data.Metadata
	}
	if login, _ := stringify(profile.Metadata["VAUTH_USER_LOGIN"]); login != "" {
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
	config := v.Config.Env
	if config == nil {
		config = &EnvConfig{}
	}
	profile := &Profile{Metadata: map[string]any{}, Database: map[string]any{}}
	rc := v.RC()
	localCredentials := v.Config.AgentCrypt != nil && rc["ssh_auth"] == nil && rc["jwt_auth"] == nil
	if localCredentials {
		if _, err := v.Connect(renew); err != nil {
			return nil, err
		}
	} else {
		var err error
		profile, err = v.GetProfile(renew)
		if err != nil {
			return nil, err
		}
	}
	env := &OrderedMap{}
	if v.VAULT_TOKEN() != "" {
		env.Set("VAULT_TOKEN", v.VAULT_TOKEN())
	}
	if v.VAULT_ADDR() != "" {
		env.Set("VAULT_ADDR", v.VAULT_ADDR())
	}

	secrets := map[string]any{}
	if v.Config.AgentCrypt != nil {
		armor, err := os.ReadFile(v.Config.AgentCrypt.Path)
		if err != nil {
			return nil, err
		}
		body, err := sshagentcrypt.Decrypt(armor, v.Config.AgentCrypt.Identity, &sshagentcrypt.Options{AgentSocket: v.Agent})
		if err != nil {
			return nil, err
		}
		if err := json.Unmarshal(body, &secrets); err != nil {
			return nil, fmt.Errorf("Invalid ssh-agent-crypt payload %s: %w", v.Config.AgentCrypt.Path, err)
		}
	}

	mapping := OrderedMap{}
	for _, key := range config.Map.Keys {
		mapping.Set(key, config.Map.Values[key])
	}
	merged := profile.Merged()
	if config.Git {
		for _, field := range [][2]string{
			{"GIT_COMMITTER_NAME", "VAUTH_USER_NAME"},
			{"GIT_COMMITTER_EMAIL", "VAUTH_USER_MAIL"},
			{"GIT_AUTHOR_EMAIL", "VAUTH_USER_MAIL"},
			{"GIT_AUTHOR_NAME", "VAUTH_USER_NAME"},
			{"GIT_USER_LOGIN", "VAUTH_USER_LOGIN"},
		} {
			value, err := envValue(merged[field[1]])
			if err != nil {
				return nil, fmt.Errorf("Invalid environment value '%s' in env.map: %w", field[0], err)
			}
			mapping.Set(field[0], value)
		}
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
	dict := map[string]any{"env": v.Environ, "profile": merged, "secrets": secrets}
	for _, key := range mapping.Keys {
		if !envName.MatchString(key) {
			return nil, fmt.Errorf("Invalid environment variable name '%s' in env.map", key)
		}
		value, err := envValue(nyksstring.ReplaceEnv(mapping.Values[key], dict))
		if err != nil {
			return nil, fmt.Errorf("Invalid environment value '%s' in env.map: %w", key, err)
		}
		env.Set(key, value)
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
		env.Set("VAULT_TOKEN", v.VAULT_TOKEN())
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
