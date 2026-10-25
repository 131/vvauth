// Command vauth is the standalone Vault credentials helper: same commands
// and flags as the vvauth npm package.
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"runtime/debug"
	"strings"

	vvauth "github.com/131/vvauth/v2"
)

const usage = `Usage: vauth <command> [--flag[=value]] [--ir://json]

Commands:
  env [--source] [--renew]    Resolve the .vauthrc environment (JSON with --ir://json)
  login [--source] [--renew]  Authenticate; --source exports VAULT_TOKEN
  connect [--renew]           Authenticate and print the token
  run <command> [args...]     Run a command with the resolved environment
  dotenv                      Print the environment as K=v lines
  show                        Print the identity profile and .vauth_database
  set <key> <value>           Store a key in the .vauth_database
  unset <key>                 Remove a key from the .vauth_database
  install                     Install the venv shell function in ~/.bashrc
  version                     Print the build version
  gitlab                      Export CI_PROJECT_* from origin without login
`

// version is set by the release build (-ldflags "-X main.version=v1.2.3");
// otherwise the module version recorded by go install is used.
var version string

func buildVersion() string {
	if version != "" {
		return version
	}
	if info, ok := debug.ReadBuildInfo(); ok && info.Main.Version != "" {
		return info.Main.Version
	}
	return "(devel)"
}

var flagPattern = regexp.MustCompile(`^--?([a-zA-Z_0-9/:-]+)(?:=(.*))?$`)

// parseArgs splits positional arguments from --flags (nyks/process/parseArgs).
func parseArgs(argv []string) ([]string, map[string]string) {
	var args []string
	dict := map[string]string{}
	for i, arg := range argv {
		if arg == "--" {
			args = append(args, argv[i+1:]...)
			break
		}
		if !strings.HasPrefix(arg, "-") {
			args = append(args, arg)
			continue
		}
		if match := flagPattern.FindStringSubmatch(arg); match != nil {
			value := "true"
			if strings.Contains(arg, "=") {
				value = match[2]
			}
			dict[match[1]] = value
		}
	}
	return args, dict
}

func truthy(value string, ok bool) bool {
	if !ok {
		return false
	}
	switch strings.ToLower(value) {
	case "", "false", "0":
		return false
	}
	return true
}

// param reads the nth positional argument or the --name flag.
func param(args []string, dict map[string]string, index int, name string) (string, bool) {
	if index < len(args) {
		return args[index], true
	}
	value, ok := dict[name]
	return value, ok
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(argv []string) error {
	if len(argv) > 0 && argv[0] == "run" {
		return runCommand(argv[1:])
	}
	args, dict := parseArgs(argv)
	if truthy(dict["gitlab"], dict["gitlab"] != "") {
		args = []string{"gitlab"}
	}
	if _, ok := dict["version"]; ok && len(args) == 0 {
		args = []string{"version"}
	}
	if len(args) == 0 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(1)
	}
	command, args := args[0], args[1:]
	_, jsonOutput := dict["ir://json"]
	if command == "version" || command == "--version" {
		fmt.Println(strings.TrimPrefix(buildVersion(), "v"))
		return nil
	}

	vvauth.Version = buildVersion()
	v, err := vvauth.New()
	if err != nil {
		return err
	}
	switch command {
	case "gitlab":
		return v.Gitlab()
	case "env":
		source, renew := truthy(param(args, dict, 0, "source")), truthy(param(args, dict, 1, "renew"))
		env, err := v.Env(renew)
		if err != nil {
			return err
		}
		if source {
			v.PublishEnv(env)
			return nil
		}
		return respond(env, jsonOutput)
	case "login":
		source, renew := truthy(param(args, dict, 0, "source")), truthy(param(args, dict, 1, "renew"))
		return v.Login(source, renew)
	case "connect":
		token, err := v.Connect(truthy(param(args, dict, 0, "renew")))
		if err != nil {
			return err
		}
		if token == "" {
			return nil
		}
		return respond(token, jsonOutput)
	case "dotenv":
		return v.Dotenv()
	case "show":
		profile, err := v.Show()
		if err != nil {
			return err
		}
		return respond(profile, jsonOutput)
	case "set":
		key, ok := param(args, dict, 0, "k")
		if !ok {
			return fmt.Errorf("Missing parameter --k")
		}
		value, ok := param(args, dict, 1, "v")
		if !ok {
			return fmt.Errorf("Missing parameter --v")
		}
		return v.Set(key, value)
	case "unset":
		key, ok := param(args, dict, 0, "k")
		if !ok {
			return fmt.Errorf("Missing parameter --k")
		}
		return v.Unset(key)
	case "install":
		return v.Install()
	}
	return fmt.Errorf("Invalid command key '%s'", command)
}

func runCommand(argv []string) error {
	if len(argv) > 0 && argv[0] == "--" {
		argv = argv[1:]
	}
	if len(argv) == 0 {
		return fmt.Errorf("run: missing command")
	}
	vvauth.Version = buildVersion()
	v, err := vvauth.New()
	if err != nil {
		return err
	}
	code, err := v.Run(argv[0], argv[1:]...)
	if err != nil {
		return err
	}
	os.Exit(code)
	return nil
}

// respond prints the command result: JSON with --ir://json, raw strings
// otherwise (objects are still rendered as JSON).
func respond(response any, jsonOutput bool) error {
	if text, ok := response.(string); ok && !jsonOutput {
		// Raw token output has no trailing newline.
		_, err := fmt.Fprint(os.Stdout, text)
		return err
	}
	if jsonOutput {
		var out bytes.Buffer
		encoder := json.NewEncoder(&out)
		encoder.SetEscapeHTML(false)
		if err := encoder.Encode(response); err != nil {
			return err
		}
		_, err := os.Stdout.Write(bytes.TrimSuffix(out.Bytes(), []byte("\n")))
		return err
	}
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetEscapeHTML(false)
	return encoder.Encode(response)
}
